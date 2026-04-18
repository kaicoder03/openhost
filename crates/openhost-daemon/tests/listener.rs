//! In-process two-peer test for the daemon's WebRTC listener.
//!
//! The daemon runs its normal `App::build_with_transport` flow; a
//! second `RTCPeerConnection` plays the client side, asserting
//! `a=setup:active`. SDPs are exchanged through `App::handle_offer`
//! directly — the offer-record polling + discovery plumbing is PR #7's
//! job; this PR only proves the listener library is correct.
//!
//! Assertions:
//! 1. A valid `setup:active` offer completes the DTLS handshake.
//! 2. The negotiated answer contains the daemon's own DTLS fingerprint.
//! 3. A `REQUEST_HEAD` frame sent over the data channel produces a
//!    `RESPONSE_HEAD` + `RESPONSE_END` pair, the head carrying a
//!    `502 Bad Gateway` body.
//! 4. An offer asserting `a=setup:passive` is rejected before any peer
//!    connection is allocated.
//! 5. `app.shutdown()` terminates the listener promptly.

use async_trait::async_trait;
use bytes::Bytes;
use openhost_core::wire::{Frame, FrameType};
use openhost_daemon::config::{
    Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, PkarrConfig,
};
use openhost_daemon::error::ListenerError;
use openhost_daemon::{App, DaemonError, Result as DaemonResult};
use openhost_pkarr::{Result as PkarrResult, Transport};
use pkarr::{SignedPacket, Timestamp};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::{mpsc, Mutex};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[derive(Default)]
struct NoopTransport;

#[async_trait]
impl Transport for NoopTransport {
    async fn publish(&self, _packet: &SignedPacket, _cas: Option<Timestamp>) -> PkarrResult<()> {
        // Pretend the publish succeeded. `App::build_with_transport`
        // doesn't care; the listener doesn't read from this either.
        Ok(())
    }
}

fn test_config(dir: &TempDir) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: dir.path().join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: vec![],
            republish_secs: 3600,
        },
        dtls: DtlsConfig {
            cert_path: dir.path().join("dtls.pem"),
            rotate_secs: 3600,
        },
        forward: None,
        log: LogConfig::default(),
    }
}

async fn build_daemon() -> (TempDir, App) {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);
    let app = App::build_with_transport(cfg, Arc::new(NoopTransport) as Arc<dyn Transport>)
        .await
        .expect("daemon builds");
    (tmp, app)
}

#[tokio::test]
async fn offer_with_passive_setup_role_is_rejected_before_any_pc_is_built() -> DaemonResult<()> {
    let (_tmp, app) = build_daemon().await;

    let bad_sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                   c=IN IP4 0.0.0.0\r\na=setup:passive\r\n";

    let err = app.handle_offer(bad_sdp).await.unwrap_err();
    assert!(matches!(
        err,
        DaemonError::Listener(ListenerError::SetupRoleMismatch { ref found }) if found == "passive"
    ));
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn offer_missing_setup_line_is_rejected() -> DaemonResult<()> {
    let (_tmp, app) = build_daemon().await;
    let bad_sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    let err = app.handle_offer(bad_sdp).await.unwrap_err();
    assert!(matches!(
        err,
        DaemonError::Listener(ListenerError::OfferParse(_))
    ));
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dtls_handshake_and_502_response_roundtrip() -> DaemonResult<()> {
    // Set up: daemon side (`app`) + client side (`client_pc`). The
    // client creates a data channel — that triggers the offer —
    // we feed the offer to the daemon via `app.handle_offer`, pipe
    // the answer back, then exchange a single REQUEST_HEAD ↔ 502 pair.
    let (_tmp, app) = build_daemon().await;

    // Build the client PC with webrtc-rs defaults (active role emerges
    // naturally because it's the offerer).
    let client_api = APIBuilder::new().build();
    let client_pc = Arc::new(
        client_api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("client pc builds"),
    );

    // Wire connection-state + DC hooks BEFORE creating the DC so we can
    // observe the DTLS completion deterministically.
    let (connected_tx, mut connected_rx) = mpsc::channel::<()>(1);
    {
        let connected_tx = connected_tx.clone();
        client_pc.on_peer_connection_state_change(Box::new(move |state| {
            let connected_tx = connected_tx.clone();
            Box::pin(async move {
                if state == RTCPeerConnectionState::Connected {
                    let _ = connected_tx.try_send(());
                }
            })
        }));
    }

    // Collect bytes arriving on the client DC (the daemon's 502 response).
    let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let (first_byte_tx, mut first_byte_rx) = mpsc::channel::<()>(1);
    let (dc_open_tx, mut dc_open_rx) = mpsc::channel::<()>(1);

    // Create the data channel BEFORE create_offer — webrtc-rs needs the
    // m-line in the SDP.
    let dc = client_pc
        .create_data_channel("openhost", Some(RTCDataChannelInit::default()))
        .await
        .expect("client DC");

    // Signal when the DC is ready to accept sends (SCTP stream open on
    // both sides). Listening only to `on_peer_connection_state_change
    // → Connected` isn't enough — DTLS can be done while the SCTP
    // association is still negotiating.
    {
        let dc_open_tx = dc_open_tx.clone();
        dc.on_open(Box::new(move || {
            let dc_open_tx = dc_open_tx.clone();
            Box::pin(async move {
                let _ = dc_open_tx.try_send(());
            })
        }));
    }

    wire_client_dc_capture(&dc, Arc::clone(&received), first_byte_tx);

    // Create and send the offer.
    let offer = client_pc
        .create_offer(None)
        .await
        .expect("client create_offer");
    client_pc
        .set_local_description(offer.clone())
        .await
        .expect("client set_local_description");

    // Drain client ICE so the offer SDP carries candidates.
    let mut client_gather = client_pc.gathering_complete_promise().await;
    let _ = client_gather.recv().await;
    let offer_sdp = client_pc.local_description().await.unwrap().sdp;

    // Verify the offerer asserted active (sanity: if webrtc-rs ever
    // changed this default we'd fail-fast right here, not via an obscure
    // DTLS error 2s later).
    assert!(
        offer_sdp.contains("a=setup:actpass") || offer_sdp.contains("a=setup:active"),
        "offer SDP didn't assert setup:active/actpass — webrtc-rs defaults changed?"
    );

    // Forward to the daemon.
    let answer_sdp = app.handle_offer(&offer_sdp).await.expect("daemon answers");

    // The daemon's answer must contain the cert fingerprint that pins
    // its published record.
    let expected_fp_colon = app.cert().fingerprint_colon_hex();
    assert!(
        answer_sdp
            .to_ascii_lowercase()
            .contains(&expected_fp_colon.to_ascii_lowercase()),
        "answer SDP missing expected fingerprint {expected_fp_colon}"
    );

    // Spec §3.1: the daemon MUST assert `a=setup:passive` in its answer.
    // The listener pins DTLSRole::Server via SettingEngine; this assertion
    // locks that invariant end-to-end. If webrtc-rs ever flips the mapping
    // between `DTLSRole::Server` and the emitted `a=setup:` value, we'd
    // fail-fast here instead of silently violating spec.
    assert!(
        answer_sdp.contains("a=setup:passive"),
        "answer SDP must assert a=setup:passive per spec \u{00a7}3.1; got:\n{answer_sdp}"
    );

    // Apply the answer.
    let answer = RTCSessionDescription::answer(answer_sdp).expect("parse answer");
    client_pc
        .set_remote_description(answer)
        .await
        .expect("client set_remote_description");

    // Wait for DTLS to complete on the client side.
    tokio::time::timeout(Duration::from_secs(5), connected_rx.recv())
        .await
        .expect("DTLS handshake timed out")
        .expect("connected channel closed");

    // Then wait for the SCTP data channel to open — webrtc-rs's DTLS
    // transport can reach Connected while the DC is still negotiating.
    tokio::time::timeout(Duration::from_secs(5), dc_open_rx.recv())
        .await
        .expect("data channel didn't open within 5s")
        .expect("dc_open channel closed");

    // Send a REQUEST_HEAD frame.
    let head_bytes = b"GET /hello HTTP/1.1\r\nHost: example\r\n\r\n";
    let req_head =
        Frame::new(FrameType::RequestHead, head_bytes.to_vec()).expect("REQUEST_HEAD frame");
    let req_end = Frame::new(FrameType::RequestEnd, vec![]).expect("REQUEST_END frame");
    let mut wire = Vec::new();
    req_head.encode(&mut wire);
    req_end.encode(&mut wire);
    dc.send(&Bytes::from(wire)).await.expect("client DC send");

    // Wait for the daemon's 502 response to arrive.
    tokio::time::timeout(Duration::from_secs(5), first_byte_rx.recv())
        .await
        .expect("timed out waiting for daemon response")
        .expect("response channel closed");

    // Give any trailing bytes a quick moment, then decode.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let bytes = received.lock().await.clone();

    let (first, consumed) = Frame::try_decode(&bytes)
        .expect("decode response head")
        .expect("response head present");
    assert_eq!(first.frame_type, FrameType::ResponseHead);
    let head_text = std::str::from_utf8(&first.payload).expect("response head is UTF-8");
    assert!(
        head_text.starts_with("HTTP/1.1 502 "),
        "unexpected response head: {head_text:?}"
    );

    let (second, _) = Frame::try_decode(&bytes[consumed..])
        .expect("decode response end")
        .expect("response end present");
    assert_eq!(second.frame_type, FrameType::ResponseEnd);
    assert!(second.payload.is_empty());

    // Clean shutdown.
    let shutdown_start = std::time::Instant::now();
    app.shutdown().await;
    let _ = client_pc.close().await;
    assert!(
        shutdown_start.elapsed() < Duration::from_secs(2),
        "shutdown took too long: {:?}",
        shutdown_start.elapsed()
    );
    Ok(())
}

fn wire_client_dc_capture(
    dc: &Arc<RTCDataChannel>,
    buffer: Arc<Mutex<Vec<u8>>>,
    first_byte_tx: mpsc::Sender<()>,
) {
    let buffer_for_msg = Arc::clone(&buffer);
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let buffer = Arc::clone(&buffer_for_msg);
        let first_byte_tx = first_byte_tx.clone();
        Box::pin(async move {
            let mut buf = buffer.lock().await;
            let was_empty = buf.is_empty();
            buf.extend_from_slice(&msg.data);
            if was_empty && !buf.is_empty() {
                let _ = first_byte_tx.try_send(());
            }
        })
    }));
}

/// Everything a test needs after a successful handshake: the client
/// PC, its open data channel, a byte accumulator for inbound frames,
/// and a `first_byte` signal. `received.lock().await.clone()` reads the
/// accumulated DC bytes at any moment.
struct ClientSession {
    client_pc: Arc<webrtc::peer_connection::RTCPeerConnection>,
    dc: Arc<RTCDataChannel>,
    received: Arc<Mutex<Vec<u8>>>,
    first_byte_rx: mpsc::Receiver<()>,
}

impl ClientSession {
    async fn close(self) {
        let _ = self.dc.close().await;
        let _ = self.client_pc.close().await;
    }
}

/// Drive one full offer/answer/ICE/DTLS/SCTP setup between a fresh
/// client `RTCPeerConnection` and the daemon. Returns a [`ClientSession`]
/// the caller can send frames through.
async fn establish_connection(app: &App) -> ClientSession {
    let client_api = APIBuilder::new().build();
    let client_pc = Arc::new(
        client_api
            .new_peer_connection(RTCConfiguration::default())
            .await
            .expect("client pc builds"),
    );

    let (connected_tx, mut connected_rx) = mpsc::channel::<()>(1);
    {
        let connected_tx = connected_tx.clone();
        client_pc.on_peer_connection_state_change(Box::new(move |state| {
            let connected_tx = connected_tx.clone();
            Box::pin(async move {
                if state == RTCPeerConnectionState::Connected {
                    let _ = connected_tx.try_send(());
                }
            })
        }));
    }

    let received: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let (first_byte_tx, first_byte_rx) = mpsc::channel::<()>(1);
    let (dc_open_tx, mut dc_open_rx) = mpsc::channel::<()>(1);

    let dc = client_pc
        .create_data_channel("openhost", Some(RTCDataChannelInit::default()))
        .await
        .expect("client DC");

    {
        let dc_open_tx = dc_open_tx.clone();
        dc.on_open(Box::new(move || {
            let dc_open_tx = dc_open_tx.clone();
            Box::pin(async move {
                let _ = dc_open_tx.try_send(());
            })
        }));
    }
    wire_client_dc_capture(&dc, Arc::clone(&received), first_byte_tx);

    let offer = client_pc.create_offer(None).await.expect("create_offer");
    client_pc
        .set_local_description(offer)
        .await
        .expect("set_local_description");
    let mut client_gather = client_pc.gathering_complete_promise().await;
    let _ = client_gather.recv().await;
    let offer_sdp = client_pc.local_description().await.unwrap().sdp;

    let answer_sdp = app.handle_offer(&offer_sdp).await.expect("daemon answers");
    let answer = RTCSessionDescription::answer(answer_sdp).expect("parse answer");
    client_pc
        .set_remote_description(answer)
        .await
        .expect("set_remote_description");

    tokio::time::timeout(Duration::from_secs(5), connected_rx.recv())
        .await
        .expect("DTLS handshake timed out")
        .expect("connected channel closed");
    tokio::time::timeout(Duration::from_secs(5), dc_open_rx.recv())
        .await
        .expect("data channel didn't open within 5s")
        .expect("dc_open channel closed");

    ClientSession {
        client_pc,
        dc,
        received,
        first_byte_rx,
    }
}

#[tokio::test]
async fn request_body_and_end_still_yield_a_single_502_response() -> DaemonResult<()> {
    // PR #5 stub behaviour: the listener replies 502 on REQUEST_HEAD and
    // silently drops REQUEST_BODY / REQUEST_END / PING / PONG. This
    // test pins that behaviour so PR #6 (localhost forwarder) can't
    // silently regress the current contract while it restructures frame
    // handling.
    let (_tmp, app) = build_daemon().await;
    let mut session = establish_connection(&app).await;

    let head = Frame::new(
        FrameType::RequestHead,
        b"POST /x HTTP/1.1\r\nHost: example\r\nContent-Length: 5\r\n\r\n".to_vec(),
    )
    .unwrap();
    let body = Frame::new(FrameType::RequestBody, b"hello".to_vec()).unwrap();
    let end = Frame::new(FrameType::RequestEnd, vec![]).unwrap();
    let mut wire = Vec::new();
    head.encode(&mut wire);
    body.encode(&mut wire);
    end.encode(&mut wire);
    session.dc.send(&Bytes::from(wire)).await.expect("send");

    tokio::time::timeout(Duration::from_secs(5), session.first_byte_rx.recv())
        .await
        .expect("timed out waiting for daemon response")
        .expect("response channel closed");
    tokio::time::sleep(Duration::from_millis(100)).await;
    let bytes = session.received.lock().await.clone();

    let (head, consumed) = Frame::try_decode(&bytes).unwrap().unwrap();
    assert_eq!(head.frame_type, FrameType::ResponseHead);
    assert!(std::str::from_utf8(&head.payload)
        .unwrap()
        .starts_with("HTTP/1.1 502 "),);

    let (end, consumed2) = Frame::try_decode(&bytes[consumed..]).unwrap().unwrap();
    assert_eq!(end.frame_type, FrameType::ResponseEnd);
    assert!(end.payload.is_empty());

    // Exactly one 502 pair — no extra frames from the body/end being
    // interpreted as additional requests.
    assert_eq!(
        bytes.len(),
        consumed + consumed2,
        "daemon emitted unexpected extra bytes; drop semantics for body/end regressed"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn active_count_drops_after_peer_closes() -> DaemonResult<()> {
    // The daemon must not accumulate dead RTCPeerConnections. After a
    // client closes its side, the daemon-side PC transitions to
    // Disconnected/Closed and the prune hook MUST remove it from the
    // listener's active map.
    let (_tmp, app) = build_daemon().await;

    let session_a = establish_connection(&app).await;
    let session_b = establish_connection(&app).await;
    assert_eq!(
        app.listener().active_count().await,
        2,
        "both PCs should be tracked after setup"
    );

    // Close one client; the daemon's PC should soon transition and prune.
    session_a.close().await;

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if app.listener().active_count().await <= 1 {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "daemon still holds {} peer connections 10 s after one closed; \
                 prune hook regressed",
                app.listener().active_count().await
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    session_b.close().await;
    app.shutdown().await;
    Ok(())
}
