//! In-process two-peer test for the daemon's WebRTC listener.
//!
//! The daemon runs its normal `App::build_with_transport` flow; a
//! second `RTCPeerConnection` plays the client side, asserting
//! `a=setup:active`. SDPs are exchanged through `App::handle_offer`
//! directly — the offer-record polling + discovery plumbing is PR #7's
//! job; this PR only proves the listener library is correct.
//!
//! Assertions:
//! 1. A valid `setup:active` offer completes the DTLS handshake **and
//!    the PR #5.5 channel-binding handshake**.
//! 2. The negotiated answer contains the daemon's own DTLS fingerprint.
//! 3. A `REQUEST_HEAD` frame sent over the data channel produces a
//!    `RESPONSE_HEAD` + `RESPONSE_END` pair, the head carrying a
//!    `502 Bad Gateway` body.
//! 4. An offer asserting `a=setup:passive` is rejected before any peer
//!    connection is allocated.
//! 5. `app.shutdown()` terminates the listener promptly.

mod support;

use bytes::Bytes;
use openhost_core::wire::{Frame, FrameType};
use openhost_daemon::error::ListenerError;
use openhost_daemon::{DaemonError, Result as DaemonResult};
use std::time::Duration;
use support::{build_noop_daemon_with_config, establish_connection, test_config_noforward};

#[tokio::test]
async fn offer_with_passive_setup_role_is_rejected_before_any_pc_is_built() -> DaemonResult<()> {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let bad_sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                   c=IN IP4 0.0.0.0\r\na=setup:passive\r\n";

    let err = app
        .handle_offer(bad_sdp, openhost_pkarr::BindingMode::Exporter)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        DaemonError::Listener(ListenerError::SetupRoleMismatch { ref found }) if found == "passive"
    ));
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn offer_missing_setup_line_is_rejected() -> DaemonResult<()> {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;
    let bad_sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
    let err = app
        .handle_offer(bad_sdp, openhost_pkarr::BindingMode::Exporter)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        DaemonError::Listener(ListenerError::OfferParse(_))
    ));
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dtls_handshake_and_502_response_roundtrip() -> DaemonResult<()> {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let session = establish_connection(&app).await;

    // Send a REQUEST_HEAD + REQUEST_END pair — binding is already done
    // inside `establish_connection`, so the daemon answers with the
    // stub 502 pair.
    let head_bytes = b"GET /hello HTTP/1.1\r\nHost: example\r\n\r\n";
    let req_head =
        Frame::new(FrameType::RequestHead, head_bytes.to_vec()).expect("REQUEST_HEAD frame");
    let req_end = Frame::new(FrameType::RequestEnd, vec![]).expect("REQUEST_END frame");
    let mut wire = Vec::new();
    req_head.encode(&mut wire);
    req_end.encode(&mut wire);
    session
        .dc
        .send(&Bytes::from(wire))
        .await
        .expect("client DC send");

    // Wait up to 5s for the 502 response pair to arrive.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let bytes = session.received.lock().await.clone();
        if let Ok(Some((head, consumed))) = Frame::try_decode(&bytes) {
            assert_eq!(head.frame_type, FrameType::ResponseHead);
            let head_text = std::str::from_utf8(&head.payload).expect("UTF-8");
            assert!(
                head_text.starts_with("HTTP/1.1 502 "),
                "unexpected response head: {head_text:?}"
            );
            if let Ok(Some((end, _))) = Frame::try_decode(&bytes[consumed..]) {
                assert_eq!(end.frame_type, FrameType::ResponseEnd);
                assert!(end.payload.is_empty());
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for daemon 502 response");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let shutdown_start = std::time::Instant::now();
    session.close().await;
    app.shutdown().await;
    assert!(
        shutdown_start.elapsed() < Duration::from_secs(2),
        "shutdown took too long: {:?}",
        shutdown_start.elapsed()
    );
    Ok(())
}

#[tokio::test]
async fn request_body_and_end_still_yield_a_single_502_response() -> DaemonResult<()> {
    // PR #5 stub behaviour: the listener replies 502 on REQUEST_HEAD and
    // silently drops REQUEST_BODY / REQUEST_END / PING / PONG. This
    // test pins that behaviour so PR #6 (localhost forwarder) can't
    // silently regress the current contract while it restructures frame
    // handling.
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;
    let session = establish_connection(&app).await;

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

    // Poll until we see a decoded ResponseEnd.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let bytes = session.received.lock().await.clone();
        let mut offset = 0;
        let mut saw_head = false;
        let mut saw_end = false;
        while offset < bytes.len() {
            match Frame::try_decode(&bytes[offset..]) {
                Ok(Some((frame, used))) => {
                    offset += used;
                    match frame.frame_type {
                        FrameType::ResponseHead => {
                            saw_head = true;
                            let text = std::str::from_utf8(&frame.payload).unwrap();
                            assert!(text.starts_with("HTTP/1.1 502 "));
                        }
                        FrameType::ResponseEnd => {
                            saw_end = true;
                        }
                        other => panic!("unexpected frame {other:?}"),
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
        if saw_head && saw_end {
            assert_eq!(
                bytes.len(),
                offset,
                "daemon emitted unexpected extra bytes; drop semantics regressed"
            );
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for full 502 response");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

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
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let session_a = establish_connection(&app).await;
    let session_b = establish_connection(&app).await;
    assert_eq!(
        app.listener().active_count().await,
        2,
        "both PCs should be tracked after setup"
    );

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
