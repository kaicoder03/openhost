//! Shared test helpers for the openhost-daemon integration tests.
//!
//! Each integration test file imports this via `mod support;`. Cargo
//! treats every `tests/*.rs` as its own crate, so we can't share types
//! through `pub use` at the crate level — this module is duplicated
//! into each test binary that needs it.
//!
//! The helpers drive a real client-side `RTCPeerConnection`, perform the
//! PR #5.5 channel-binding handshake, and hand back a [`ClientSession`]
//! that tests can send REQUEST frames through.

#![allow(dead_code)] // different test files use different helpers

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::Signer as _;
use openhost_core::crypto::auth_bytes_bound;
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_core::wire::{Frame, FrameType};
use openhost_daemon::channel_binding::{
    AUTH_HOST_PAYLOAD_LEN, AUTH_NONCE_LEN, EXPORTER_LABEL, EXPORTER_SECRET_LEN,
};
use openhost_daemon::App;
use openhost_pkarr::{Resolve, Result as PkarrResult, Transport};
use pkarr::{SignedPacket, Timestamp};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// No-op pkarr transport used by every integration test — the listener
/// doesn't read from the transport, so tests that only exercise the
/// WebRTC/frame path don't need a real relay.
#[derive(Default)]
pub struct NoopTransport;

#[async_trait]
impl Transport for NoopTransport {
    async fn publish(&self, _packet: &SignedPacket, _cas: Option<Timestamp>) -> PkarrResult<()> {
        Ok(())
    }
}

/// A [`Transport`] that records every published packet as serialized
/// bytes (via `SignedPacket::serialize`, which prepends the 8-byte
/// last_seen prefix that `deserialize` expects).
///
/// Used by PR #7a's offer-poll integration tests to inspect the TXT
/// records the daemon emits in response to a scripted offer.
#[derive(Default)]
pub struct CaptureTransport {
    pub packets: StdMutex<Vec<Vec<u8>>>,
}

impl CaptureTransport {
    pub fn snapshot(&self) -> Vec<Vec<u8>> {
        self.packets.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for CaptureTransport {
    async fn publish(&self, packet: &SignedPacket, _cas: Option<Timestamp>) -> PkarrResult<()> {
        self.packets.lock().unwrap().push(packet.serialize());
        Ok(())
    }
}

/// A [`Resolve`] that serves whatever `SignedPacket` is stashed under a
/// given pkarr pubkey. Tests stage a sealed offer via `set_packet`
/// before kicking the poller.
#[derive(Default)]
pub struct ScriptedResolve {
    // Key: pkarr pubkey's 32-byte representation (z-base-32 form).
    // Value: serialized `SignedPacket` bytes (via `serialize()`).
    map: StdMutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl ScriptedResolve {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Stash a packet to be returned for `pubkey`. Later calls overwrite.
    pub fn set_packet(&self, pubkey: &PublicKey, packet: &SignedPacket) {
        let key = pubkey.to_zbase32();
        self.map.lock().unwrap().insert(key, packet.serialize());
    }

    /// Remove the stashed packet for `pubkey`. Subsequent resolves return None.
    pub fn clear(&self, pubkey: &PublicKey) {
        let key = pubkey.to_zbase32();
        self.map.lock().unwrap().remove(&key);
    }
}

#[async_trait]
impl Resolve for ScriptedResolve {
    async fn resolve_most_recent(&self, pubkey: &pkarr::PublicKey) -> Option<SignedPacket> {
        let key = pubkey.to_z32();
        let raw = self.map.lock().unwrap().get(&key).cloned()?;
        SignedPacket::deserialize(&raw).ok()
    }
}

/// Opaque test-side client context: holds the PC, DC, the inbound-byte
/// accumulator, and the client's Ed25519 key. `received` only holds
/// frames delivered AFTER the channel-binding handshake completed —
/// [`establish_connection`] drains the binding frames internally.
pub struct ClientSession {
    pub client_pc: Arc<RTCPeerConnection>,
    pub dc: Arc<RTCDataChannel>,
    pub received: Arc<Mutex<Vec<u8>>>,
    pub client_sk: SigningKey,
    pub client_pk: PublicKey,
    pub host_pk: PublicKey,
}

impl ClientSession {
    pub async fn close(self) {
        let _ = self.dc.close().await;
        let _ = self.client_pc.close().await;
    }
}

/// Options for [`establish_connection_opts`]. The default runs the full
/// PR #5.5 binding dance and returns a session ready for REQUEST frames.
pub struct EstablishOpts {
    /// Client-side Ed25519 key to use. `None` generates a fresh key.
    pub client_sk: Option<SigningKey>,
    /// Binding behaviour. Most tests use `BindingMode::Honest`.
    pub binding: BindingMode,
}

impl Default for EstablishOpts {
    fn default() -> Self {
        Self {
            client_sk: None,
            binding: BindingMode::Honest,
        }
    }
}

/// How the test client should behave during the binding handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingMode {
    /// Run the binding handshake correctly. Standard path used by every
    /// regression test.
    Honest,
    /// Skip AuthClient entirely and immediately send a REQUEST_HEAD
    /// instead. The daemon MUST tear the channel down.
    SendRequestBeforeBinding,
    /// Send AuthClient with a valid-shape payload but a bit-flipped
    /// signature. The daemon MUST tear the channel down.
    TamperSignature,
    /// Send AuthClient with client_pk = A but a signature signed by
    /// client_pk = B. The daemon MUST tear the channel down.
    SwapPubkey,
    /// Never send AuthClient at all; wait for the daemon's timeout.
    TimeoutByNeverAuthing,
}

/// Build a fresh daemon `App` wired to the no-op transport.
pub async fn build_noop_daemon_with_config(
    cfg: openhost_daemon::Config,
) -> (tempfile::TempDir, App) {
    let tmp = tempfile::TempDir::new().unwrap();
    let app = App::build_with_transport(cfg, Arc::new(NoopTransport) as Arc<dyn Transport>)
        .await
        .expect("daemon builds");
    (tmp, app)
}

/// Default test config with no forwarder (stub-502 mode).
pub fn test_config_noforward(dir: &tempfile::TempDir) -> openhost_daemon::Config {
    use openhost_daemon::config::{
        Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, PkarrConfig,
    };
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: dir.path().join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: vec![],
            republish_secs: 3600,
            offer_poll: Default::default(),
        },
        dtls: DtlsConfig {
            cert_path: dir.path().join("dtls.pem"),
            rotate_secs: 3600,
        },
        forward: None,
        log: LogConfig::default(),
        pairing: Default::default(),
    }
}

/// Drive a full WebRTC handshake + PR #5.5 binding handshake between a
/// fresh client PC and `app`. Returns a [`ClientSession`] sitting on an
/// authenticated data channel. Panics on any failure.
pub async fn establish_connection(app: &App) -> ClientSession {
    establish_connection_honest(app).await
}

/// Full-featured helper: drives the WebRTC handshake and then performs
/// the binding dance according to `opts.binding`. Returns `Err(session)`
/// when the caller asked for a misbehaviour (so they can still assert on
/// teardown state); returns `Ok(session)` on successful authenticated
/// binding.
pub async fn establish_connection_opts(
    app: &App,
    opts: EstablishOpts,
) -> Result<ClientSession, ClientSession> {
    let client_sk = opts.client_sk.unwrap_or_else(SigningKey::generate_os_rng);
    let client_pk = client_sk.public_key();
    let host_pk = app.identity().public_key();

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
    let received_for_dc = Arc::clone(&received);
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let received = Arc::clone(&received_for_dc);
        Box::pin(async move {
            let mut buf = received.lock().await;
            buf.extend_from_slice(&msg.data);
        })
    }));

    let offer = client_pc.create_offer(None).await.expect("create_offer");
    client_pc
        .set_local_description(offer)
        .await
        .expect("set_local_description");
    let mut gather = client_pc.gathering_complete_promise().await;
    let _ = gather.recv().await;
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

    // Perform the binding dance. Returns Ok(()) after AuthHost is
    // observed + drained; Err(()) if the caller asked for a misbehaviour.
    let session = ClientSession {
        client_pc,
        dc,
        received,
        client_sk,
        client_pk,
        host_pk,
    };

    match run_binding(&session, opts.binding).await {
        BindingOutcome::Authenticated => Ok(session),
        BindingOutcome::Misbehaved => Err(session),
    }
}

/// Infallible wrapper around [`establish_connection_opts`] for the honest
/// path; panics if binding fails.
pub async fn establish_connection_honest(app: &App) -> ClientSession {
    match establish_connection_opts(app, EstablishOpts::default()).await {
        Ok(s) => s,
        Err(_) => panic!("honest binding should always authenticate"),
    }
}

enum BindingOutcome {
    Authenticated,
    Misbehaved,
}

async fn run_binding(session: &ClientSession, mode: BindingMode) -> BindingOutcome {
    // Wait for the daemon's AuthNonce frame.
    let nonce = match wait_for_auth_nonce(session).await {
        Some(n) => n,
        None => return BindingOutcome::Misbehaved,
    };

    match mode {
        BindingMode::Honest => {
            let payload =
                sign_auth_client(session, &session.client_sk, &session.client_pk, &nonce).await;
            send_frame(&session.dc, FrameType::AuthClient, payload).await;
            // Wait for AuthHost + drain it, then return.
            wait_and_drain_auth_host(session).await;
            BindingOutcome::Authenticated
        }
        BindingMode::SendRequestBeforeBinding => {
            // Skip AuthClient; send a REQUEST_HEAD. Daemon must reject.
            send_frame(
                &session.dc,
                FrameType::RequestHead,
                b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
            )
            .await;
            BindingOutcome::Misbehaved
        }
        BindingMode::TamperSignature => {
            let mut payload =
                sign_auth_client(session, &session.client_sk, &session.client_pk, &nonce).await;
            payload[64] ^= 0x01; // flip a bit in the signature
            send_frame(&session.dc, FrameType::AuthClient, payload).await;
            BindingOutcome::Misbehaved
        }
        BindingMode::SwapPubkey => {
            // client_pk = A, but sig was produced by B.
            // payload[..32] = a_pk, payload[32..] = sig-by-B over
            // auth_bytes(host, a_pk, nonce). Verification fails because
            // B didn't produce the signature the verifier will check.
            let other_sk = SigningKey::generate_os_rng();
            let a_pk = session.client_pk;
            let payload = sign_auth_client(session, &other_sk, &a_pk, &nonce).await;
            send_frame(&session.dc, FrameType::AuthClient, payload).await;
            BindingOutcome::Misbehaved
        }
        BindingMode::TimeoutByNeverAuthing => {
            // Sit idle. Daemon will time out + tear down.
            BindingOutcome::Misbehaved
        }
    }
}

async fn wait_for_auth_nonce(session: &ClientSession) -> Option<[u8; AUTH_NONCE_LEN]> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut consumed = 0usize;
    loop {
        let bytes = session.received.lock().await.clone();
        if let Ok(Some((frame, used))) = Frame::try_decode(&bytes[consumed..]) {
            consumed += used;
            if frame.frame_type == FrameType::AuthNonce && frame.payload.len() == AUTH_NONCE_LEN {
                // Drain consumed bytes from `received` so subsequent
                // tests don't see the auth handshake frames.
                drain_prefix(&session.received, consumed).await;
                let mut nonce = [0u8; AUTH_NONCE_LEN];
                nonce.copy_from_slice(&frame.payload);
                return Some(nonce);
            }
            // Skip any other frame that somehow arrived (shouldn't happen
            // pre-binding but be defensive).
            continue;
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_and_drain_auth_host(session: &ClientSession) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let bytes = session.received.lock().await.clone();
        if let Ok(Some((frame, used))) = Frame::try_decode(&bytes) {
            if frame.frame_type == FrameType::AuthHost
                && frame.payload.len() == AUTH_HOST_PAYLOAD_LEN
            {
                drain_prefix(&session.received, used).await;
                return;
            }
        }
        if std::time::Instant::now() >= deadline {
            panic!("AuthHost not received within 5s");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn drain_prefix(received: &Mutex<Vec<u8>>, n: usize) {
    let mut buf = received.lock().await;
    let take = n.min(buf.len());
    buf.drain(..take);
}

async fn sign_auth_client(
    session: &ClientSession,
    signing_key: &SigningKey,
    pk_in_payload: &PublicKey,
    nonce: &[u8; AUTH_NONCE_LEN],
) -> Vec<u8> {
    let exporter = client_exporter_secret(&session.client_pc).await;
    let host_pk_bytes = session.host_pk.to_bytes();
    let pk_bytes = pk_in_payload.to_bytes();
    let auth =
        auth_bytes_bound(&exporter, &host_pk_bytes, &pk_bytes, nonce).expect("32-byte exporter");
    let sig = signing_key.as_dalek().sign(&auth);
    let mut payload = Vec::with_capacity(32 + 64);
    payload.extend_from_slice(&pk_bytes);
    payload.extend_from_slice(&sig.to_bytes());
    payload
}

async fn client_exporter_secret(pc: &Arc<RTCPeerConnection>) -> Vec<u8> {
    pc.sctp()
        .transport()
        .export_keying_material(EXPORTER_LABEL, EXPORTER_SECRET_LEN)
        .await
        .expect("client DTLS exporter succeeds after handshake")
}

async fn send_frame(dc: &RTCDataChannel, ty: FrameType, payload: Vec<u8>) {
    let frame = Frame::new(ty, payload).expect("frame constructs");
    let mut out = Vec::new();
    frame.encode(&mut out);
    dc.send(&Bytes::from(out)).await.expect("DC send");
}
