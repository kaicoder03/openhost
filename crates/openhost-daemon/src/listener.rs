//! WebRTC passive listener for inbound DTLS handshakes.
//!
//! The daemon publishes a record pinning its DTLS certificate fingerprint
//! (PR #2 / M3.1); PR #5 turns that record into something clients can
//! actually dial. [`PassivePeer::handle_offer`] takes a client-originated
//! SDP offer (provided by whatever signalling mechanism the caller has —
//! the offer-record poller is PR #7's job), builds an `RTCPeerConnection`
//! pre-loaded with the daemon's persisted cert, applies the offer,
//! creates an answer, drains ICE, and returns the answer SDP.
//!
//! Data channels opened on the accepted peer first run the spec §7.1
//! channel-binding handshake ([`crate::channel_binding`]). Only after
//! the client proves possession of its Ed25519 key and both sides agree
//! on the DTLS exporter secret does the listener accept REQUEST frames.
//! A `REQUEST_HEAD` after authentication runs through the configured
//! [`Forwarder`], or falls back to a stub `HTTP/1.1 502 Bad Gateway`
//! when no `[forward]` section is configured.

use crate::channel_binding::{
    ChannelBinder, ChannelBindingError, AUTH_NONCE_LEN, BINDING_TIMEOUT_SECS, EXPORTER_LABEL,
    EXPORTER_SECRET_LEN,
};
use crate::error::ListenerError;
use crate::forward::{ForwardResponse, Forwarder};
use crate::publish::SharedState;
use bytes::{Bytes, BytesMut};
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_core::wire::{Frame, FrameType, MAX_PAYLOAD_LEN};
use std::collections::HashMap;
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::sync::Mutex;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::dtls_transport::dtls_transport_state::RTCDtlsTransportState;
use webrtc::dtls_transport::RTCDtlsTransport;
use webrtc::peer_connection::certificate::RTCCertificate;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Ensures the rustls CryptoProvider is installed exactly once per
/// process. Required in rustls 0.23+ because the crate no longer picks
/// a default provider at compile time; we pick `ring` to keep binary
/// size modest and avoid the aws-lc-rs C build dependency.
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

fn install_crypto_provider_once() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => tracing::debug!("openhost-daemon: installed rustls `ring` crypto provider"),
            Err(_existing) => tracing::debug!(
                "openhost-daemon: rustls CryptoProvider already installed; using existing"
            ),
        }
    });
}

/// Default budget for `handle_offer`. Covers SDP apply + ICE trickle +
/// set_local_description. Tests can override via [`PassivePeer::with_offer_timeout`].
const DEFAULT_OFFER_TIMEOUT_SECS: u64 = 10;

/// Fixed 502 body the stub listener replies with on every `REQUEST_HEAD`.
/// Replaced by the real localhost-forward response in PR #6. The wire
/// format is HTTP/1.1 (spec §4 per frame type 0x11).
const RESPONSE_502_HEAD: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

/// Default request-body cap applied when the daemon has no `[forward]`
/// section configured — the stub 502 path still accumulates
/// `REQUEST_BODY` frames until `REQUEST_END` arrives, so without a cap
/// a hostile client could pile unbounded bytes into the per-DC
/// `RequestInProgress` buffer before we ever get to refuse them.
const STUB_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// Map key identifying one tracked `RTCPeerConnection`. We use the
/// `Arc::as_ptr` value: unique per Arc allocation, stable for the
/// lifetime of the map entry (because the entry keeps the Arc alive),
/// cheap to compute, and no dep on `uuid`.
type PcKey = usize;

fn pc_key(pc: &Arc<RTCPeerConnection>) -> PcKey {
    Arc::as_ptr(pc) as PcKey
}

/// The daemon's passive WebRTC peer.
///
/// Holds a single `webrtc::api::API` so every inbound offer shares one
/// `RTCCertificate` (the one whose fingerprint is pinned in the
/// published record). `PassivePeer` keeps active `RTCPeerConnection`s
/// alive inside a `Mutex<HashMap<PcKey, Arc<RTCPeerConnection>>>` so
/// they aren't dropped the moment `handle_offer` returns the answer
/// SDP, AND so they're removed when their state reaches a terminal
/// value (`Closed` / `Failed` / `Disconnected`). The prune hook is what
/// prevents a long-running daemon from accumulating dead PCs forever.
pub struct PassivePeer {
    api: Arc<API>,
    certificate: RTCCertificate,
    #[allow(dead_code)] // retained for future rotation-consistency checks
    identity: Arc<SigningKey>,
    #[allow(dead_code)] // read by future rotation-consistency checks
    state: Arc<SharedState>,
    active: Arc<Mutex<HashMap<PcKey, Arc<RTCPeerConnection>>>>,
    offer_timeout_secs: u64,
    /// Channel-binding helper built from the daemon's identity. The
    /// binder signs `AuthHost` payloads and verifies `AuthClient`
    /// signatures per spec §7.1.
    binder: Arc<ChannelBinder>,
    /// Localhost forwarder. `None` falls back to the PR #5 stub
    /// (`HTTP/1.1 502 Bad Gateway` on every `REQUEST_HEAD`) — a daemon
    /// without a `[forward]` config section stays serviceable as a
    /// pkarr-only host discovery target.
    forwarder: Option<Arc<Forwarder>>,
}

impl PassivePeer {
    /// Build a `PassivePeer` from an already-loaded [`RTCCertificate`]
    /// (obtained via [`crate::dtls_cert::load_or_generate`]), plus the
    /// daemon's identity and live shared state. The cert is cloned per
    /// accepted offer — webrtc-rs `RTCCertificate` is `Arc`-backed so
    /// cloning is cheap.
    pub async fn new(
        certificate: RTCCertificate,
        identity: Arc<SigningKey>,
        state: Arc<SharedState>,
        forwarder: Option<Arc<Forwarder>>,
    ) -> Result<Self, ListenerError> {
        // rustls 0.23+ requires a CryptoProvider before any TLS / DTLS
        // session is established. Install ring once per process; the
        // call is idempotent for subsequent PassivePeer::new calls.
        install_crypto_provider_once();

        // Pin the DTLS role to Server (passive) so the stack never tries
        // to pick active based on some SDP semantics it inferred. Spec
        // §3.1 says the daemon MUST be passive.
        let mut engine = SettingEngine::default();
        engine.set_answering_dtls_role(DTLSRole::Server)?;

        let api = APIBuilder::new().with_setting_engine(engine).build();

        let binder = Arc::new(ChannelBinder::new(identity.clone()));

        Ok(Self {
            api: Arc::new(api),
            certificate,
            identity,
            state,
            active: Arc::new(Mutex::new(HashMap::new())),
            offer_timeout_secs: DEFAULT_OFFER_TIMEOUT_SECS,
            binder,
            forwarder,
        })
    }

    /// Override the `handle_offer` timeout budget.
    ///
    /// **Note:** as of PR #5 no test actually exercises the timeout
    /// path (constructing an SDP that's valid enough to pass
    /// `check_setup_role_is_active` but hangs inside webrtc-rs's
    /// `set_remote_description` is awkward). If the webrtc crate ever
    /// changes its hang-on-malformed-offer behaviour, this timeout may
    /// stop firing silently.
    pub fn with_offer_timeout(mut self, secs: u64) -> Self {
        self.offer_timeout_secs = secs;
        self
    }

    /// Accept an inbound SDP offer and return the SDP answer.
    ///
    /// Rejects offers that don't assert `a=setup:active` (spec §3.1)
    /// before any `RTCPeerConnection` is built. The returned
    /// `RTCPeerConnection` is retained inside the `PassivePeer` so the
    /// DTLS handshake can actually complete — callers don't need to
    /// keep it alive themselves.
    pub async fn handle_offer(&self, offer_sdp: &str) -> Result<String, ListenerError> {
        // 1. Pre-validate the DTLS role asserted in the offer.
        check_setup_role_is_active(offer_sdp)?;

        // 2. Wrap the whole handshake in a timeout so a broken peer
        //    can't wedge the caller.
        let budget = std::time::Duration::from_secs(self.offer_timeout_secs);
        tokio::time::timeout(budget, self.negotiate(offer_sdp))
            .await
            .map_err(|_| ListenerError::Timeout {
                secs: self.offer_timeout_secs,
            })?
    }

    /// Number of currently-tracked peer connections. Used by tests and
    /// future diagnostics. Kept `pub` so integration tests that assert
    /// pruning behaviour can observe it.
    pub async fn active_count(&self) -> usize {
        self.active.lock().await.len()
    }

    /// Close every tracked peer connection and drop its slot.
    pub async fn shutdown(&self) {
        let peers = std::mem::take(&mut *self.active.lock().await);
        for (_key, pc) in peers {
            let _ = pc.close().await;
        }
    }

    async fn negotiate(&self, offer_sdp: &str) -> Result<String, ListenerError> {
        let config = RTCConfiguration {
            certificates: vec![self.certificate.clone()],
            ..Default::default()
        };
        let pc = Arc::new(self.api.new_peer_connection(config).await?);

        // Wire the DataChannel handler, the DTLS-state observer, and the
        // peer-connection-state prune hook BEFORE applying the remote
        // description — webrtc-rs fires handlers off internal event loops
        // that can race the DTLS handshake start.
        let dtls_transport = pc.sctp().transport();
        wire_data_channel_handler(
            Arc::clone(&pc),
            Arc::clone(&self.binder),
            dtls_transport,
            self.forwarder.clone(),
        );
        wire_dtls_state_observer(Arc::clone(&pc));
        wire_prune_on_terminal_state(Arc::clone(&pc), Arc::clone(&self.active));

        let offer = RTCSessionDescription::offer(offer_sdp.to_string())?;
        pc.set_remote_description(offer).await?;

        let answer = pc.create_answer(None).await?;
        pc.set_local_description(answer).await?;

        // Drain the trickle so the returned SDP carries every candidate.
        // Without this, the answer goes out with no `a=candidate:` lines
        // and the peer can't reach us.
        let mut gather_complete = pc.gathering_complete_promise().await;
        let _ = gather_complete.recv().await;

        let local_desc = pc
            .local_description()
            .await
            .ok_or(ListenerError::OfferParse(
                "local description missing after set_local_description",
            ))?;

        // Keep the PC alive so the DTLS handshake can complete after we
        // return the answer SDP. The prune hook wired above will remove
        // this entry on Closed / Failed / Disconnected.
        let key = pc_key(&pc);
        self.active.lock().await.insert(key, pc);

        Ok(local_desc.sdp)
    }
}

/// Validate `a=setup:` on a raw SDP string.
///
/// Spec §3.1 requires the client to assert `setup:active` and the
/// daemon to assert `setup:passive`. Standard WebRTC offerers (browsers,
/// webrtc-rs's own defaults) emit `setup:actpass` per RFC 5763 §5 —
/// "either role is acceptable, answerer chooses". Rejecting every
/// browser offer would make the protocol unusable, so the daemon
/// accepts `active` OR `actpass` here; its own answer still asserts
/// `passive` (guaranteed by `SettingEngine::set_answering_dtls_role(
/// DTLSRole::Server)` in [`PassivePeer::new`]).
///
/// Explicit `passive` in an offer IS rejected — that would flip the
/// DTLS roles against spec.
///
/// TODO(spec): `01-wire-format.md §3.1` reads as a strict
/// "MUST assert active" on offers. That wording should be softened to
/// "MUST assert active or actpass" in the v0.1 spec-freeze PR so the
/// text matches deployable clients.
fn check_setup_role_is_active(sdp: &str) -> Result<(), ListenerError> {
    let mut saw = None;
    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("a=setup:") {
            saw = Some(rest.trim().to_string());
            break;
        }
    }
    match saw.as_deref() {
        Some("active") | Some("actpass") => Ok(()),
        Some(other) => Err(ListenerError::SetupRoleMismatch {
            found: other.to_string(),
        }),
        None => Err(ListenerError::OfferParse(
            "offer SDP is missing a=setup: attribute",
        )),
    }
}

/// Log when DTLS reaches `Connected` state. The channel-binding
/// handshake itself fires per-data-channel in [`wire_frame_loop`] so it
/// can observe the first inbound bytes — this observer is debug-only.
fn wire_dtls_state_observer(pc: Arc<RTCPeerConnection>) {
    pc.sctp()
        .transport()
        .on_state_change(Box::new(move |state: RTCDtlsTransportState| {
            Box::pin(async move {
                tracing::debug!(?state, "openhostd: DTLS transport state change");
                if state == RTCDtlsTransportState::Connected {
                    tracing::info!("openhostd: DTLS handshake completed — data channel ready");
                }
            })
        }));
}

/// Register the peer-connection-state callback that prunes `active`
/// when this PC reaches a terminal state (Closed / Failed /
/// Disconnected). Captures only a `Weak` to the map + the PcKey
/// (`usize`), so the callback doesn't form an Arc cycle with the PC
/// itself — once the map removes the entry, both drop cleanly.
fn wire_prune_on_terminal_state(
    pc: Arc<RTCPeerConnection>,
    active: Arc<Mutex<HashMap<PcKey, Arc<RTCPeerConnection>>>>,
) {
    let key = pc_key(&pc);
    let weak_active = Arc::downgrade(&active);
    pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        let weak_active = weak_active.clone();
        Box::pin(async move {
            if matches!(
                state,
                RTCPeerConnectionState::Closed
                    | RTCPeerConnectionState::Failed
                    | RTCPeerConnectionState::Disconnected
            ) {
                if let Some(active) = weak_active.upgrade() {
                    let removed = active.lock().await.remove(&key).is_some();
                    if removed {
                        tracing::debug!(
                            ?state,
                            pc_key = key,
                            "openhostd: pruning terminal peer connection"
                        );
                    }
                }
            }
        })
    }));
}

/// Register the `on_data_channel` handler that converts raw
/// DataChannel messages into framed responses.
fn wire_data_channel_handler(
    pc: Arc<RTCPeerConnection>,
    binder: Arc<ChannelBinder>,
    dtls_transport: Arc<RTCDtlsTransport>,
    forwarder: Option<Arc<Forwarder>>,
) {
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let label = dc.label().to_string();
        let binder = Arc::clone(&binder);
        let dtls_transport = Arc::clone(&dtls_transport);
        let forwarder = forwarder.clone();
        Box::pin(async move {
            tracing::debug!(label, "openhostd: data channel opened");
            wire_frame_loop(dc, binder, dtls_transport, forwarder).await;
        })
    }));
}

/// Per-data-channel request assembly state. Populated on `RequestHead`,
/// appended to on `RequestBody`, consumed on `RequestEnd`.
#[derive(Default)]
struct RequestInProgress {
    head_payload: Option<Vec<u8>>,
    body: BytesMut,
}

impl RequestInProgress {
    fn reset(&mut self) {
        self.head_payload = None;
        self.body.clear();
    }
}

/// Channel-binding state machine (spec §7.1). Progresses strictly:
/// `Pending` → `AwaitingAuthClient` (set from `on_open`) →
/// `Authenticated` (set after valid AuthClient). `Failed` is terminal
/// and triggers teardown.
enum BindingState {
    /// The data channel has not yet opened. The on_open callback will
    /// transition to `AwaitingAuthClient` once SCTP is ready and the
    /// nonce has been sent.
    Pending,
    /// AuthNonce has been sent; daemon is waiting for the client's
    /// AuthClient frame.
    AwaitingAuthClient { nonce: [u8; AUTH_NONCE_LEN] },
    /// AuthClient verified and AuthHost emitted. Forwarded traffic
    /// accepted from this point on.
    Authenticated {
        #[allow(dead_code)] // reserved for allowlist check in PR #7
        client_pk: PublicKey,
    },
    /// Terminal — any inbound frame triggers immediate teardown.
    Failed,
}

/// Attach `on_open` and `on_message` handlers to `dc`. The `on_open`
/// handler fires the channel-binding handshake (send AuthNonce, start a
/// timeout); the `on_message` handler dispatches frames to either the
/// binding verifier or the request forwarder depending on
/// [`BindingState`].
async fn wire_frame_loop(
    dc: Arc<RTCDataChannel>,
    binder: Arc<ChannelBinder>,
    dtls_transport: Arc<RTCDtlsTransport>,
    forwarder: Option<Arc<Forwarder>>,
) {
    let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let request: Arc<Mutex<RequestInProgress>> = Arc::new(Mutex::new(RequestInProgress::default()));
    let binding: Arc<Mutex<BindingState>> = Arc::new(Mutex::new(BindingState::Pending));

    // on_open: generate + send the 32-byte nonce, then arm the timeout.
    // Running here (rather than from the DTLS-state observer) guarantees
    // the SCTP stream is ready, so the first outbound frame actually
    // reaches the peer.
    {
        let dc_for_open = Arc::clone(&dc);
        let binding_for_open = Arc::clone(&binding);
        dc.on_open(Box::new(move || {
            let dc = Arc::clone(&dc_for_open);
            let binding = Arc::clone(&binding_for_open);
            Box::pin(async move {
                let nonce = ChannelBinder::fresh_nonce();
                {
                    let mut s = binding.lock().await;
                    *s = BindingState::AwaitingAuthClient { nonce };
                }
                let frame = Frame::new(FrameType::AuthNonce, nonce.to_vec())
                    .expect("32-byte nonce always fits the frame cap");
                if let Err(err) = send_frame(&dc, frame).await {
                    tracing::warn!(?err, "openhostd: failed to send AuthNonce; closing DC");
                    let _ = dc.close().await;
                    return;
                }

                // Timeout enforcer. If binding hasn't advanced past
                // `AwaitingAuthClient` inside BINDING_TIMEOUT_SECS, emit
                // an ERROR frame and tear down.
                let dc_for_timeout = Arc::clone(&dc);
                let binding_for_timeout = Arc::clone(&binding);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(BINDING_TIMEOUT_SECS)).await;
                    let mut s = binding_for_timeout.lock().await;
                    if matches!(*s, BindingState::AwaitingAuthClient { .. }) {
                        *s = BindingState::Failed;
                        drop(s);
                        tracing::warn!(
                            timeout_secs = BINDING_TIMEOUT_SECS,
                            "openhostd: channel binding timed out; tearing down DC"
                        );
                        let _ = send_error_frame(&dc_for_timeout, "channel binding timeout").await;
                        let _ = dc_for_timeout.close().await;
                    }
                });
            })
        }));
    }

    let dc_handler = Arc::clone(&dc);
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let buffer = Arc::clone(&buffer);
        let request = Arc::clone(&request);
        let binding = Arc::clone(&binding);
        let binder = Arc::clone(&binder);
        let dtls_transport = Arc::clone(&dtls_transport);
        let dc = Arc::clone(&dc_handler);
        let forwarder = forwarder.clone();
        Box::pin(async move {
            let mut buf = buffer.lock().await;
            buf.extend_from_slice(&msg.data);
            loop {
                match Frame::try_decode(&buf) {
                    Ok(Some((frame, consumed))) => {
                        buf.drain(..consumed);
                        let outcome = dispatch_frame(
                            &frame,
                            &dc,
                            &binding,
                            &binder,
                            &dtls_transport,
                            &request,
                            forwarder.as_deref(),
                        )
                        .await;
                        if let FrameOutcome::Teardown = outcome {
                            let _ = dc.close().await;
                            buf.clear();
                            request.lock().await.reset();
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!(?err, "openhostd: malformed frame; tearing down channel");
                        let _ = send_error_frame(&dc, "malformed frame").await;
                        let _ = dc.close().await;
                        buf.clear();
                        request.lock().await.reset();
                        break;
                    }
                }
            }
        })
    }));
}

enum FrameOutcome {
    Continue,
    Teardown,
}

/// Top-level dispatch. Gates on [`BindingState`]: until the channel
/// binding is `Authenticated`, the ONLY frame accepted from the peer is
/// `AuthClient`. Anything else produces an `ERROR` frame + teardown.
async fn dispatch_frame(
    frame: &Frame,
    dc: &RTCDataChannel,
    binding: &Arc<Mutex<BindingState>>,
    binder: &ChannelBinder,
    dtls_transport: &RTCDtlsTransport,
    request: &Arc<Mutex<RequestInProgress>>,
    forwarder: Option<&Forwarder>,
) -> FrameOutcome {
    // Look up binding state, then release the lock before awaiting
    // webrtc I/O (the send + close paths below both await).
    let binding_snapshot = {
        let guard = binding.lock().await;
        match &*guard {
            BindingState::Pending => BindingSnapshot::Pending,
            BindingState::AwaitingAuthClient { nonce } => {
                BindingSnapshot::AwaitingAuthClient { nonce: *nonce }
            }
            BindingState::Authenticated { .. } => BindingSnapshot::Authenticated,
            BindingState::Failed => BindingSnapshot::Failed,
        }
    };

    match binding_snapshot {
        BindingSnapshot::Failed => {
            // Timeout or earlier failure already closed the DC; anything
            // landing here is racy and safe to swallow.
            return FrameOutcome::Teardown;
        }
        BindingSnapshot::Pending => {
            tracing::warn!(
                ?frame.frame_type,
                "openhostd: frame arrived before data channel opened; tearing down"
            );
            let _ = send_error_frame(dc, "frame before channel opened").await;
            return FrameOutcome::Teardown;
        }
        BindingSnapshot::AwaitingAuthClient { nonce } => {
            if frame.frame_type != FrameType::AuthClient {
                tracing::warn!(
                    ?frame.frame_type,
                    "openhostd: non-AuthClient frame before binding completed; tearing down"
                );
                let _ = send_error_frame(
                    dc,
                    &format!(
                        "expected AuthClient before any other frame (got 0x{:02x})",
                        frame.frame_type.as_u8()
                    ),
                )
                .await;
                return FrameOutcome::Teardown;
            }
            return handle_auth_client(frame, dc, binding, binder, dtls_transport, &nonce).await;
        }
        BindingSnapshot::Authenticated => {
            // Fall through into the request-handling arm below.
        }
    }

    match frame.frame_type {
        FrameType::RequestHead => {
            let mut req = request.lock().await;
            req.head_payload = Some(frame.payload.clone());
            req.body.clear();
            FrameOutcome::Continue
        }
        FrameType::RequestBody => {
            let mut req = request.lock().await;
            if req.head_payload.is_none() {
                tracing::warn!("openhostd: REQUEST_BODY before REQUEST_HEAD; tearing down");
                let _ = send_error_frame(dc, "REQUEST_BODY before REQUEST_HEAD").await;
                return FrameOutcome::Teardown;
            }
            // Always cap the accumulated body — even on the stub-502 path
            // where the bytes will be discarded on REQUEST_END. Without
            // this, a hostile client could inflate memory on a daemon
            // with no `[forward]` configured.
            let cap = forwarder
                .map(Forwarder::max_body_bytes)
                .unwrap_or(STUB_MAX_BODY_BYTES);
            if req.body.len().saturating_add(frame.payload.len()) > cap {
                tracing::warn!(cap, "openhostd: request body exceeded cap; tearing down");
                let _ = send_error_frame(dc, "request body too large").await;
                return FrameOutcome::Teardown;
            }
            req.body.extend_from_slice(&frame.payload);
            FrameOutcome::Continue
        }
        FrameType::RequestEnd => {
            let (head, body) = {
                let mut req = request.lock().await;
                match req.head_payload.take() {
                    Some(h) => (h, std::mem::take(&mut req.body)),
                    None => {
                        tracing::warn!("openhostd: REQUEST_END without REQUEST_HEAD; tearing down");
                        let _ = send_error_frame(dc, "REQUEST_END without REQUEST_HEAD").await;
                        return FrameOutcome::Teardown;
                    }
                }
            };
            match forwarder {
                Some(fwd) => match fwd.forward(&head, body.freeze()).await {
                    Ok(resp) => {
                        if let Err(err) = emit_response(dc, resp).await {
                            tracing::warn!(?err, "openhostd: failed to emit response frames");
                        }
                    }
                    Err(err) => {
                        tracing::warn!(?err, "openhostd: forwarder failed; replying 502");
                        let _ = emit_stub_502(dc).await;
                    }
                },
                None => {
                    // PR #5 stub path — no forwarder configured.
                    let _ = emit_stub_502(dc).await;
                }
            }
            FrameOutcome::Continue
        }
        FrameType::Ping => {
            let pong = Frame::new(FrameType::Pong, Vec::new()).expect("Pong is empty");
            let mut out = Vec::with_capacity(5);
            pong.encode(&mut out);
            if let Err(err) = dc.send(&Bytes::from(out)).await {
                tracing::warn!(?err, "openhostd: failed to send Pong");
            }
            FrameOutcome::Continue
        }
        FrameType::Error => {
            let payload = String::from_utf8_lossy(&frame.payload);
            tracing::warn!(
                client_error = %payload,
                "openhostd: client sent ERROR frame; tearing down channel"
            );
            FrameOutcome::Teardown
        }
        // Keepalive responses from the client are fine to ignore — the
        // daemon doesn't currently initiate Pings.
        FrameType::Pong => FrameOutcome::Continue,
        // Response frames coming from the CLIENT side are protocol
        // violations; REQUEST_* is the only direction we accept.
        FrameType::ResponseHead
        | FrameType::ResponseBody
        | FrameType::ResponseEnd
        | FrameType::WsUpgrade
        | FrameType::WsFrame => {
            tracing::warn!(
                ?frame.frame_type,
                "openhostd: client sent unexpected frame type; tearing down"
            );
            let _ = send_error_frame(dc, "unexpected frame type from client").await;
            FrameOutcome::Teardown
        }
        // Auth frames after binding is complete are a protocol violation.
        // A client retrying binding mid-session would also land here —
        // spec §7.1 says binding runs once per DC; re-binding requires
        // tearing the channel down and dialling again.
        FrameType::AuthNonce | FrameType::AuthClient | FrameType::AuthHost => {
            tracing::warn!(
                ?frame.frame_type,
                "openhostd: auth frame after binding completed; tearing down"
            );
            let _ = send_error_frame(dc, "auth frame after binding completed").await;
            FrameOutcome::Teardown
        }
    }
}

/// Snapshot of [`BindingState`] used by [`dispatch_frame`] to hold no
/// lock across `await` points while still branching on state.
enum BindingSnapshot {
    Pending,
    AwaitingAuthClient { nonce: [u8; AUTH_NONCE_LEN] },
    Authenticated,
    Failed,
}

/// Verify an inbound `AuthClient` frame, and if it passes:
///   1. Reply with `AuthHost`.
///   2. Transition the binding state to `Authenticated`.
///
/// Any failure (bad payload, bad signature, exporter error) emits an
/// `ERROR` frame, marks state `Failed`, and requests teardown.
async fn handle_auth_client(
    frame: &Frame,
    dc: &RTCDataChannel,
    binding: &Arc<Mutex<BindingState>>,
    binder: &ChannelBinder,
    dtls_transport: &RTCDtlsTransport,
    nonce: &[u8; AUTH_NONCE_LEN],
) -> FrameOutcome {
    let exporter = match dtls_transport
        .export_keying_material(EXPORTER_LABEL, EXPORTER_SECRET_LEN)
        .await
    {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(?err, "openhostd: DTLS exporter failed; tearing down");
            let _ = send_error_frame(dc, "DTLS exporter failed").await;
            *binding.lock().await = BindingState::Failed;
            return FrameOutcome::Teardown;
        }
    };
    if exporter.len() != EXPORTER_SECRET_LEN {
        tracing::warn!(
            got = exporter.len(),
            "openhostd: DTLS exporter returned wrong length; tearing down"
        );
        let _ = send_error_frame(dc, "DTLS exporter returned wrong length").await;
        *binding.lock().await = BindingState::Failed;
        return FrameOutcome::Teardown;
    }

    let client_pk = match binder.verify_client_sig(&exporter, nonce, &frame.payload) {
        Ok(pk) => pk,
        Err(err) => {
            tracing::warn!(
                ?err,
                "openhostd: AuthClient verification failed; tearing down"
            );
            let reason = match err {
                ChannelBindingError::MalformedAuthClient(_) => "malformed AuthClient",
                ChannelBindingError::MalformedClientPk => "malformed client_pk",
                ChannelBindingError::VerifyFailed => "client signature failed to verify",
                _ => "channel binding failed",
            };
            let _ = send_error_frame(dc, reason).await;
            *binding.lock().await = BindingState::Failed;
            return FrameOutcome::Teardown;
        }
    };

    let host_sig = match binder.sign_host(&exporter, nonce, &client_pk) {
        Ok(sig) => sig,
        Err(err) => {
            tracing::warn!(?err, "openhostd: sign_host failed; tearing down");
            let _ = send_error_frame(dc, "host signing failed").await;
            *binding.lock().await = BindingState::Failed;
            return FrameOutcome::Teardown;
        }
    };

    if let Err(err) = send_frame(
        dc,
        Frame::new(FrameType::AuthHost, host_sig.to_vec())
            .expect("64-byte host signature fits the frame cap"),
    )
    .await
    {
        tracing::warn!(?err, "openhostd: failed to send AuthHost; tearing down");
        *binding.lock().await = BindingState::Failed;
        return FrameOutcome::Teardown;
    }

    tracing::info!(
        client_pk = %client_pk,
        "openhostd: channel binding authenticated"
    );
    *binding.lock().await = BindingState::Authenticated { client_pk };
    FrameOutcome::Continue
}

/// Emit a forwarder response as `RESPONSE_HEAD` + `RESPONSE_BODY*` +
/// `RESPONSE_END`. Each frame is sent as its own SCTP message via
/// [`RTCDataChannel::send`]. Bundling everything into one `send`
/// overflows browser-side data-channel message caps (Chrome ≈ 256 KiB,
/// historically 64 KiB) — one-frame-per-message keeps us within
/// browser limits and also matches the "openhost frames are self-
/// contained" contract the spec implies.
///
/// Body chunks are bounded by [`MAX_PAYLOAD_LEN`] (16 MiB − 1) per
/// the wire codec; larger upstream bodies get split into multiple
/// `RESPONSE_BODY` frames.
async fn emit_response(dc: &RTCDataChannel, resp: ForwardResponse) -> Result<(), webrtc::Error> {
    send_frame(
        dc,
        Frame::new(FrameType::ResponseHead, resp.head_bytes).expect("response head is well-formed"),
    )
    .await?;

    let body = resp.body;
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + MAX_PAYLOAD_LEN).min(body.len());
        let slice = body.slice(offset..end);
        let body_frame = Frame::new(FrameType::ResponseBody, slice.to_vec())
            .expect("chunk length bounded by MAX_PAYLOAD_LEN");
        send_frame(dc, body_frame).await?;
        offset = end;
    }

    send_frame(
        dc,
        Frame::new(FrameType::ResponseEnd, Vec::new()).expect("ResponseEnd empty"),
    )
    .await?;
    Ok(())
}

/// Encode one frame and send it as its own data-channel message.
async fn send_frame(dc: &RTCDataChannel, frame: Frame) -> Result<(), webrtc::Error> {
    let mut buf = Vec::with_capacity(5 + frame.payload.len());
    frame.encode(&mut buf);
    dc.send(&Bytes::from(buf)).await?;
    Ok(())
}

/// Emit the PR #5 stub response: HTTP 502 head + empty body. Used when
/// no forwarder is configured AND as the fallback when the forwarder
/// errors (upstream unreachable, body too large, etc.).
async fn emit_stub_502(dc: &RTCDataChannel) -> Result<(), webrtc::Error> {
    send_frame(
        dc,
        Frame::new(FrameType::ResponseHead, RESPONSE_502_HEAD.to_vec())
            .expect("502 head payload is well-formed"),
    )
    .await?;
    send_frame(
        dc,
        Frame::new(FrameType::ResponseEnd, Vec::new()).expect("ResponseEnd has empty payload"),
    )
    .await?;
    Ok(())
}

/// Send a spec §5 `ERROR` frame with a short diagnostic string. Best
/// effort — failure is logged by the caller but doesn't prevent
/// teardown.
async fn send_error_frame(dc: &RTCDataChannel, reason: &str) -> Result<(), webrtc::Error> {
    send_frame(
        dc,
        Frame::new(FrameType::Error, reason.as_bytes().to_vec())
            .expect("error diagnostic is well-formed"),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal SDP fixtures — only the bit `check_setup_role_is_active`
    // looks at matters for these unit tests.
    fn sdp_with_setup(role: &str) -> String {
        format!(
            "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             c=IN IP4 0.0.0.0\r\na=setup:{role}\r\n"
        )
    }

    #[test]
    fn setup_role_active_is_accepted() {
        assert!(check_setup_role_is_active(&sdp_with_setup("active")).is_ok());
    }

    #[test]
    fn setup_role_passive_is_rejected() {
        let err = check_setup_role_is_active(&sdp_with_setup("passive")).unwrap_err();
        assert!(matches!(
            err,
            ListenerError::SetupRoleMismatch { ref found } if found == "passive"
        ));
    }

    #[test]
    fn setup_role_actpass_is_accepted() {
        // See the doc-comment on `check_setup_role_is_active`: offers
        // asserting `actpass` are valid WebRTC (browser default) and the
        // daemon's own answer still asserts `passive`, so spec §3.1's
        // role-split invariant is preserved.
        assert!(check_setup_role_is_active(&sdp_with_setup("actpass")).is_ok());
    }

    #[test]
    fn offer_missing_setup_line_is_rejected() {
        let sdp = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n";
        let err = check_setup_role_is_active(sdp).unwrap_err();
        assert!(matches!(err, ListenerError::OfferParse(_)));
    }

    #[test]
    fn response_502_frame_pair_encodes_and_decodes() {
        let head = Frame::new(FrameType::ResponseHead, RESPONSE_502_HEAD.to_vec()).unwrap();
        let end = Frame::new(FrameType::ResponseEnd, Vec::new()).unwrap();

        let mut wire = Vec::new();
        head.encode(&mut wire);
        end.encode(&mut wire);

        let (decoded_head, consumed_head) = Frame::try_decode(&wire).unwrap().unwrap();
        assert_eq!(decoded_head.frame_type, FrameType::ResponseHead);
        assert_eq!(decoded_head.payload, RESPONSE_502_HEAD);

        let (decoded_end, consumed_end) =
            Frame::try_decode(&wire[consumed_head..]).unwrap().unwrap();
        assert_eq!(decoded_end.frame_type, FrameType::ResponseEnd);
        assert!(decoded_end.payload.is_empty());
        assert_eq!(consumed_head + consumed_end, wire.len());
    }
}
