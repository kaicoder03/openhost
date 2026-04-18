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
//! Data channels opened on the accepted peer run inbound bytes through
//! [`openhost_core::wire::Frame::try_decode`]; any `REQUEST_HEAD` frame
//! is answered with an `HTTP/1.1 502 Bad Gateway` `RESPONSE_HEAD` +
//! empty `RESPONSE_END`. The real localhost forwarder lands in PR #6.
//!
//! **Channel binding (spec §7.1 / RFC 8844 mitigation) is NOT
//! implemented in this PR.** The `webrtc` v0.17.x stable line does not
//! publicly expose RFC 5705 exporter keying material; PR #5.5 will add
//! that via a patched fork. See the `TODO(spec §7.1 / PR #5.5)` marker
//! in [`PassivePeer::wire_dtls_state_observer`].

use crate::error::ListenerError;
use crate::publish::SharedState;
use bytes::Bytes;
use openhost_core::identity::SigningKey;
use openhost_core::wire::{Frame, FrameType};
use std::sync::{Arc, Once};
use tokio::sync::Mutex;

/// Ensures the rustls CryptoProvider is installed exactly once per
/// process. Required in rustls 0.23+ because the crate no longer picks
/// a default provider at compile time; we pick `ring` to keep binary
/// size modest and avoid the aws-lc-rs C build dependency.
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

fn install_crypto_provider_once() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        // The install may fail if a provider was already installed
        // earlier in the process (e.g. by a different test harness);
        // ignoring the `Err` is safe — we only need one to be active.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::dtls_transport::dtls_transport_state::RTCDtlsTransportState;
use webrtc::peer_connection::certificate::RTCCertificate;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

/// Default budget for `handle_offer`. Covers SDP apply + ICE trickle +
/// set_local_description. Tests can override via [`PassivePeer::with_offer_timeout`].
const DEFAULT_OFFER_TIMEOUT_SECS: u64 = 10;

/// Fixed 502 body the stub listener replies with on every `REQUEST_HEAD`.
/// Replaced by the real localhost-forward response in PR #6. The wire
/// format is HTTP/1.1 (spec §4 per frame type 0x11).
pub(crate) const RESPONSE_502_HEAD: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";

/// The daemon's passive WebRTC peer.
///
/// Holds a single `webrtc::api::API` so every inbound offer shares one
/// `RTCCertificate` (the one whose fingerprint is pinned in the
/// published record). `PassivePeer` keeps active `RTCPeerConnection`s
/// alive inside a `Mutex<Vec<Arc<RTCPeerConnection>>>` so they aren't
/// dropped the moment `handle_offer` returns the answer SDP.
pub struct PassivePeer {
    api: Arc<API>,
    certificate: RTCCertificate,
    #[allow(dead_code)] // wired in PR #5.5 for channel-binding signatures
    identity: Arc<SigningKey>,
    #[allow(dead_code)] // read by future rotation-consistency checks
    state: Arc<SharedState>,
    active: Mutex<Vec<Arc<RTCPeerConnection>>>,
    offer_timeout_secs: u64,
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

        Ok(Self {
            api: Arc::new(api),
            certificate,
            identity,
            state,
            active: Mutex::new(Vec::new()),
            offer_timeout_secs: DEFAULT_OFFER_TIMEOUT_SECS,
        })
    }

    /// Override the `handle_offer` timeout budget. Tests use this to
    /// fail fast when an offer is intentionally malformed past the SDP
    /// layer.
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
    /// future diagnostics.
    pub async fn active_count(&self) -> usize {
        self.active.lock().await.len()
    }

    /// Close every tracked peer connection and drop its slot.
    pub async fn shutdown(&self) {
        let peers = std::mem::take(&mut *self.active.lock().await);
        for pc in peers {
            let _ = pc.close().await;
        }
    }

    async fn negotiate(&self, offer_sdp: &str) -> Result<String, ListenerError> {
        let config = RTCConfiguration {
            certificates: vec![self.certificate.clone()],
            ..Default::default()
        };
        let pc = Arc::new(self.api.new_peer_connection(config).await?);

        // Wire the DataChannel handler and the DTLS-state observer BEFORE
        // applying the remote description — webrtc-rs fires handlers off
        // internal event loops that can race the DTLS handshake start.
        wire_data_channel_handler(Arc::clone(&pc));
        wire_dtls_state_observer(Arc::clone(&pc), self.certificate.clone());

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
        // return the answer SDP.
        self.active.lock().await.push(pc);

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

/// Log when DTLS reaches `Connected` state and mark the channel-binding
/// TODO. Called once per `RTCPeerConnection` during setup.
fn wire_dtls_state_observer(pc: Arc<RTCPeerConnection>, _cert: RTCCertificate) {
    pc.sctp()
        .transport()
        .on_state_change(Box::new(move |state: RTCDtlsTransportState| {
            Box::pin(async move {
                tracing::debug!(?state, "openhostd: DTLS transport state change");
                if state == RTCDtlsTransportState::Connected {
                    tracing::info!("openhostd: DTLS handshake completed — data channel ready");
                    // TODO(spec §7.1 / PR #5.5): RFC 5705 exporter keying
                    // material is not exposed by webrtc-rs v0.17.x. Once we
                    // vendor a patched fork that adds an
                    // `export_keying_material` accessor on
                    // `RTCDtlsTransport`, this is where the channel-binding
                    // handshake fires:
                    //
                    //   let exporter = transport.export_keying_material(
                    //       b"EXPORTER-openhost-auth-v1",
                    //       &openhost_core::crypto::exporter_context(
                    //           &host_pk, &client_pk, &nonce),
                    //       32).await?;
                    //   let auth = openhost_core::crypto::auth_bytes(&exporter)?;
                    //   send(nonce || sign(auth));
                    //
                    // Until then the daemon is vulnerable to RFC 8844
                    // unknown-key-share attacks from any offerer that
                    // possesses our fingerprint. No openhost offerer
                    // exists yet (client-side WebRTC is PR #8), so the
                    // attack surface is currently empty.
                    tracing::warn!(
                        "openhostd: channel binding unimplemented (see spec §7.1 / PR #5.5)"
                    );
                }
            })
        }));
}

/// Register the `on_data_channel` handler that converts raw
/// DataChannel messages into framed responses.
fn wire_data_channel_handler(pc: Arc<RTCPeerConnection>) {
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let label = dc.label().to_string();
        Box::pin(async move {
            tracing::debug!(label, "openhostd: data channel opened");
            wire_frame_loop(dc).await;
        })
    }));
}

/// Attach a `on_message` handler to `dc` that accumulates bytes, decodes
/// frames, and replies `502 Bad Gateway` to every `REQUEST_HEAD`.
async fn wire_frame_loop(dc: Arc<RTCDataChannel>) {
    let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let dc_handler = Arc::clone(&dc);
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let buffer = Arc::clone(&buffer);
        let dc = Arc::clone(&dc_handler);
        Box::pin(async move {
            let mut buf = buffer.lock().await;
            buf.extend_from_slice(&msg.data);
            loop {
                match Frame::try_decode(&buf) {
                    Ok(Some((frame, consumed))) => {
                        buf.drain(..consumed);
                        if let Err(err) = handle_frame(&frame, &dc).await {
                            tracing::warn!(?err, "openhostd: failed to send response frame");
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        tracing::warn!(?err, "openhostd: malformed frame; tearing down channel");
                        let _ = dc.close().await;
                        buf.clear();
                        break;
                    }
                }
            }
        })
    }));
}

/// Handle one decoded inbound frame. For this PR every `REQUEST_HEAD`
/// is answered with a `502 Bad Gateway`; body/end/keepalive/error
/// frames are silently dropped until PR #6 wires the forwarder.
async fn handle_frame(frame: &Frame, dc: &RTCDataChannel) -> Result<(), webrtc::Error> {
    if frame.frame_type != FrameType::RequestHead {
        // Ignore body/end/keepalive/error for now. PR #6 will stitch
        // REQUEST_BODY → REQUEST_END into an upstream hyper call.
        return Ok(());
    }
    let response_head = Frame::new(FrameType::ResponseHead, RESPONSE_502_HEAD.to_vec())
        .expect("502 head payload is well-formed");
    let response_end =
        Frame::new(FrameType::ResponseEnd, Vec::new()).expect("ResponseEnd has empty payload");

    let mut out = Vec::with_capacity(RESPONSE_502_HEAD.len() + 16);
    response_head.encode(&mut out);
    response_end.encode(&mut out);
    dc.send(&Bytes::from(out)).await?;
    Ok(())
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
