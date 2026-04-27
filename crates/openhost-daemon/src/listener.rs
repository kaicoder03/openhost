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
use crate::forward::{ForwardOutcome, ForwardResponse, Forwarder, WebSocketUpgrade};
use crate::publish::SharedState;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_core::wire::{Frame, FrameType};
use openhost_pkarr::{AnswerBlob, BindingMode, BlobCandidate, CandidateType, SetupRole};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
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

/// Bundled STUN server used to discover the daemon's server-
/// reflexive (srflx) ICE candidate. Without at least one STUN server
/// in `RTCConfiguration.ice_servers`, webrtc-rs produces only
/// `host`-type candidates — i.e. the local LAN / VPC address — which
/// is useless for dials from outside the local network.
///
/// Exactly one STUN server is configured: each binding response from
/// a different STUN host produces its own `srflx` candidate line, and
/// the sealed answer record's BEP44 1000-byte `v` cap doesn't have
/// headroom for duplicates. Cloudflare's STUN is preferred over
/// Google for privacy. A failover list (with eviction under cap
/// pressure) is tracked for a later PR.
fn default_stun_servers() -> Vec<webrtc::ice_transport::ice_server::RTCIceServer> {
    vec![webrtc::ice_transport::ice_server::RTCIceServer {
        urls: vec!["stun:stun.cloudflare.com:3478".to_string()],
        ..Default::default()
    }]
}

/// Extract the subset of an SDP answer the compact answer-blob needs.
///
/// Parses `a=ice-ufrag:`, `a=ice-pwd:`, `a=setup:`, and every
/// `a=candidate:` line. Applies the same candidate-hygiene filters the
/// legacy trim path used: component-1-only (SCTP data channels use
/// `a=rtcp-mux` so component 2 is dead freight) and IPv4-only (IPv6
/// answers routinely blew past BEP44's 1000-byte `v` cap on
/// dual-stack hosts; see PR #31). Malformed `a=candidate:` lines are
/// skipped with a `debug!` rather than rejected so a webrtc-rs format
/// drift doesn't fail the whole handshake.
fn sdp_to_answer_blob(sdp: &str) -> Result<AnswerBlob, ListenerError> {
    let mut ice_ufrag: Option<String> = None;
    let mut ice_pwd: Option<String> = None;
    let mut setup: Option<SetupRole> = None;
    let mut candidates: Vec<BlobCandidate> = Vec::new();

    for raw_line in sdp.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("a=ice-ufrag:") {
            ice_ufrag = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=ice-pwd:") {
            ice_pwd = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=setup:") {
            setup = match rest.trim() {
                "active" => Some(SetupRole::Active),
                "passive" => Some(SetupRole::Passive),
                // webrtc-rs answers always pick a concrete role, so
                // `actpass` / `holdconn` in the answer SDP is either a
                // spec violation or a severe bug — refuse to encode.
                other => {
                    return Err(ListenerError::OfferParse(match other {
                        "actpass" => {
                            "answer SDP a=setup:actpass is invalid (answerer must pick a role)"
                        }
                        "holdconn" => "answer SDP a=setup:holdconn is unsupported",
                        _ => "answer SDP a=setup has unknown value",
                    }))
                }
            };
        } else if let Some(rest) = line.strip_prefix("a=candidate:") {
            if let Some(cand) = parse_candidate_line_for_blob(rest) {
                if candidates.len() < openhost_pkarr::MAX_BLOB_CANDIDATES {
                    candidates.push(cand);
                } else {
                    tracing::debug!(
                        "openhostd: extra candidate beyond MAX_BLOB_CANDIDATES dropped"
                    );
                }
            }
        }
    }

    Ok(AnswerBlob {
        ice_ufrag: ice_ufrag.ok_or(ListenerError::OfferParse("answer SDP missing a=ice-ufrag"))?,
        ice_pwd: ice_pwd.ok_or(ListenerError::OfferParse("answer SDP missing a=ice-pwd"))?,
        setup: setup.ok_or(ListenerError::OfferParse("answer SDP missing a=setup"))?,
        candidates,
    })
}

/// Parse the post-`a=candidate:` portion of one candidate line into a
/// `BlobCandidate`, or `None` if the line fails any hygiene filter
/// (component 2, IPv6, unknown type, unparseable port/ip, too few
/// tokens). Returning `None` silently is intentional — callers log
/// at `debug` and continue so one malformed line doesn't abort the
/// whole answer.
fn parse_candidate_line_for_blob(rest: &str) -> Option<BlobCandidate> {
    let mut toks = rest.split_whitespace();
    let _foundation = toks.next()?;
    let component = toks.next()?;
    if component != "1" {
        return None;
    }
    let transport = toks.next()?;
    if !transport.eq_ignore_ascii_case("udp") {
        return None;
    }
    let _priority = toks.next()?;
    let addr_s = toks.next()?;
    let port_s = toks.next()?;
    if toks.next() != Some("typ") {
        return None;
    }
    let typ_s = toks.next()?;
    let ip: std::net::IpAddr = addr_s.parse().ok()?;
    let port: u16 = port_s.parse().ok()?;
    // IPv4 only — mirrors the PR #31 filter on the client side; IPv6 is
    // reserved for a future encoder bump when multi-fragment headroom
    // is explicit.
    let std::net::IpAddr::V4(_) = ip else {
        return None;
    };
    let typ = match typ_s {
        "host" => CandidateType::Host,
        "srflx" => CandidateType::Srflx,
        "prflx" => CandidateType::Prflx,
        "relay" => CandidateType::Relay,
        _ => return None,
    };
    Some(BlobCandidate { typ, ip, port })
}

#[cfg(test)]
mod sdp_blob_tests {
    use super::{parse_candidate_line_for_blob, sdp_to_answer_blob};
    use openhost_pkarr::{CandidateType, SetupRole};

    const SAMPLE: &str = "v=0\r\n\
                          o=- 0 0 IN IP4 0.0.0.0\r\n\
                          s=-\r\n\
                          a=ice-ufrag:abcd\r\n\
                          a=ice-pwd:0123456789abcdefghij!@\r\n\
                          a=setup:passive\r\n\
                          a=candidate:111 1 udp 2130706431 10.0.0.5 1000 typ host\r\n\
                          a=candidate:111 2 udp 2130706431 10.0.0.5 1000 typ host\r\n\
                          a=candidate:222 1 udp 1694498815 1.2.3.4 2000 typ srflx raddr 0.0.0.0 rport 2000\r\n\
                          a=candidate:222 2 udp 1694498815 1.2.3.4 2000 typ srflx raddr 0.0.0.0 rport 2000\r\n\
                          a=candidate:333 1 udp 2130706431 fe80::1 3000 typ host\r\n\
                          a=end-of-candidates\r\n";

    #[test]
    fn sdp_to_answer_blob_extracts_ufrag_pwd_setup_candidates() {
        let blob = sdp_to_answer_blob(SAMPLE).unwrap();
        assert_eq!(blob.ice_ufrag, "abcd");
        assert_eq!(blob.ice_pwd, "0123456789abcdefghij!@");
        assert_eq!(blob.setup, SetupRole::Passive);
        // Expect exactly 2 candidates: the two component-1 IPv4 entries.
        // Component-2 entries dropped, the IPv6 host dropped.
        assert_eq!(blob.candidates.len(), 2);
        assert!(matches!(blob.candidates[0].typ, CandidateType::Host));
        assert!(matches!(blob.candidates[1].typ, CandidateType::Srflx));
        assert_eq!(
            blob.candidates[0].ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(blob.candidates[0].port, 1000);
    }

    #[test]
    fn sdp_to_answer_blob_errors_when_ufrag_missing() {
        let bad = "v=0\r\na=setup:passive\r\na=ice-pwd:0123456789abcdefghij!@\r\n";
        assert!(sdp_to_answer_blob(bad).is_err());
    }

    #[test]
    fn parse_candidate_line_drops_component_2() {
        let drop = parse_candidate_line_for_blob("111 2 udp 2130706431 10.0.0.5 1000 typ host");
        assert!(drop.is_none());
    }

    #[test]
    fn parse_candidate_line_drops_ipv6() {
        let drop = parse_candidate_line_for_blob("222 1 udp 1 fe80::1 1000 typ host");
        assert!(drop.is_none());
    }

    #[test]
    fn parse_candidate_line_drops_malformed_tokens() {
        assert!(parse_candidate_line_for_blob("notenoughtoken").is_none());
    }
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
    /// SHA-256 over the DER encoding of the daemon's own DTLS cert.
    /// Used by the `CertFp` channel-binding path — both sides
    /// (spec/04-security.md §4.1) MUST hash the *host's* cert, not the
    /// remote peer's. On the daemon that means our own cert, not the
    /// client's (which is what `get_remote_certificate()` returns).
    local_dtls_fp: [u8; 32],
    #[allow(dead_code)] // read by future rotation-consistency checks
    state: Arc<SharedState>,
    active: Arc<Mutex<HashMap<PcKey, Arc<RTCPeerConnection>>>>,
    offer_timeout_secs: u64,
    /// Channel-binding timeout in seconds. Stored atomically so tests
    /// can shrink it after the peer is wrapped in an `Arc`.
    binding_timeout_secs: Arc<AtomicU64>,
    /// When `true`, `negotiate` skips `gathering_complete_promise()`
    /// so the answer SDP doesn't accumulate ICE candidates. Intended
    /// ONLY for in-process end-to-end tests where the full ICE SDP
    /// overflows the BEP44 1000-byte cap when folded into the
    /// daemon's pkarr packet. Default: `false`.
    skip_ice_gather: Arc<AtomicBool>,
    /// Channel-binding helper built from the daemon's identity. The
    /// binder signs `AuthHost` payloads and verifies `AuthClient`
    /// signatures per spec §7.1.
    binder: Arc<ChannelBinder>,
    /// TURN credential (deterministic in the daemon's public key)
    /// the listener presents to its OWN embedded TURN relay when
    /// it self-allocates a relay candidate for ICE. Empty string
    /// when the daemon wasn't started with TURN enabled.
    turn_password: String,
    /// Additional ICE servers threaded in by the caller (e.g. `oh
    /// send` adds a public-internet TURN from env vars so
    /// cross-network dials can relay without the sender owning a
    /// public IP). Always appended to the listener's own STUN +
    /// embedded-TURN entries — never replaces them.
    extra_ice_servers: Vec<webrtc::ice_transport::ice_server::RTCIceServer>,
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
        local_dtls_fp: [u8; 32],
        identity: Arc<SigningKey>,
        state: Arc<SharedState>,
        forwarder: Option<Arc<Forwarder>>,
        extra_ice_servers: Vec<webrtc::ice_transport::ice_server::RTCIceServer>,
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
        // Filter ICE candidate gathering:
        //   - interface name NOT in {docker0, docker*, br-*, veth*, tap*}.
        //     These are local bridges with per-host-only routability;
        //     gathering them crowds out the real LAN interface and
        //     produces answers that no remote peer can connect to.
        //   - IP NOT IPv6 link-local (fe80::/10) — scope-required,
        //     can't be bound raw, and adds ~60-100 bytes of SDP each.
        engine.set_interface_filter(Box::new(|iface: &str| {
            !(iface.starts_with("docker")
                || iface.starts_with("br-")
                || iface.starts_with("veth")
                || iface.starts_with("tap"))
        }));
        // IPv4-only on the answer side too — mirror client filter
        // (webrtc_helpers.rs). Multi-family candidate sets blow out
        // the BEP44 1000-byte `v` cap on the fragmented answer record
        // and get silently evicted. Revisit when fragmentation has
        // more headroom (e.g. offer/answer move off the main packet).
        engine.set_ip_filter(Box::new(|ip: std::net::IpAddr| {
            matches!(ip, std::net::IpAddr::V4(_))
        }));

        let api = APIBuilder::new().with_setting_engine(engine).build();

        // Pre-compute our own TURN password — deterministic in the
        // daemon's pubkey, same value the embedded TURN server
        // authenticates against. Cheap, and we only need it once
        // per listener build.
        let turn_password = crate::turn_server::password_for_daemon(&identity.public_key());
        let binder = Arc::new(ChannelBinder::new(identity));

        Ok(Self {
            api: Arc::new(api),
            certificate,
            local_dtls_fp,
            state,
            active: Arc::new(Mutex::new(HashMap::new())),
            offer_timeout_secs: DEFAULT_OFFER_TIMEOUT_SECS,
            binding_timeout_secs: Arc::new(AtomicU64::new(BINDING_TIMEOUT_SECS)),
            skip_ice_gather: Arc::new(AtomicBool::new(false)),
            binder,
            turn_password,
            extra_ice_servers,
            forwarder,
        })
    }

    /// Build an `RTCIceServer` pointing at our OWN embedded TURN
    /// relay if one is advertised in the shared state. Returns
    /// `None` when `[turn] enabled = false` (or the endpoint hasn't
    /// been set yet — rare race at startup).
    fn turn_ice_server(&self) -> Option<webrtc::ice_transport::ice_server::RTCIceServer> {
        let ep = self.state.turn_endpoint()?;
        Some(webrtc::ice_transport::ice_server::RTCIceServer {
            urls: vec![format!("turn:{}:{}", ep.ip, ep.port)],
            username: crate::turn_server::TURN_USERNAME.to_owned(),
            credential: self.turn_password.clone(),
        })
    }

    /// Override the channel-binding timeout. Tests shorten this so the
    /// timeout regression test doesn't burn 10 s per run. Callable after
    /// the peer has been wrapped in an `Arc`.
    pub fn set_binding_timeout(&self, secs: u64) {
        self.binding_timeout_secs.store(secs, Ordering::Relaxed);
    }

    /// Skip waiting for ICE gather completion in `negotiate`. The
    /// emitted answer SDP will not carry any candidates — webrtc-rs
    /// will trickle them over the data channel instead. Intended ONLY
    /// for in-process end-to-end tests where the full ICE SDP would
    /// overflow the BEP44 1000-byte cap when folded into the main
    /// pkarr packet; DO NOT set in production.
    pub fn set_skip_ice_gather_for_tests(&self, skip: bool) {
        self.skip_ice_gather.store(skip, Ordering::Relaxed);
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

    /// Accept an inbound SDP offer and return the compact answer blob
    /// the caller will seal into the pkarr `_answer-*` records.
    ///
    /// Rejects offers that don't assert `a=setup:active` (spec §3.1)
    /// before any `RTCPeerConnection` is built. The returned
    /// `RTCPeerConnection` is retained inside the `PassivePeer` so the
    /// DTLS handshake can actually complete — callers don't need to
    /// keep it alive themselves.
    pub async fn handle_offer(
        &self,
        offer_sdp: &str,
        binding_mode: BindingMode,
    ) -> Result<AnswerBlob, ListenerError> {
        // 1. Pre-validate the DTLS role asserted in the offer.
        check_setup_role_is_active(offer_sdp)?;

        // 2. Wrap the whole handshake in a timeout so a broken peer
        //    can't wedge the caller.
        let budget = std::time::Duration::from_secs(self.offer_timeout_secs);
        tokio::time::timeout(budget, self.negotiate(offer_sdp, binding_mode))
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

    async fn negotiate(
        &self,
        offer_sdp: &str,
        binding_mode: BindingMode,
    ) -> Result<AnswerBlob, ListenerError> {
        // Build ICE servers: STUN for srflx, PLUS the daemon's own
        // embedded TURN relay (if running) so the listener itself
        // gathers a `relay` candidate. Without this the answer only
        // exposes host + srflx — and Chrome on the same machine
        // emits `.local` mDNS host candidates that webrtc-rs doesn't
        // resolve reliably, so no (host, *) pair ever succeeds. The
        // (relay, relay) pair via our TURN is always reachable over
        // loopback + LAN.
        let mut ice_servers = default_stun_servers();
        if let Some(turn_srv) = self.turn_ice_server() {
            ice_servers.push(turn_srv);
        }
        // Caller-supplied extras: e.g. a public-internet TURN on a
        // cloud VPS so peers on unrelated NATs (phone on cellular
        // + laptop on home WiFi) still get a reachable relay pair.
        ice_servers.extend(self.extra_ice_servers.iter().cloned());
        let config = RTCConfiguration {
            certificates: vec![self.certificate.clone()],
            ice_servers,
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
            Arc::clone(&self.binding_timeout_secs),
            self.forwarder.clone(),
            binding_mode,
            self.local_dtls_fp,
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
        //
        // `skip_ice_gather` short-circuits this for in-process tests
        // whose answer would otherwise exceed the BEP44 packet cap
        // (see `set_skip_ice_gather_for_tests`).
        if !self.skip_ice_gather.load(Ordering::Relaxed) {
            let mut gather_complete = pc.gathering_complete_promise().await;
            let _ = gather_complete.recv().await;
        }

        let local_desc = pc
            .local_description()
            .await
            .ok_or(ListenerError::OfferParse(
                "local description missing after set_local_description",
            ))?;

        // Project the answer SDP into the compact answer-blob shape.
        // The blob's candidate-hygiene filters (component-1-only,
        // IPv4-only) live inside `sdp_to_answer_blob`.
        let blob = sdp_to_answer_blob(&local_desc.sdp)?;
        // Diagnostic: surface the candidate set that made it into the
        // answer so operators can tell at a glance whether srflx
        // gathering succeeded. Each line is one candidate.
        for cand in &blob.candidates {
            tracing::info!(
                typ = ?cand.typ,
                ip = %cand.ip,
                port = cand.port,
                "openhostd: answer candidate",
            );
        }

        // Keep the PC alive so the DTLS handshake can complete after we
        // return the answer. The prune hook wired above will remove
        // this entry on Closed / Failed / Disconnected.
        let key = pc_key(&pc);
        self.active.lock().await.insert(key, pc);

        Ok(blob)
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
    binding_timeout_secs: Arc<AtomicU64>,
    forwarder: Option<Arc<Forwarder>>,
    binding_mode: BindingMode,
    local_dtls_fp: [u8; 32],
) {
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        let label = dc.label().to_string();
        let binder = Arc::clone(&binder);
        let dtls_transport = Arc::clone(&dtls_transport);
        let binding_timeout_secs = Arc::clone(&binding_timeout_secs);
        let forwarder = forwarder.clone();
        Box::pin(async move {
            tracing::debug!(label, ?binding_mode, "openhostd: data channel opened");
            wire_frame_loop(
                dc,
                binder,
                dtls_transport,
                binding_timeout_secs,
                forwarder,
                binding_mode,
                local_dtls_fp,
            )
            .await;
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
    binding_timeout_secs: Arc<AtomicU64>,
    forwarder: Option<Arc<Forwarder>>,
    binding_mode: BindingMode,
    local_dtls_fp: [u8; 32],
) {
    // Inbound frame buffer. Using BytesMut with an initial 64 KiB capacity
    // avoids immediate reallocations and replaces O(N) Vec::drain with
    // O(1) buf.advance.
    let buffer: Arc<Mutex<BytesMut>> = Arc::new(Mutex::new(BytesMut::with_capacity(64 * 1024)));
    let request: Arc<Mutex<RequestInProgress>> = Arc::new(Mutex::new(RequestInProgress::default()));
    let binding: Arc<Mutex<BindingState>> = Arc::new(Mutex::new(BindingState::Pending));
    // `Some(tx)` during an active WebSocket tunnel; `None` otherwise.
    // Incoming `WsFrame` frames push their payload into `tx`, which the
    // tunnel's upstream-writer task reads and relays to the upgraded
    // TCP socket. Arc'd so dispatch_frame can hold a short read lock
    // per frame without serialising the whole tunnel.
    let ws_tunnel: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<Bytes>>>> =
        Arc::new(Mutex::new(None));
    // Notified by `handle_auth_client` on success OR on terminal failure
    // so the timeout task exits early instead of sleeping its full budget
    // after binding has already resolved.
    let binding_done: Arc<Notify> = Arc::new(Notify::new());

    // on_open: generate + send the 32-byte nonce, then arm the timeout.
    // Running here (rather than from the DTLS-state observer) guarantees
    // the SCTP stream is ready, so the first outbound frame actually
    // reaches the peer.
    {
        let dc_for_open = Arc::clone(&dc);
        let binding_for_open = Arc::clone(&binding);
        let done_for_open = Arc::clone(&binding_done);
        dc.on_open(Box::new(move || {
            let dc = Arc::clone(&dc_for_open);
            let binding = Arc::clone(&binding_for_open);
            let binding_done = Arc::clone(&done_for_open);
            Box::pin(async move {
                let nonce = ChannelBinder::fresh_nonce();
                // NB(lock ordering): we release the binding lock before
                // the `send_frame(AuthNonce)` await. If the client races
                // us with an early `AuthClient`, `on_message` will now
                // observe `AwaitingAuthClient{nonce}` and run
                // verification correctly. An early non-`AuthClient`
                // frame is rejected by `dispatch_frame` in the same
                // state, which is also correct.
                {
                    let mut s = binding.lock().await;
                    *s = BindingState::AwaitingAuthClient { nonce };
                }
                let frame = Frame::new(FrameType::AuthNonce, nonce.to_vec())
                    .expect("32-byte nonce always fits the frame cap");
                if let Err(err) = send_frame(&dc, frame).await {
                    tracing::warn!(?err, "openhostd: failed to send AuthNonce; closing DC");
                    *binding.lock().await = BindingState::Failed;
                    binding_done.notify_waiters();
                    let _ = dc.close().await;
                    return;
                }

                // Timeout enforcer. Exits early if `handle_auth_client`
                // reports a terminal binding outcome via `binding_done`.
                let dc_for_timeout = Arc::clone(&dc);
                let binding_for_timeout = Arc::clone(&binding);
                let done_for_timeout = Arc::clone(&binding_done);
                let budget_secs = binding_timeout_secs.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(budget_secs)) => {},
                        _ = done_for_timeout.notified() => return,
                    }
                    let mut s = binding_for_timeout.lock().await;
                    if matches!(*s, BindingState::AwaitingAuthClient { .. }) {
                        *s = BindingState::Failed;
                        drop(s);
                        tracing::warn!(
                            timeout_secs = budget_secs,
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
        let binding_done = Arc::clone(&binding_done);
        let binder = Arc::clone(&binder);
        let dtls_transport = Arc::clone(&dtls_transport);
        let dc = Arc::clone(&dc_handler);
        let ws_tunnel = Arc::clone(&ws_tunnel);
        let forwarder = forwarder.clone();
        Box::pin(async move {
            let mut buf = buffer.lock().await;
            buf.put_slice(&msg.data);
            loop {
                match Frame::try_decode(&buf) {
                    Ok(Some((frame, consumed))) => {
                        buf.advance(consumed);
                        let outcome = dispatch_frame(
                            &frame,
                            &dc,
                            &binding,
                            &binding_done,
                            &binder,
                            &dtls_transport,
                            &request,
                            &ws_tunnel,
                            forwarder.as_deref(),
                            binding_mode,
                            &local_dtls_fp,
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
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
async fn dispatch_frame(
    frame: &Frame,
    dc: &Arc<RTCDataChannel>,
    binding: &Arc<Mutex<BindingState>>,
    binding_done: &Arc<Notify>,
    binder: &ChannelBinder,
    dtls_transport: &RTCDtlsTransport,
    request: &Arc<Mutex<RequestInProgress>>,
    ws_tunnel: &Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<Bytes>>>>,
    forwarder: Option<&Forwarder>,
    binding_mode: BindingMode,
    local_dtls_fp: &[u8; 32],
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
            // Timeout or earlier failure already closed the DC (and
            // notified the timeout task). Swallow the frame without
            // re-emitting an ERROR or re-closing.
            return FrameOutcome::Continue;
        }
        BindingSnapshot::Pending => {
            tracing::warn!(
                ?frame.frame_type,
                "openhostd: frame arrived before data channel opened; tearing down"
            );
            let _ = send_error_frame(dc, "frame before channel opened").await;
            *binding.lock().await = BindingState::Failed;
            binding_done.notify_waiters();
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
                *binding.lock().await = BindingState::Failed;
                binding_done.notify_waiters();
                return FrameOutcome::Teardown;
            }
            return handle_auth_client(
                frame,
                dc,
                binding,
                binding_done,
                binder,
                dtls_transport,
                &nonce,
                binding_mode,
                local_dtls_fp,
            )
            .await;
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
                    Ok(ForwardOutcome::Response(resp)) => {
                        if let Err(err) = emit_response(dc, resp).await {
                            tracing::warn!(?err, "openhostd: failed to emit response frames");
                        }
                    }
                    Ok(ForwardOutcome::WebSocket(upgrade)) => {
                        let ws_tunnel = Arc::clone(ws_tunnel);
                        if let Err(err) = start_websocket_tunnel(dc, upgrade, ws_tunnel).await {
                            tracing::warn!(
                                ?err,
                                "openhostd: failed to start websocket tunnel; replying 502"
                            );
                            let _ = emit_stub_502(dc).await;
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
        FrameType::WsFrame => {
            let tx_opt = ws_tunnel.lock().await.clone();
            match tx_opt {
                Some(tx) => {
                    if tx.send(Bytes::from(frame.payload.clone())).is_err() {
                        // Upstream tunnel task dropped the receiver →
                        // the upgraded TCP socket closed. Tear the DC
                        // down so the client notices.
                        tracing::info!("openhostd: websocket upstream closed; tearing down DC");
                        return FrameOutcome::Teardown;
                    }
                    FrameOutcome::Continue
                }
                None => {
                    tracing::warn!("openhostd: WS_FRAME before websocket upgrade; tearing down");
                    let _ = send_error_frame(dc, "WS_FRAME before upgrade").await;
                    FrameOutcome::Teardown
                }
            }
        }
        FrameType::WsUpgrade => {
            // WS_UPGRADE is reserved but unused in this release —
            // upgrades are driven by REQUEST_HEAD's `Upgrade:
            // websocket` header. Receiving it from a client is a
            // protocol violation.
            tracing::warn!("openhostd: unexpected WS_UPGRADE frame; tearing down");
            let _ = send_error_frame(dc, "WS_UPGRADE frames are reserved").await;
            FrameOutcome::Teardown
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
        // WsUpgrade + WsFrame are handled by their own arms above.
        FrameType::ResponseHead | FrameType::ResponseBody | FrameType::ResponseEnd => {
            tracing::warn!(
                ?frame.frame_type,
                "openhostd: client sent unexpected frame type; tearing down"
            );
            let _ = send_error_frame(dc, "unexpected frame type from client").await;
            FrameOutcome::Teardown
        }
        // Auth frames after binding is complete are a protocol violation.
        // Spec §7.1 says binding runs once per DC; a client wishing to
        // re-bind must open a new data channel.
        FrameType::AuthNonce | FrameType::AuthClient | FrameType::AuthHost => {
            tracing::warn!(
                ?frame.frame_type,
                "openhostd: auth frame after binding completed; tearing down"
            );
            let _ = send_error_frame(
                dc,
                "auth frame after binding completed; re-binding requires a new data channel",
            )
            .await;
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
///
/// `binding_mode` picks where the 32-byte channel-binding secret
/// comes from (see `spec/04-security.md §4.1`):
///
/// - [`BindingMode::Exporter`]: RFC 5705 DTLS exporter output with
///   label [`EXPORTER_LABEL`] — the original CLI path.
/// - [`BindingMode::CertFp`]: SHA-256 over the remote DTLS cert DER
///   (via `RTCDtlsTransport::get_remote_certificate`) — mandatory
///   for browser clients, which cannot reach the exporter today.
#[allow(clippy::too_many_arguments)]
async fn handle_auth_client(
    frame: &Frame,
    dc: &RTCDataChannel,
    binding: &Arc<Mutex<BindingState>>,
    binding_done: &Arc<Notify>,
    binder: &ChannelBinder,
    dtls_transport: &RTCDtlsTransport,
    nonce: &[u8; AUTH_NONCE_LEN],
    binding_mode: BindingMode,
    local_dtls_fp: &[u8; 32],
) -> FrameOutcome {
    let binding_secret =
        match derive_binding_secret(dtls_transport, binding_mode, local_dtls_fp).await {
            Ok(bytes) => bytes,
            Err(reason) => {
                tracing::warn!(
                    ?binding_mode,
                    reason,
                    "openhostd: binding-secret derivation failed; tearing down"
                );
                let _ = send_error_frame(dc, reason).await;
                *binding.lock().await = BindingState::Failed;
                binding_done.notify_waiters();
                return FrameOutcome::Teardown;
            }
        };

    let client_pk = match binder.verify_client_sig(&binding_secret, nonce, &frame.payload) {
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
            binding_done.notify_waiters();
            return FrameOutcome::Teardown;
        }
    };

    let host_sig = match binder.sign_host(&binding_secret, nonce, &client_pk) {
        Ok(sig) => sig,
        Err(err) => {
            tracing::warn!(?err, "openhostd: sign_host failed; tearing down");
            let _ = send_error_frame(dc, "host signing failed").await;
            *binding.lock().await = BindingState::Failed;
            binding_done.notify_waiters();
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
        binding_done.notify_waiters();
        return FrameOutcome::Teardown;
    }

    tracing::info!(
        client_pk = %client_pk,
        "openhostd: channel binding authenticated"
    );
    *binding.lock().await = BindingState::Authenticated { client_pk };
    binding_done.notify_waiters();
    FrameOutcome::Continue
}

/// Produce the 32-byte channel-binding secret that feeds
/// [`ChannelBinder::verify_client_sig`] + [`ChannelBinder::sign_host`],
/// branching on the client's advertised [`BindingMode`].
///
/// Returns a static `&str` reason on failure, suitable for the
/// `ERROR` frame the caller emits before teardown.
async fn derive_binding_secret(
    dtls_transport: &RTCDtlsTransport,
    binding_mode: BindingMode,
    local_dtls_fp: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    match binding_mode {
        BindingMode::Exporter => {
            let exporter = dtls_transport
                .export_keying_material(EXPORTER_LABEL, EXPORTER_SECRET_LEN)
                .await
                .map_err(|_| "DTLS exporter failed")?;
            if exporter.len() != EXPORTER_SECRET_LEN {
                return Err("DTLS exporter returned wrong length");
            }
            Ok(exporter)
        }
        BindingMode::CertFp => {
            // Spec/04-security.md §4.1 says both sides hash *the host's*
            // DTLS cert (the one pinned in the Pkarr record). Browser
            // peers hash the cert they see as "remote" — which is
            // ours. To symmetrise, WE hash OUR OWN cert here, not the
            // remote peer's cert. Using `get_remote_certificate()`
            // (client's cert from the daemon's perspective) would give
            // different bytes on each side and break AUTH_CLIENT
            // verification. Fixed in the compact-offer-blob PR — was
            // latent since PR #28.3 because the pre-compact-offer
            // dial path could not reach the binding step from a real
            // browser.
            Ok(local_dtls_fp.to_vec())
        }
    }
}

/// Emit a forwarder response as `RESPONSE_HEAD` + `RESPONSE_BODY*` +
/// `RESPONSE_END`. Each frame is sent as its own SCTP message via
/// [`RTCDataChannel::send`]. Bundling everything into one `send`
/// overflows browser-side data-channel message caps (Chrome ≈ 256 KiB,
/// historically 64 KiB) — one-frame-per-message keeps us within
/// browser limits and also matches the "openhost frames are self-
/// contained" contract the spec implies.
///
/// Start a WebSocket tunnel after a successful upstream 101. Emits
/// the 101 head as `RESPONSE_HEAD`, wires an mpsc channel into the
/// listener's per-DC `ws_tunnel` slot, and spawns two detached
/// tasks: one copies bytes from the upgraded upstream socket into
/// `WsFrame` frames on the DC, and one pulls bytes received as
/// `WsFrame` out of the mpsc channel and writes them to the socket.
/// Returns once both tasks are spawned; the tasks run until either
/// side closes.
async fn start_websocket_tunnel(
    dc: &Arc<RTCDataChannel>,
    upgrade: WebSocketUpgrade,
    ws_tunnel: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<Bytes>>>>,
) -> Result<(), webrtc::Error> {
    use hyper_util::rt::TokioIo;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Emit the 101 first so the client transitions to WS mode before
    // any WsFrame arrives.
    send_frame(
        dc,
        Frame::new(FrameType::ResponseHead, upgrade.head_bytes)
            .expect("response head is well-formed"),
    )
    .await?;

    // hyper's `Upgraded` implements hyper::rt::{Read, Write}. Wrap it
    // in TokioIo so we can use tokio's AsyncRead/AsyncWrite surface.
    let upstream = TokioIo::new(upgrade.upstream);
    let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);

    // Arm the ws_tunnel slot so inbound WsFrame routes to us.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    *ws_tunnel.lock().await = Some(tx);

    // Upstream → client: read bytes, wrap in WsFrame, send on DC.
    let dc_upstream = Arc::clone(dc);
    let ws_tunnel_up = Arc::clone(&ws_tunnel);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match upstream_r.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let frame = match Frame::new(FrameType::WsFrame, buf[..n].to_vec()) {
                        Ok(f) => f,
                        Err(e) => {
                            tracing::warn!(?e, "openhostd: ws_frame build failed; closing tunnel");
                            break;
                        }
                    };
                    let mut wire = Vec::with_capacity(n + 5);
                    frame.encode(&mut wire);
                    if dc_upstream.send(&Bytes::from(wire)).await.is_err() {
                        break;
                    }
                }
                Err(err) => {
                    tracing::debug!(?err, "openhostd: ws upstream read error; closing tunnel");
                    break;
                }
            }
        }
        // Upstream closed → clear the slot + close the DC so the
        // client stops trying to send further WsFrame.
        *ws_tunnel_up.lock().await = None;
        let _ = dc_upstream.close().await;
    });

    // Client → upstream: receive bytes via mpsc, write to socket.
    let ws_tunnel_down = Arc::clone(&ws_tunnel);
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if upstream_w.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = upstream_w.shutdown().await;
        *ws_tunnel_down.lock().await = None;
    });

    Ok(())
}

/// SCTP per-message ceiling for RESPONSE_BODY chunks. The wire
/// codec allows up to `MAX_PAYLOAD_LEN` (16 MiB), but SCTP itself
/// rejects individual messages above its negotiated MTU. 60 KiB
/// has comfortable headroom under every real-world SCTP
/// negotiation we've observed while keeping the per-message
/// overhead low.
const SCTP_SAFE_CHUNK_BYTES: usize = 60 * 1024;

/// Pause sending new body chunks once the data-channel's send buffer
/// exceeds this high-water mark (1 MiB). Resume when it drains under
/// the low-water mark. Prevents "Failure to send data" from the SCTP
/// transport when the application outruns the peer's receive window.
const SCTP_BUFFER_HIGH_WATER: usize = 1024 * 1024;
const SCTP_BUFFER_LOW_WATER: usize = 256 * 1024;

/// Emit a forwarder response split across frames of at most
/// [`SCTP_SAFE_CHUNK_BYTES`] bytes per `RESPONSE_BODY`, with
/// `buffered_amount`-based backpressure so a large body does not
/// overrun the SCTP send buffer.
async fn emit_response(dc: &RTCDataChannel, resp: ForwardResponse) -> Result<(), webrtc::Error> {
    send_frame(
        dc,
        Frame::new(FrameType::ResponseHead, resp.head_bytes).expect("response head is well-formed"),
    )
    .await?;

    // Wire up a drain-notify: the SCTP stack fires
    // `on_buffered_amount_low` when the buffered byte count drops
    // below our threshold. We wait on that notify after every
    // chunk that pushes us over the high-water mark.
    let drain_notify: Arc<tokio::sync::Notify> = Arc::new(tokio::sync::Notify::new());
    dc.set_buffered_amount_low_threshold(SCTP_BUFFER_LOW_WATER)
        .await;
    {
        let drain_notify = drain_notify.clone();
        dc.on_buffered_amount_low(Box::new(move || {
            let drain_notify = drain_notify.clone();
            Box::pin(async move {
                drain_notify.notify_waiters();
            })
        }))
        .await;
    }

    let body = resp.body;
    let mut offset = 0;
    while offset < body.len() {
        // Backpressure: if the DC buffer is above the high-water
        // mark, wait for the low-threshold callback before enqueuing
        // another chunk. 50 ms fallback poll so we don't deadlock
        // if the callback is ever missed.
        while dc.buffered_amount().await > SCTP_BUFFER_HIGH_WATER {
            let wait = drain_notify.notified();
            tokio::pin!(wait);
            let _ = tokio::time::timeout(Duration::from_millis(50), &mut wait).await;
        }

        let end = (offset + SCTP_SAFE_CHUNK_BYTES).min(body.len());
        let slice = body.slice(offset..end);
        let body_frame = Frame::new(FrameType::ResponseBody, slice.to_vec())
            .expect("chunk length bounded by SCTP_SAFE_CHUNK_BYTES");
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
