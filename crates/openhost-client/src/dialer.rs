//! Client-side WebRTC dialer (PR #8).
//!
//! One-shot: construct a [`Dialer`], call [`Dialer::dial`] to resolve
//! the host, seal + publish an offer, poll for the answer, run the
//! PR #5.5 channel-binding handshake, and get back an authenticated
//! [`crate::session::OpenhostSession`] ready for a single HTTP
//! round-trip.
//!
//! The staged methods (`resolve_host`, `build_offer`, `publish_offer`,
//! `poll_answer`, `complete_binding`) are public but NOT the intended
//! everyday API — use them only for fault-injection tests. Production
//! callers go through `dial()`.

use crate::binding::{ClientBinder, ClientBindingError};
use crate::error::{ClientError, Result};
use crate::session::{OpenhostSession, SessionInboundReader};
use crate::webrtc_helpers::{
    build_client_api, dc_open_signal, install_crypto_provider_once, state_change_receiver,
};
use bytes::Bytes;
use openhost_core::channel_binding_wire::{
    AUTH_HOST_PAYLOAD_LEN, AUTH_NONCE_LEN, BINDING_TIMEOUT_SECS, EXPORTER_LABEL,
    EXPORTER_SECRET_LEN,
};
use openhost_core::identity::{OpenhostUrl, PublicKey, SigningKey};
use openhost_core::pkarr_record::SignedRecord;
use openhost_core::wire::{Frame, FrameType};
use openhost_pkarr::offer::{OfferPlaintext, OfferRecord, OFFER_TXT_PREFIX, OFFER_TXT_TTL};
use openhost_pkarr::{
    decode_answer_fragments_from_packet, hash_offer_sdp, host_hash_label, PkarrResolve,
    PkarrTransport, Resolve, Resolver, Transport, DEFAULT_RELAYS,
};
use pkarr::dns::rdata::TXT;
use pkarr::dns::Name;
use pkarr::{Keypair, SignedPacket, Timestamp};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use webrtc::api::API;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use zeroize::Zeroizing;

/// Tunable knobs on a [`Dialer`]. Defaults are production-sensible;
/// tests typically shrink `dial_timeout` + `answer_poll_interval`.
#[derive(Debug, Clone)]
pub struct DialerConfig {
    /// Total budget for [`Dialer::dial`]. Covers resolve + publish +
    /// answer-poll + webrtc connect + channel binding.
    pub dial_timeout: Duration,
    /// Cadence for the answer-record poll loop.
    pub answer_poll_interval: Duration,
    /// Time budget for the webrtc handshake up to `Connected` +
    /// data-channel `open`.
    pub webrtc_connect_timeout: Duration,
    /// Time budget for the channel-binding handshake (AuthNonce →
    /// AuthClient → AuthHost).
    pub binding_timeout: Duration,
}

impl Default for DialerConfig {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(30),
            answer_poll_interval: Duration::from_millis(500),
            webrtc_connect_timeout: Duration::from_secs(10),
            binding_timeout: Duration::from_secs(BINDING_TIMEOUT_SECS),
        }
    }
}

/// Builder for [`Dialer`].
#[derive(Default)]
pub struct DialerBuilder {
    identity: Option<Arc<SigningKey>>,
    host_url: Option<OpenhostUrl>,
    transport: Option<Arc<dyn Transport>>,
    resolver: Option<Arc<dyn Resolve>>,
    relays: Vec<String>,
    config: DialerConfig,
}

impl DialerBuilder {
    /// The client's Ed25519 identity. Signs `AuthClient` and the outer
    /// BEP44 publish of the sealed offer.
    #[must_use]
    pub fn identity(mut self, identity: Arc<SigningKey>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// The host to dial. Parsed via [`OpenhostUrl::parse`].
    #[must_use]
    pub fn host_url(mut self, url: OpenhostUrl) -> Self {
        self.host_url = Some(url);
        self
    }

    /// Replace the relay list used to build the default pkarr client.
    /// Ignored when both [`transport`] and [`resolver`] are set.
    ///
    /// [`transport`]: Self::transport
    /// [`resolver`]: Self::resolver
    #[must_use]
    pub fn relays<I, S>(mut self, relays: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.relays = relays.into_iter().map(Into::into).collect();
        self
    }

    /// Inject a caller-supplied [`Transport`]. Pairs with [`resolver`].
    /// Both halves must come from the same substrate (e.g. the same
    /// [`openhost_pkarr::MemoryPkarrNetwork`]) or the client's publish
    /// will never be visible to the host's resolver.
    ///
    /// [`resolver`]: Self::resolver
    #[must_use]
    pub fn transport(mut self, transport: Arc<dyn Transport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Inject a caller-supplied [`Resolve`].
    #[must_use]
    pub fn resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Override the config defaults.
    #[must_use]
    pub fn config(mut self, config: DialerConfig) -> Self {
        self.config = config;
        self
    }

    /// Build the [`Dialer`]. If `transport` and `resolver` weren't set
    /// explicitly, a real `pkarr::Client` is constructed from the
    /// relay list.
    pub fn build(self) -> Result<Dialer> {
        install_crypto_provider_once();
        let identity = self.identity.ok_or(ClientError::ResolveHost(
            "identity not set on DialerBuilder",
        ))?;
        let host_url = self.host_url.ok_or(ClientError::ResolveHost(
            "host_url not set on DialerBuilder",
        ))?;
        let (transport, resolver) = match (self.transport, self.resolver) {
            (Some(t), Some(r)) => (t, r),
            (None, None) => {
                let relays: Vec<&str> = if self.relays.is_empty() {
                    DEFAULT_RELAYS.to_vec()
                } else {
                    self.relays.iter().map(String::as_str).collect()
                };
                let mut builder = pkarr::Client::builder();
                builder
                    .relays(&relays)
                    .map_err(|e| ClientError::ClientBuild(format!("invalid relay URL: {e}")))?;
                let client = builder
                    .build()
                    .map_err(|e| ClientError::ClientBuild(e.to_string()))?;
                let shared = Arc::new(client);
                (
                    Arc::new(PkarrTransport::new(Arc::clone(&shared))) as Arc<dyn Transport>,
                    Arc::new(PkarrResolve::new(shared)) as Arc<dyn Resolve>,
                )
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(ClientError::ClientBuild(
                    "DialerBuilder requires both transport and resolver, or neither".into(),
                ));
            }
        };
        Ok(Dialer {
            identity,
            host_url,
            transport,
            resolver,
            api: build_client_api(),
            config: self.config,
            last_seq: None,
        })
    }
}

/// WebRTC dialer. One `Dialer` is one dial attempt; after a successful
/// [`dial`] the `Dialer` can be re-used for another attempt, but an
/// in-flight `OpenhostSession` holds its own `RTCPeerConnection`.
///
/// [`dial`]: Dialer::dial
pub struct Dialer {
    identity: Arc<SigningKey>,
    host_url: OpenhostUrl,
    transport: Arc<dyn Transport>,
    resolver: Arc<dyn Resolve>,
    api: Arc<API>,
    config: DialerConfig,
    /// Highest `ts` we've published for our own pkarr zone. Bumped
    /// forward if the system clock would produce a colliding or
    /// regressing value — same trick the daemon's publisher uses.
    last_seq: Option<u64>,
}

impl Dialer {
    /// Start a new builder.
    #[must_use]
    pub fn builder() -> DialerBuilder {
        DialerBuilder::default()
    }

    /// Run the full handshake and return an authenticated session.
    pub async fn dial(&mut self) -> Result<OpenhostSession> {
        let total_budget = self.config.dial_timeout;
        let deadline = Instant::now() + total_budget;
        tokio::time::timeout(total_budget, self.dial_inner(deadline))
            .await
            .map_err(|_| ClientError::PollAnswerTimeout(total_budget.as_secs()))?
    }

    async fn dial_inner(&mut self, _deadline: Instant) -> Result<OpenhostSession> {
        // Stage 1: resolve the host record.
        let signed = self.resolve_host().await?;
        let daemon_pk = signed.record_pubkey_from(&self.host_url);
        let daemon_salt = signed.record.salt;

        // Stage 2: build the WebRTC offer (no ICE trickle — keeps SDP
        // under the BEP44 1000-byte cap).
        let (pc, dc, offer_sdp) = self.build_offer().await?;

        // RAII guard: if any stage 3-6 fails, close pc+dc before we
        // bubble the error. webrtc-rs's `RTCPeerConnection` holds UDP
        // sockets, ICE task handles, and DTLS state that Drop does
        // NOT release — without this guard every failed dial leaks a
        // full peer connection until process exit.
        let mut teardown = Some(PeerConnectionGuard::new(Arc::clone(&pc), Arc::clone(&dc)));

        // Stage 3: seal + publish the offer as a v3 compact blob.
        // Canonical SDP (reconstructed from the blob) is what both
        // sides hash for answer binding, so we compute it here and
        // thread the same string into publish + hash.
        let client_fp = openhost_pkarr::extract_sha256_fingerprint_from_sdp(&offer_sdp)
            .map_err(|e| ClientError::PublishOffer(format!("client DTLS fp: {e}")))?;
        let offer_blob = openhost_pkarr::sdp_to_offer_blob(
            &offer_sdp,
            &client_fp,
            openhost_pkarr::BindingMode::Exporter,
        )
        .map_err(|e| ClientError::PublishOffer(format!("offer→blob: {e}")))?;
        let canonical_offer_sdp = openhost_pkarr::offer_blob_to_sdp(&offer_blob);
        self.publish_offer_blob(&daemon_pk, offer_blob).await?;

        // Stage 4: poll for the daemon's answer. The host's DTLS
        // fingerprint (already verified under the outer BEP44 signature
        // on `signed`) is threaded through so the v2 compact-blob
        // branch can reconstruct a complete SDP locally. The daemon
        // hashes its reconstructed offer SDP; we hash ours — both
        // forms are byte-identical because `offer_blob_to_sdp` is
        // deterministic over the shared blob.
        let offer_hash = hash_offer_sdp(&canonical_offer_sdp);
        let answer_sdp = self
            .poll_answer(
                &daemon_pk,
                &daemon_salt,
                &offer_hash,
                &signed.record.dtls_fp,
            )
            .await?;

        // Stage 5: apply the answer + wait for webrtc Connected + DC open.
        self.apply_answer(&pc, &answer_sdp).await?;
        let inbound = wait_for_ready(&pc, &dc, self.config.webrtc_connect_timeout).await?;

        // Stage 6: run the client-side channel-binding handshake.
        let binder = ClientBinder::new(Arc::clone(&self.identity), daemon_pk);
        complete_binding(&pc, &dc, &inbound, &binder, self.config.binding_timeout).await?;

        // Authenticated — transfer pc+dc ownership to the session;
        // the guard's Drop is now a no-op.
        if let Some(g) = teardown.take() {
            g.disarm();
        }

        Ok(OpenhostSession::new(pc, dc, inbound))
    }

    /// Resolve the host's `_openhost` pkarr record.
    pub async fn resolve_host(&self) -> Result<SignedRecord> {
        // Zero grace window: the dialer is latency-sensitive and the
        // resolver's 1.5 s grace would add a full tick to every dial.
        let resolver = Resolver::new(Arc::clone(&self.resolver)).with_grace_window(Duration::ZERO);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        resolver
            .resolve(&self.host_url.pubkey, now, None)
            .await
            .map_err(ClientError::from)
    }

    /// Build a fresh WebRTC offer SDP, waiting for full ICE gather
    /// before returning.
    ///
    /// The pre-PR-28.3 version of this function skipped
    /// `gathering_complete_promise` on the theory that trickle-ICE
    /// would deliver candidates over the data channel after it
    /// opened. That never worked in practice: the DC can't open until
    /// DTLS, DTLS can't start until ICE, ICE needs candidates on both
    /// sides, and there's no out-of-band trickle channel before the
    /// first DC frame. The daemon side (`listener::negotiate`) has
    /// always waited for gather; this brings the client in line.
    ///
    /// BEP44 packet-size caveat: a real-world offer SDP with one host
    /// candidate and one or two srflx candidates runs around 500-700
    /// bytes plaintext depending on the ice-ufrag / fingerprint values
    /// webrtc-rs generates. Sealed-box plus base64url push that into
    /// the 700-950 byte range, which is within the 1000-byte `v` cap
    /// but not by much. Dual-stack or multi-bridge hosts WILL overflow
    /// without the IP filter installed in
    /// `webrtc_helpers::build_client_api`. If the cap is tripped the
    /// dial errors with `PublishOffer` rather than silently succeeding
    /// with zero candidates.
    pub async fn build_offer(
        &self,
    ) -> Result<(Arc<RTCPeerConnection>, Arc<RTCDataChannel>, String)> {
        // STUN servers are mandatory for cross-NAT dials — without
        // them webrtc-rs gathers only `host`-type candidates and
        // can't discover the client's public address.
        let config = RTCConfiguration {
            ice_servers: vec![webrtc::ice_transport::ice_server::RTCIceServer {
                urls: vec!["stun:stun.cloudflare.com:3478".to_string()],
                ..Default::default()
            }],
            ..Default::default()
        };
        let pc = Arc::new(
            self.api
                .new_peer_connection(config)
                .await
                .map_err(|e| ClientError::WebRtcSetup(format!("new_peer_connection: {e}")))?,
        );
        let dc = pc
            .create_data_channel("openhost", Some(RTCDataChannelInit::default()))
            .await
            .map_err(|e| ClientError::WebRtcSetup(format!("create_data_channel: {e}")))?;
        let offer = pc
            .create_offer(None)
            .await
            .map_err(|e| ClientError::WebRtcSetup(format!("create_offer: {e}")))?;
        pc.set_local_description(offer)
            .await
            .map_err(|e| ClientError::WebRtcSetup(format!("set_local_description: {e}")))?;
        // Drain ICE gathering so the returned SDP carries every
        // candidate the local agent could find.
        let mut gather = pc.gathering_complete_promise().await;
        let _ = gather.recv().await;
        let sdp = pc
            .local_description()
            .await
            .ok_or(ClientError::WebRtcSetup("local description missing".into()))?
            .sdp;
        Ok((pc, dc, sdp))
    }

    /// Seal a [`OfferBlob`] to the daemon + publish a pkarr packet
    /// under the client's own Ed25519 pubkey carrying the
    /// `_offer-<host-hash>` TXT. Compact-offer-blob PR: v3 offers
    /// replace the full-SDP seal with a ~130-byte binary blob so
    /// Chrome-sized SDPs fit under BEP44's 1000-byte packet cap.
    pub async fn publish_offer_blob(
        &mut self,
        daemon_pk: &PublicKey,
        offer_blob: openhost_pkarr::OfferBlob,
    ) -> Result<()> {
        // CLI dialers advertise `Exporter` unconditionally. CertFp is
        // the browser-only variant from `spec/04-security.md §4.1`; a
        // CLI that silently downgraded to CertFp would reduce its
        // channel binding to a value the cert-pin alone already
        // covers. The constant below is load-bearing — refactors that
        // thread a runtime-chosen mode into this call site MUST route
        // through [`assert_cli_binding_mode`] so the CLI cannot ship
        // a weaker binding than the spec mandates.
        const CLI_BINDING_MODE: openhost_pkarr::BindingMode = openhost_pkarr::BindingMode::Exporter;
        assert_cli_binding_mode(CLI_BINDING_MODE)?;
        let mut blob = offer_blob;
        blob.binding_mode = CLI_BINDING_MODE;
        let plaintext = OfferPlaintext::new_v3(self.identity.public_key(), blob);
        let mut rng = rand::rngs::OsRng;
        let offer = OfferRecord::seal(&mut rng, daemon_pk, &plaintext)
            .map_err(|e| ClientError::PublishOffer(format!("seal: {e}")))?;
        let txt_value = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &offer.sealed,
        );
        let label = host_hash_label(daemon_pk);
        let name = format!("{OFFER_TXT_PREFIX}{label}");

        let seed = Zeroizing::new(self.identity.to_bytes());
        let keypair = Keypair::from_secret_key(&seed);

        // Monotonic-seq bump: if the system clock would produce a
        // value ≤ our last publish, bump by 1 so BEP44 CAS accepts it.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ts = match self.last_seq {
            Some(last) if now_secs <= last => last.saturating_add(1),
            _ => now_secs,
        };
        let ts_micros = ts
            .checked_mul(1_000_000)
            .ok_or(ClientError::PublishOffer("ts overflow".into()))?;

        let packet = SignedPacket::builder()
            .txt(
                Name::new_unchecked(&name),
                TXT::try_from(txt_value.as_str())
                    .map_err(|e| ClientError::PublishOffer(format!("txt build: {e}")))?,
                OFFER_TXT_TTL,
            )
            .timestamp(Timestamp::from(ts_micros))
            .sign(&keypair)
            .map_err(|e| ClientError::PublishOffer(format!("sign: {e}")))?;

        self.transport
            .publish(&packet, None)
            .await
            .map_err(|e| ClientError::PublishOffer(format!("transport: {e}")))?;
        self.last_seq = Some(ts);
        Ok(())
    }

    /// Poll the host's pkarr zone for the `_answer-<client-hash>` TXT
    /// and return a complete answer SDP. Cross-checks the inner
    /// `daemon_pk` and `offer_sdp_hash` against what the client
    /// expects. For v2 (compact blob) answers, reconstructs the SDP
    /// from the blob + the host's DTLS fingerprint (which was pinned
    /// under the BEP44 signature on the main `_openhost` record). For
    /// legacy v1 answers, returns the embedded SDP string verbatim.
    pub async fn poll_answer(
        &self,
        daemon_pk: &PublicKey,
        daemon_salt: &[u8; openhost_core::pkarr_record::SALT_LEN],
        expected_offer_hash: &[u8; 32],
        host_dtls_fp: &[u8; openhost_pkarr::DTLS_FP_LEN],
    ) -> Result<String> {
        let budget = self.config.dial_timeout; // enforced by outer timeout
        let deadline = Instant::now() + budget;
        let client_pk = self.identity.public_key();
        let pk_bytes = daemon_pk.to_bytes();
        let pkarr_pk = pkarr::PublicKey::try_from(&pk_bytes)
            .map_err(|_| ClientError::ResolveHost("host pubkey → pkarr conversion failed"))?;

        loop {
            if Instant::now() >= deadline {
                return Err(ClientError::PollAnswerTimeout(budget.as_secs()));
            }
            if let Some(packet) = self.resolver.resolve_most_recent(&pkarr_pk).await {
                match decode_answer_fragments_from_packet(&packet, daemon_salt, &client_pk) {
                    Ok(Some(entry)) => {
                        let opened = entry
                            .open(&self.identity)
                            .map_err(|e| ClientError::AnswerDecode(format!("open: {e}")))?;
                        if opened.daemon_pk != *daemon_pk {
                            return Err(ClientError::AnswerBindingMismatch(
                                "inner daemon_pk mismatches outer signer",
                            ));
                        }
                        if &opened.offer_sdp_hash != expected_offer_hash {
                            // Stale answer from a prior dial attempt
                            // (pkarr cache lag). Keep polling — the
                            // daemon's newer publish for THIS offer
                            // will eventually arrive. An adversary
                            // cannot replay a mismatched answer past
                            // the poll window because the window is
                            // bounded by `dial_timeout`.
                            tracing::debug!(
                                "dialer: answer hash mismatch (stale from prior attempt); polling again"
                            );
                        } else {
                            let sdp = match opened.answer {
                                openhost_pkarr::AnswerPayload::V2Blob(blob) => {
                                    openhost_pkarr::answer_blob_to_sdp(&blob, host_dtls_fp)
                                }
                                openhost_pkarr::AnswerPayload::V1Sdp(s) => s,
                            };
                            return Ok(sdp);
                        }
                    }
                    Ok(None) => {
                        // Main record is present but no `_answer.*`
                        // TXT for us yet. Keep polling.
                    }
                    Err(e) => {
                        return Err(ClientError::AnswerDecode(format!("{e}")));
                    }
                }
            }
            tokio::time::sleep(self.config.answer_poll_interval).await;
        }
    }

    /// Apply the answer SDP to the WebRTC peer connection. After this
    /// returns, webrtc-rs starts its side of the DTLS handshake.
    pub async fn apply_answer(&self, pc: &Arc<RTCPeerConnection>, answer_sdp: &str) -> Result<()> {
        let answer = RTCSessionDescription::answer(answer_sdp.to_string())
            .map_err(|e| ClientError::WebRtcSetup(format!("parse answer: {e}")))?;
        pc.set_remote_description(answer)
            .await
            .map_err(|e| ClientError::WebRtcSetup(format!("set_remote_description: {e}")))?;
        Ok(())
    }
}

/// Extension trait: look up the host's pubkey off a resolved record.
/// The record itself doesn't carry the pubkey; it's whatever we
/// resolved against.
trait RecordPubkeyExt {
    fn record_pubkey_from(&self, url: &OpenhostUrl) -> PublicKey;
}

impl RecordPubkeyExt for SignedRecord {
    fn record_pubkey_from(&self, url: &OpenhostUrl) -> PublicKey {
        url.pubkey
    }
}

/// Wait for `RTCPeerConnectionState::Connected` AND for the data
/// channel to emit `on_open`. Returns a reader primed on the open DC.
async fn wait_for_ready(
    pc: &Arc<RTCPeerConnection>,
    dc: &Arc<RTCDataChannel>,
    timeout: Duration,
) -> Result<SessionInboundReader> {
    let mut states = state_change_receiver(pc);
    let dc_open = dc_open_signal(dc);
    let inbound = SessionInboundReader::install(dc);

    let connected = async {
        loop {
            match states.recv().await {
                Some(RTCPeerConnectionState::Connected) => return Ok::<(), ClientError>(()),
                Some(RTCPeerConnectionState::Failed) | Some(RTCPeerConnectionState::Closed) => {
                    return Err(ClientError::WebRtcSetup(
                        "peer connection reached a terminal state before Connected".into(),
                    ));
                }
                Some(_) => continue,
                None => {
                    return Err(ClientError::WebRtcSetup(
                        "state-change channel closed before Connected".into(),
                    ));
                }
            }
        }
    };
    tokio::time::timeout(timeout, connected)
        .await
        .map_err(|_| ClientError::WebRtcSetup(format!("not Connected within {timeout:?}")))??;

    tokio::time::timeout(timeout, dc_open.notified())
        .await
        .map_err(|_| {
            ClientError::WebRtcSetup(format!("data channel not open within {timeout:?}"))
        })?;

    Ok(inbound)
}

/// Run the three-frame client side of the channel binding:
/// receive AuthNonce → send AuthClient → receive AuthHost.
async fn complete_binding(
    pc: &Arc<RTCPeerConnection>,
    dc: &Arc<RTCDataChannel>,
    inbound: &SessionInboundReader,
    binder: &ClientBinder,
    timeout: Duration,
) -> Result<()> {
    let dtls_transport = pc.sctp().transport();
    let exporter = dtls_transport
        .export_keying_material(EXPORTER_LABEL, EXPORTER_SECRET_LEN)
        .await
        .map_err(|e| ClientError::ChannelBinding(ClientBindingError::Exporter(format!("{e}"))))?;
    if exporter.len() != EXPORTER_SECRET_LEN {
        return Err(ClientError::ChannelBinding(
            ClientBindingError::ExporterLength(exporter.len()),
        ));
    }

    // Wait for AuthNonce.
    let nonce_frame = inbound.next_frame(timeout).await?;
    if nonce_frame.frame_type != FrameType::AuthNonce || nonce_frame.payload.len() != AUTH_NONCE_LEN
    {
        return Err(ClientError::ChannelBinding(
            ClientBindingError::UnexpectedFrame(nonce_frame.frame_type.as_u8()),
        ));
    }
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    nonce.copy_from_slice(&nonce_frame.payload);

    // Send AuthClient.
    let payload = binder.sign_auth_client(&exporter, &nonce)?;
    let auth_client =
        Frame::new(FrameType::AuthClient, payload).expect("96-byte AuthClient fits the frame cap");
    send_frame(dc, auth_client).await?;

    // Wait for AuthHost.
    let host_frame = inbound.next_frame(timeout).await?;
    if host_frame.frame_type != FrameType::AuthHost
        || host_frame.payload.len() != AUTH_HOST_PAYLOAD_LEN
    {
        return Err(ClientError::ChannelBinding(
            ClientBindingError::UnexpectedFrame(host_frame.frame_type.as_u8()),
        ));
    }
    binder.verify_auth_host(&exporter, &nonce, &host_frame.payload)?;

    Ok(())
}

/// RAII guard that closes a `(pc, dc)` pair on drop unless `disarm`
/// was called. Used to plug the resource leak on `dial_inner` error
/// paths — webrtc-rs does NOT close peer connections in Drop, so a
/// naked drop leaks UDP sockets + ICE tasks + DTLS state per failed
/// dial.
struct PeerConnectionGuard {
    pc: Option<Arc<RTCPeerConnection>>,
    dc: Option<Arc<RTCDataChannel>>,
}

impl PeerConnectionGuard {
    fn new(pc: Arc<RTCPeerConnection>, dc: Arc<RTCDataChannel>) -> Self {
        Self {
            pc: Some(pc),
            dc: Some(dc),
        }
    }

    /// Transfer ownership to the caller; subsequent `Drop` is a no-op.
    fn disarm(mut self) {
        self.pc.take();
        self.dc.take();
    }
}

impl Drop for PeerConnectionGuard {
    fn drop(&mut self) {
        if let (Some(pc), Some(dc)) = (self.pc.take(), self.dc.take()) {
            // Best-effort async close. On a current-thread runtime
            // the futures run the next time the runtime is driven;
            // on multi-thread they fire immediately on a worker.
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = dc.close().await;
                    let _ = pc.close().await;
                });
            }
        }
    }
}

async fn send_frame(dc: &RTCDataChannel, frame: Frame) -> Result<()> {
    let mut buf = Vec::with_capacity(5 + frame.payload.len());
    frame.encode(&mut buf);
    dc.send(&Bytes::from(buf))
        .await
        .map_err(|e| ClientError::WebRtcSetup(format!("data channel send: {e}")))?;
    Ok(())
}

/// Spec §4.1 (`spec/04-security.md`) forbids CLI clients from
/// advertising a channel-binding mode weaker than
/// [`openhost_pkarr::BindingMode::Exporter`]. This is the one-line
/// gate every CLI code path that constructs an `OfferPlaintext` MUST
/// route through so a refactor can't silently ship a weaker binding.
/// Browsers run a different code path (the WASM shim) and are NOT
/// subject to this check — they're mandated to use `CertFp`.
fn assert_cli_binding_mode(mode: openhost_pkarr::BindingMode) -> Result<()> {
    match mode {
        openhost_pkarr::BindingMode::Exporter => Ok(()),
        other => Err(ClientError::ChannelBinding(
            ClientBindingError::DowngradeRejected(other),
        )),
    }
}

#[cfg(test)]
mod downgrade_tests {
    use super::*;

    #[test]
    fn cli_rejects_cert_fp_downgrade() {
        let err = assert_cli_binding_mode(openhost_pkarr::BindingMode::CertFp)
            .expect_err("CertFp must be refused on the CLI path");
        assert!(matches!(
            err,
            ClientError::ChannelBinding(ClientBindingError::DowngradeRejected(
                openhost_pkarr::BindingMode::CertFp,
            ))
        ));
    }

    #[test]
    fn cli_accepts_exporter() {
        assert_cli_binding_mode(openhost_pkarr::BindingMode::Exporter)
            .expect("Exporter is the CLI's only supported mode");
    }
}
