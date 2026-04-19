//! Offer-record polling loop (PR #7a).
//!
//! Polls every watched client's pkarr zone for a sealed `_offer-<host-hash>`
//! TXT record addressed to this daemon, decrypts it, runs the SDP through
//! [`crate::listener::PassivePeer::handle_offer`], seals the answer back,
//! pushes it into [`crate::publish::SharedState`], and triggers an
//! immediate republish so the client can fetch the answer on its own
//! next poll.
//!
//! Failure policy: any single-record error (decrypt fail, SDP parse
//! fail, handshake error) is logged at `warn!` and skipped. The loop
//! never terminates from a per-record failure; only an explicit
//! [`OfferPoller::shutdown`] call (or drop) stops it.
//!
//! # Spec deviations (TODO v0.1 freeze)
//!
//! - Allowlist enforcement is not applied here (PR #7b). Any offer
//!   that successfully unseals is processed. Harden after pairing.
//! - `watched_clients` is a pre-pairing stopgap — configured manually
//!   until PR #7 lands.
//! - Concurrent polls across clients are intentionally NOT rate-limited
//!   at the loop level beyond the per-client throttle; a 1 Hz cadence
//!   with a handful of watched clients is well inside what pkarr can
//!   handle.

use crate::listener::PassivePeer;
use crate::publish::SharedState;
use crate::rate_limit::TokenBucket;
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_pkarr::{
    decode_offer_from_packet, hash_offer_sdp, AnswerEntry, AnswerPlaintext, Resolve,
};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Configuration for a running [`OfferPoller`].
#[derive(Debug, Clone)]
pub struct OfferPollerConfig {
    /// How often the poller fires.
    pub poll_interval: Duration,
    /// Clients whose zones to poll. Empty disables the loop entirely.
    pub watched_clients: Vec<PublicKey>,
    /// At most one offer per client per this duration is processed.
    pub per_client_throttle: Duration,
    /// Whether to require the unsealed client pubkey to be in the
    /// allow list before running `handle_offer`. See PR #7b.
    pub enforce_allowlist: bool,
    /// Token-bucket burst capacity per client pubkey.
    pub rate_limit_burst: u32,
    /// Token-bucket refill rate in tokens per second (= 1.0 /
    /// `rate_limit_refill_secs` in the config).
    pub rate_limit_refill_per_sec: f64,
    /// Channel-binding modes the daemon accepts on incoming offers.
    /// Offers whose `binding_mode` is absent from this list are
    /// dropped pre-handshake with a `warn!`. Mirrors
    /// `[dtls] allowed_binding_modes` from the config file.
    pub allowed_binding_modes: Vec<openhost_pkarr::BindingMode>,
}

impl Default for OfferPollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            watched_clients: Vec::new(),
            per_client_throttle: Duration::from_secs(5),
            enforce_allowlist: true,
            rate_limit_burst: 3,
            rate_limit_refill_per_sec: 1.0 / 5.0,
            allowed_binding_modes: vec![
                openhost_pkarr::BindingMode::Exporter,
                openhost_pkarr::BindingMode::CertFp,
            ],
        }
    }
}

/// A running offer poller. Holds the background task + a shutdown
/// signal. Dropping the poller aborts the task; [`shutdown`] awaits
/// task exit.
///
/// [`shutdown`]: OfferPoller::shutdown
pub struct OfferPoller {
    task: Option<JoinHandle<()>>,
    shutdown_tx: watch::Sender<bool>,
}

impl OfferPoller {
    /// Spawn the poller. Returns immediately.
    ///
    /// The returned handle keeps the task alive for its lifetime. A
    /// noop poller is returned when `cfg.watched_clients` is empty —
    /// the background task still exists but immediately exits, keeping
    /// the `App::shutdown` path uniform.
    /// # Panics
    ///
    /// `cfg.watched_clients` MUST be non-empty — callers check that
    /// first (see `openhost-daemon::app::build_offer_poller`, which
    /// returns `None` for an empty watch list rather than calling
    /// `spawn`). Passing an empty list here is a programmer error.
    pub fn spawn(
        identity: Arc<SigningKey>,
        resolver: Arc<dyn Resolve>,
        listener: Arc<PassivePeer>,
        state: Arc<SharedState>,
        publisher_trigger: Arc<dyn Fn() + Send + Sync>,
        cfg: OfferPollerConfig,
    ) -> Self {
        assert!(
            !cfg.watched_clients.is_empty(),
            "OfferPoller::spawn requires a non-empty watched_clients list",
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task = tokio::spawn(run_poll_loop(
            identity,
            resolver,
            listener,
            state,
            publisher_trigger,
            cfg,
            shutdown_rx,
        ));

        Self {
            task: Some(task),
            shutdown_tx,
        }
    }

    /// Signal the poller to stop and await task completion. Idempotent.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for OfferPoller {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Per-client cache entry. Bundles:
/// - Seen-cache: the highest `ts` we've processed + last-touch time
///   (for TTL eviction).
/// - Token bucket: abuse-control gate on how often we'll spend CPU
///   running `handle_offer` for this client.
#[derive(Debug, Clone)]
struct ClientState {
    last_ts: u64,
    last_touched: Instant,
    last_processed: Option<Instant>,
    bucket: TokenBucket,
}

const SEEN_TTL: Duration = Duration::from_secs(600);

async fn run_poll_loop(
    identity: Arc<SigningKey>,
    resolver: Arc<dyn Resolve>,
    listener: Arc<PassivePeer>,
    state: Arc<SharedState>,
    publisher_trigger: Arc<dyn Fn() + Send + Sync>,
    cfg: OfferPollerConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut seen: HashMap<PublicKey, ClientState> = HashMap::new();
    let mut ticker = tokio::time::interval(cfg.poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval(..)` fires immediately on the first tick; that's exactly
    // what we want — poll right away so a client whose offer is already
    // live at daemon start is picked up without waiting a full period.

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                poll_one_cycle(
                    &identity,
                    resolver.as_ref(),
                    &listener,
                    &state,
                    &publisher_trigger,
                    &cfg,
                    &mut seen,
                )
                .await;
            }
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() {
                    tracing::debug!("openhostd: offer poller shutting down");
                    return;
                }
            }
        }
    }
}

async fn poll_one_cycle(
    identity: &SigningKey,
    resolver: &dyn Resolve,
    listener: &PassivePeer,
    state: &SharedState,
    publisher_trigger: &Arc<dyn Fn() + Send + Sync>,
    cfg: &OfferPollerConfig,
    seen: &mut HashMap<PublicKey, ClientState>,
) {
    let now_instant = Instant::now();
    let daemon_pk = identity.public_key();

    // Evict stale entries.
    seen.retain(|_, v| now_instant.duration_since(v.last_touched) < SEEN_TTL);

    for client_pk in &cfg.watched_clients {
        let pk_bytes = client_pk.to_bytes();
        let pkarr_pk = match pkarr::PublicKey::try_from(&pk_bytes) {
            Ok(k) => k,
            Err(_) => continue,
        };
        let packet = match resolver.resolve_most_recent(&pkarr_pk).await {
            Some(p) => p,
            None => continue,
        };

        process_client_packet(
            identity,
            &daemon_pk,
            client_pk,
            &packet,
            listener,
            state,
            publisher_trigger,
            cfg,
            seen,
            now_instant,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_client_packet(
    identity: &SigningKey,
    daemon_pk: &PublicKey,
    client_pk: &PublicKey,
    packet: &pkarr::SignedPacket,
    listener: &PassivePeer,
    state: &SharedState,
    publisher_trigger: &Arc<dyn Fn() + Send + Sync>,
    cfg: &OfferPollerConfig,
    seen: &mut HashMap<PublicKey, ClientState>,
    now_instant: Instant,
) {
    let offer_record = match decode_offer_from_packet(packet, daemon_pk) {
        Ok(Some(r)) => r,
        Ok(None) => return, // zone has a pkarr record but no _offer TXT
        Err(err) => {
            // Malformed packet or multi-TXT at the `_offer-<host-hash>`
            // name — both are worth operator attention.
            tracing::warn!(?err, client = %client_pk, "offer poll: decode failed");
            return;
        }
    };

    // Packet timestamp doubles as the offer's `ts` for dedup.
    //
    // NOTE: a legitimate client that publishes two distinct offers
    // within the same wall-clock second (e.g. quick retry after a
    // failed first dial) will see the second dropped by the
    // `packet_ts_secs <= entry.last_ts` gate below. Acceptable given
    // BEP44's own second-granularity `seq`; a content-hash dedup would
    // let the second publish through but complicate the cache.
    let packet_ts: u64 = packet.timestamp().into();
    let packet_ts_secs = packet_ts / openhost_pkarr::MICROS_PER_SECOND;

    // Dedup + throttle. Entry construction seeds a fresh token bucket.
    let entry = seen.entry(*client_pk).or_insert_with(|| ClientState {
        last_ts: 0,
        last_touched: now_instant,
        last_processed: None,
        bucket: TokenBucket::new(
            cfg.rate_limit_burst,
            cfg.rate_limit_refill_per_sec,
            now_instant,
        ),
    });
    entry.last_touched = now_instant;
    if packet_ts_secs <= entry.last_ts {
        return; // already processed (or regression — skip)
    }
    if let Some(last) = entry.last_processed {
        if now_instant.duration_since(last) < cfg.per_client_throttle {
            tracing::debug!(
                client = %client_pk,
                "offer poll: client throttled; skipping",
            );
            // Advance `last_ts` so a hostile client can't bypass the
            // throttle by bumping its packet timestamp — the same
            // (client_pk, ts) gets dropped on every subsequent poll
            // until the throttle window elapses.
            entry.last_ts = packet_ts_secs;
            return;
        }
    }

    // Unseal. Any packet we fetched from the zone under the client's
    // pubkey that happens to carry a TXT at our expected offer name but
    // isn't actually sealed to us falls through here — cheaper than
    // ping-spamming at warn-level, so we log at debug.
    let plaintext = match offer_record.open(identity) {
        Ok(p) => p,
        Err(err) => {
            tracing::debug!(?err, client = %client_pk, "offer poll: unseal failed");
            // Advance both cache fields so a hostile / broken client
            // can't reset the decrypt workload every single tick by
            // re-publishing under incrementing timestamps.
            entry.last_ts = packet_ts_secs;
            entry.last_processed = Some(now_instant);
            return;
        }
    };

    // Cross-check: the inner `client_pk` must match the outer BEP44 signer.
    if plaintext.client_pk != *client_pk {
        tracing::warn!(
            outer = %client_pk,
            inner = %plaintext.client_pk,
            "offer poll: inner client_pk mismatch; tearing down",
        );
        entry.last_ts = packet_ts_secs;
        entry.last_processed = Some(now_instant);
        return;
    }

    // PR #7b allowlist gate: reject offers from unpaired clients.
    // Runs BEFORE the rate-limit consume so an unpaired flood can't
    // drain a legitimate client's bucket (each pk has its own entry
    // anyway, but the ordering is also cheap and readable).
    //
    // Note on log severity: the FIRST rejection for an unpaired pk
    // logs at `warn!` so operators see the actionable message. Any
    // subsequent tick from the same unpaired pk falls into the
    // per-client throttle branch above and logs at `debug!` instead
    // — preventing a single misconfigured client from flooding the
    // daemon's `warn!` stream.
    if cfg.enforce_allowlist && !state.is_client_allowed(client_pk) {
        tracing::warn!(
            client = %client_pk,
            "offer poll: client is not in allowlist; skipping. Add via 'openhostd pair add'.",
        );
        entry.last_ts = packet_ts_secs;
        entry.last_processed = Some(now_instant);
        return;
    }

    // PR #28.3 binding-mode gate: drop offers whose advertised mode is
    // not on the operator's allowlist (e.g. a CLI-only deployment that
    // explicitly excludes browser cert_fp offers).
    if !cfg.allowed_binding_modes.contains(&plaintext.binding_mode) {
        tracing::warn!(
            client = %client_pk,
            binding_mode = ?plaintext.binding_mode,
            "offer poll: binding mode not in [dtls] allowed_binding_modes; skipping",
        );
        entry.last_ts = packet_ts_secs;
        entry.last_processed = Some(now_instant);
        return;
    }

    // PR #7b rate-limit gate: consume a token. On empty bucket, skip.
    if !entry.bucket.try_consume(now_instant) {
        tracing::warn!(
            client = %client_pk,
            "offer poll: client rate-limited; skipping",
        );
        entry.last_ts = packet_ts_secs;
        entry.last_processed = Some(now_instant);
        return;
    }

    tracing::info!(client = %client_pk, "offer poll: processing offer");

    // Run the handshake. `handle_offer` drains ICE and returns the
    // answer SDP.
    let answer_sdp = match listener
        .handle_offer(&plaintext.offer_sdp, plaintext.binding_mode)
        .await
    {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(?err, client = %client_pk, "offer poll: handle_offer failed");
            entry.last_ts = packet_ts_secs;
            entry.last_processed = Some(now_instant);
            return;
        }
    };

    // Seal the answer back to the client.
    let plaintext_answer = AnswerPlaintext {
        daemon_pk: *daemon_pk,
        offer_sdp_hash: hash_offer_sdp(&plaintext.offer_sdp),
        answer_sdp,
    };
    let daemon_salt = state.salt();
    let mut rng = OsRng;
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entry_seal = match AnswerEntry::seal(
        &mut rng,
        client_pk,
        &daemon_salt,
        &plaintext_answer,
        created_at,
    ) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(?err, client = %client_pk, "offer poll: seal answer failed");
            entry.last_ts = packet_ts_secs;
            entry.last_processed = Some(now_instant);
            return;
        }
    };

    state.push_answer(entry_seal);
    publisher_trigger();

    entry.last_ts = packet_ts_secs;
    entry.last_processed = Some(now_instant);
}
