//! Top-level daemon lifecycle.
//!
//! [`App::build`] loads the identity, generates/loads the DTLS cert,
//! constructs [`crate::publish::SharedState`], spawns the pkarr
//! publisher, and prepares the WebRTC passive listener.
//!
//! [`App::run`] awaits the initial publish's terminal outcome (with a
//! bounded timeout), logs a structured "openhostd: up" line with the
//! pubkey + fingerprint, and then blocks on [`shutdown_signal`] before
//! tearing everything down cleanly.
//!
//! The binary's `main` is a thin shim over these two methods; integration
//! tests skip the binary and drive [`App`] directly with an injected
//! `Transport`.

use crate::config::{Config, IdentityStore};
use crate::dtls_cert::{self, DtlsCertificate};
use crate::error::Result;
use crate::forward::Forwarder;
use crate::identity_store::{load_or_create, FsKeyStore, KeyStore};
use crate::listener::PassivePeer;
use crate::offer_poller::{OfferPoller, OfferPollerConfig};
use crate::pairing;
use crate::publish::{self, PublishService, SharedState};
use crate::signal::{reload_signal, shutdown_signal};
use openhost_core::identity::SigningKey;
use openhost_pkarr::{InitialPublishOutcome, Resolve, Transport};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How long `App::run` waits for the first publish to land before
/// logging "up" anyway. 10 s is slack enough for a healthy relay and
/// tight enough that a totally-offline daemon yells promptly.
const INITIAL_PUBLISH_WAIT: Duration = Duration::from_secs(10);

/// A fully-constructed daemon, ready to run.
///
/// Building an `App` already performed every side effect that can fail
/// without running the event loop: identity loaded or generated, DTLS cert
/// loaded or generated, initial publish request in flight, listener ready
/// to accept offers.
pub struct App {
    identity: Arc<SigningKey>,
    cert: DtlsCertificate,
    state: Arc<SharedState>,
    publisher: PublishService,
    listener: Arc<PassivePeer>,
    /// Offer-record poller. `Some` on the production build path; `None`
    /// on the `build_with_transport` test path that doesn't provide a
    /// resolver, keeping pre-PR #7a tests working without changes.
    poller: Option<OfferPoller>,
    /// Resolved path to the pairing DB. Consulted on SIGHUP / watcher
    /// events to reload the allow list + trigger a republish.
    pair_db_path: PathBuf,
    /// File-watcher that fires whenever `pair_db_path` is created,
    /// modified, or removed. `None` when the watcher couldn't start —
    /// the daemon keeps running and pairing changes fall back to the
    /// SIGHUP path (Unix) or a restart (Windows).
    pair_watcher: Option<crate::pair_watcher::PairWatcher>,
    /// Embedded TURN relay (PR #42.2). `Some` only when
    /// `[turn] enabled = true` in config. Dropped alongside the other
    /// subsystems on shutdown.
    turn: Option<crate::turn_server::TurnHandle>,
}

impl App {
    /// Build the daemon against the real pkarr network.
    pub async fn build(cfg: Config) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let pair_db_path = resolve_pair_db_path(&cfg);
        load_pair_db_into_state(&pair_db_path, &state, &cfg)?;
        let forwarder = build_forwarder(&cfg)?;
        let listener =
            build_listener(&cert, identity.clone(), state.clone(), forwarder.clone()).await?;
        let turn = maybe_spawn_turn(&cfg, &identity, &state).await?;
        let (publisher, resolver) =
            publish::start(&cfg.pkarr, identity.clone(), state.clone()).await?;
        let poller = build_offer_poller(
            &cfg,
            &pair_db_path,
            identity.clone(),
            Arc::clone(&listener),
            state.clone(),
            resolver,
            &publisher,
        );
        let pair_watcher = crate::pair_watcher::PairWatcher::spawn(
            &pair_db_path,
            Duration::from_millis(cfg.pairing.watch_debounce_ms),
        );
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
            listener,
            poller,
            pair_db_path,
            pair_watcher,
            turn,
        })
    }

    /// Build the daemon with a caller-supplied [`Transport`] (no
    /// resolver). Used by integration tests that don't exercise the
    /// offer-polling path.
    pub async fn build_with_transport(cfg: Config, transport: Arc<dyn Transport>) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let pair_db_path = resolve_pair_db_path(&cfg);
        load_pair_db_into_state(&pair_db_path, &state, &cfg)?;
        let forwarder = build_forwarder(&cfg)?;
        let listener =
            build_listener(&cert, identity.clone(), state.clone(), forwarder.clone()).await?;
        let publisher =
            publish::start_with_transport(&cfg.pkarr, identity.clone(), state.clone(), transport);
        let pair_watcher = crate::pair_watcher::PairWatcher::spawn(
            &pair_db_path,
            Duration::from_millis(cfg.pairing.watch_debounce_ms),
        );
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
            listener,
            poller: None,
            pair_db_path,
            pair_watcher,
            turn: None,
        })
    }

    /// Build the daemon with caller-supplied transport AND resolver.
    /// PR #7a integration tests use this to drive a scripted offer
    /// response through the full poll → handle_offer → answer-publish
    /// flow without hitting the network.
    pub async fn build_with_transport_and_resolve(
        cfg: Config,
        transport: Arc<dyn Transport>,
        resolver: Arc<dyn Resolve>,
    ) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let pair_db_path = resolve_pair_db_path(&cfg);
        load_pair_db_into_state(&pair_db_path, &state, &cfg)?;
        let forwarder = build_forwarder(&cfg)?;
        let listener =
            build_listener(&cert, identity.clone(), state.clone(), forwarder.clone()).await?;
        let publisher =
            publish::start_with_transport(&cfg.pkarr, identity.clone(), state.clone(), transport);
        let poller = build_offer_poller(
            &cfg,
            &pair_db_path,
            identity.clone(),
            Arc::clone(&listener),
            state.clone(),
            resolver,
            &publisher,
        );
        let pair_watcher = crate::pair_watcher::PairWatcher::spawn(
            &pair_db_path,
            Duration::from_millis(cfg.pairing.watch_debounce_ms),
        );
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
            listener,
            poller,
            pair_db_path,
            pair_watcher,
            turn: None,
        })
    }

    /// Path to the pairing DB this daemon is using. Exposed for
    /// integration tests that want to mutate the DB and send SIGHUP.
    pub fn pair_db_path(&self) -> &Path {
        &self.pair_db_path
    }

    /// The host's Ed25519 identity.
    pub fn identity(&self) -> &SigningKey {
        &self.identity
    }

    /// The DTLS certificate pinned into the published record.
    pub fn cert(&self) -> &DtlsCertificate {
        &self.cert
    }

    /// The mutable state the publisher reads each tick.
    pub fn state(&self) -> &Arc<SharedState> {
        &self.state
    }

    /// The passive WebRTC peer. Integration tests call
    /// `app.listener().handle_offer(offer_sdp)` to drive the handshake
    /// without spinning up a signalling layer.
    pub fn listener(&self) -> &Arc<PassivePeer> {
        &self.listener
    }

    /// Convenience: hand `offer_sdp` to the listener and return the
    /// compact [`openhost_pkarr::AnswerBlob`] the daemon seals into
    /// its pkarr `_answer-*` record. `binding_mode` is the channel-
    /// binding variant the client advertised in its offer plaintext —
    /// the offer poller threads it in; direct callers (tests, examples)
    /// default to [`openhost_pkarr::BindingMode::Exporter`].
    pub async fn handle_offer(
        &self,
        offer_sdp: &str,
        binding_mode: openhost_pkarr::BindingMode,
    ) -> Result<openhost_pkarr::AnswerBlob> {
        self.listener
            .handle_offer(offer_sdp, binding_mode)
            .await
            .map_err(Into::into)
    }

    /// Request an immediate republish.
    pub fn trigger_republish(&self) {
        self.publisher.trigger();
    }

    /// Block until a shutdown signal arrives, then shut the publisher
    /// and listener down cleanly.
    ///
    /// Before logging "openhostd: up" this method gates on the
    /// publisher's first-publish outcome via
    /// [`openhost_pkarr::PublisherHandle::await_initial_publish`]
    /// (bounded by [`INITIAL_PUBLISH_WAIT`]). `Succeeded` → regular
    /// info log. `Exhausted` or timeout → a `warn!` makes the partial
    /// state observable; the daemon keeps running so a later scheduled
    /// republish can still succeed.
    pub async fn run(mut self) -> Result<()> {
        self.wait_for_initial_publish().await;
        tracing::info!(
            pubkey = %self.identity.public_key(),
            dtls_fp = %self.cert.fingerprint_colon_hex(),
            "openhostd: up",
        );

        // Drive the event loop: shutdown wins over concurrent
        // SIGHUP/file-watcher events (`biased;` makes the select poll
        // the shutdown arm first). Rapid reload bursts coalesce —
        // tokio-signal collapses SIGHUPs, notify-debouncer-mini
        // collapses bursty filesystem writes at the 250 ms window, and
        // the loop boundary provides a final coalescing point. Reload
        // is idempotent: each event just re-runs load + replace_allow.
        loop {
            // `pair_watcher.recv()` needs `&mut` access but `None` when
            // the watcher didn't start; use a branch guard so the
            // select resolves only when the option is populated.
            let watcher_active = self.pair_watcher.is_some();
            tokio::select! {
                biased;
                _ = shutdown_signal() => {
                    break;
                }
                _ = reload_signal() => {
                    reload_and_trigger(
                        &self.pair_db_path,
                        &self.state,
                        &self.publisher,
                        "SIGHUP",
                    );
                }
                event = async {
                    match self.pair_watcher.as_mut() {
                        Some(w) => w.recv().await,
                        // Never resolves: the `watcher_active` guard
                        // below keeps this branch disabled when the
                        // watcher is `None`, but the future body still
                        // needs to type-check on the `None` side.
                        None => std::future::pending().await,
                    }
                }, if watcher_active => {
                    if event.is_some() {
                        reload_and_trigger(
                            &self.pair_db_path,
                            &self.state,
                            &self.publisher,
                            "file-watcher",
                        );
                    }
                }
            }
        }

        tracing::info!("openhostd: shutdown signal received, stopping publisher");
        // Order: listener first (tears down in-flight DTLS); poller
        // next (stops the loop that might otherwise push a late answer
        // into the publisher); pair-watcher next (drops inotify
        // resources before the publisher whose trigger it calls);
        // publisher last.
        self.listener.shutdown().await;
        if let Some(p) = self.poller {
            p.shutdown().await;
        }
        if let Some(w) = self.pair_watcher.take() {
            w.shutdown();
        }
        if let Some(t) = self.turn.take() {
            if let Err(err) = t.shutdown().await {
                tracing::warn!(?err, "openhostd: TURN relay shutdown error");
            }
        }
        self.publisher.shutdown().await;
        tracing::info!("openhostd: bye");
        Ok(())
    }

    async fn wait_for_initial_publish(&self) {
        let outcome =
            tokio::time::timeout(INITIAL_PUBLISH_WAIT, self.publisher.await_initial_publish())
                .await;
        match outcome {
            Ok(InitialPublishOutcome::Succeeded(ts)) => {
                tracing::info!(record_ts = ts, "openhostd: initial publish succeeded");
            }
            Ok(InitialPublishOutcome::Exhausted) => {
                tracing::warn!(
                    "openhostd: initial publish retries exhausted; \
                     host will be undiscoverable until next scheduled republish"
                );
            }
            Err(_) => {
                tracing::warn!(
                    wait_secs = INITIAL_PUBLISH_WAIT.as_secs(),
                    "openhostd: initial publish didn't land inside the startup window; \
                     continuing so a later tick can still succeed"
                );
            }
        }
    }

    /// Shut the publisher and listener down without waiting for a
    /// signal. Intended for integration tests.
    pub async fn shutdown(self) {
        self.listener.shutdown().await;
        if let Some(p) = self.poller {
            p.shutdown().await;
        }
        if let Some(w) = self.pair_watcher {
            w.shutdown();
        }
        self.publisher.shutdown().await;
    }
}

async fn init_common(cfg: &Config) -> Result<(Arc<SigningKey>, DtlsCertificate, Arc<SharedState>)> {
    let identity = match &cfg.identity.store {
        IdentityStore::Fs { path } => {
            let store = FsKeyStore::new(path.clone());
            load_or_create(&store as &dyn KeyStore).await?
        }
    };

    let (cert, rotated) =
        dtls_cert::load_or_generate(&cfg.dtls.cert_path, cfg.rotate_interval()).await?;
    if rotated {
        // Cert-rotation policy (was TODO(M3.2) pre-PR #5):
        //
        // `PassivePeer` is built with a single `webrtc::api::API` that
        // binds the current cert. Connections established before a
        // future rotation keep their already-bound DTLS session — the
        // API is rebuilt per-daemon-restart, not per-offer, so existing
        // peers hold references to the old API's cert via their
        // RTCPeerConnection's config. Clients that resolve AFTER
        // rotation see the new `fp` from the republished record
        // (publisher.trigger() fires below) and dial the new cert.
        //
        // The brief window between "cert rotates on disk" and "next
        // relay poll observes the new record" is the only gap —
        // clients in that window will fingerprint-mismatch on DTLS
        // and MUST retry. Preventing that requires publishing both
        // old + new fingerprints in the record simultaneously, which
        // breaks schema compatibility. Acceptable trade-off until
        // daily rotations become a deployment reality.
        tracing::info!("openhostd: DTLS certificate generated");
    }

    let state = Arc::new(SharedState::new(&identity, cert.fingerprint_sha256));

    Ok((Arc::new(identity), cert, state))
}

async fn build_listener(
    cert: &DtlsCertificate,
    identity: Arc<SigningKey>,
    state: Arc<SharedState>,
    forwarder: Option<Arc<Forwarder>>,
) -> Result<Arc<PassivePeer>> {
    let peer = PassivePeer::new(
        cert.certificate.clone(),
        cert.fingerprint_sha256,
        identity,
        state,
        forwarder,
    )
    .await?;
    Ok(Arc::new(peer))
}

/// Spawn an [`OfferPoller`] from the config's `offer_poll` section.
/// Returns `None` when `watched_clients` is empty — no poller is
/// needed.
fn build_offer_poller(
    cfg: &Config,
    pair_db_path: &Path,
    identity: Arc<SigningKey>,
    listener: Arc<PassivePeer>,
    state: Arc<SharedState>,
    resolver: Arc<dyn Resolve>,
    publisher: &PublishService,
) -> Option<OfferPoller> {
    let cfg_poll = &cfg.pkarr.offer_poll;
    // Parse z-base-32 client pubkeys; `Config::validate` already
    // guaranteed they decode, so the unwrap cannot fire in prod.
    let watched: Vec<_> = cfg_poll
        .watched_clients
        .iter()
        .filter_map(|s| openhost_core::identity::PublicKey::from_zbase32(s).ok())
        .collect();
    // PR #39 — auto-watch paired clients: the poller also consumes the
    // pair DB on every tick, so a daemon with empty `watched_clients`
    // but a pair-DB path still spawns. `openhostd pair add <pk>` then
    // becomes sufficient to make a client dialable with no config edit.
    // The pair-DB path is always produced by `resolve_pair_db_path`
    // (falls back to the platform-default location), so the poller
    // effectively always spawns from this build path. The `spawn`
    // assert inside `OfferPoller` catches the truly-degenerate case.
    let pair_db_path_owned = pair_db_path.to_path_buf();
    let trigger: Arc<dyn Fn() + Send + Sync> = {
        let handle = publisher.trigger_handle();
        Arc::new(move || handle())
    };
    Some(OfferPoller::spawn(
        identity,
        resolver,
        listener,
        state,
        trigger,
        OfferPollerConfig {
            poll_interval: Duration::from_secs(cfg_poll.poll_secs),
            watched_clients: watched,
            per_client_throttle: Duration::from_secs(cfg_poll.per_client_throttle_secs),
            enforce_allowlist: cfg_poll.enforce_allowlist,
            rate_limit_burst: cfg_poll.rate_limit_burst,
            rate_limit_refill_per_sec: 1.0 / cfg_poll.rate_limit_refill_secs,
            allowed_binding_modes: cfg
                .dtls
                .allowed_binding_modes
                .iter()
                .copied()
                .map(openhost_pkarr::BindingMode::from)
                .collect(),
            pair_db_path: Some(pair_db_path_owned),
        },
    ))
}

/// Build a [`Forwarder`] from the daemon's `ForwardConfig`, or return
/// `None` if no `[forward]` section was configured. In the `None` case
/// the listener keeps the PR #5 stub 502 response path.
fn build_forwarder(cfg: &Config) -> Result<Option<Arc<Forwarder>>> {
    match cfg.forward.as_ref() {
        Some(forward_cfg) => {
            let forwarder = Forwarder::from_config(forward_cfg)?;
            if forwarder.is_some() {
                tracing::info!(
                    target = cfg.forward.as_ref().and_then(|f| f.target.as_deref()),
                    "openhostd: forwarder configured",
                );
            }
            Ok(forwarder.map(Arc::new))
        }
        None => Ok(None),
    }
}

/// Resolve the pairing DB path from config, falling back to the
/// platform default.
fn resolve_pair_db_path(cfg: &Config) -> PathBuf {
    cfg.pairing
        .db_path
        .clone()
        .unwrap_or_else(pairing::default_db_path)
}

/// Spawn the embedded TURN relay when `[turn] enabled = true`,
/// otherwise return `None` and leave the publisher's v2 path intact.
///
/// On success, installs `turn_endpoint` on [`SharedState`] so the
/// publisher's next `snapshot_record` call emits a v3 record.
async fn maybe_spawn_turn(
    cfg: &Config,
    identity: &Arc<SigningKey>,
    state: &Arc<SharedState>,
) -> Result<Option<crate::turn_server::TurnHandle>> {
    if !cfg.turn.enabled {
        return Ok(None);
    }
    let public_ip = cfg.turn.public_ip.ok_or_else(|| {
        crate::error::DaemonError::Turn(
            "turn.enabled = true requires turn.public_ip to be set".into(),
        )
    })?;
    let bind_addr: std::net::SocketAddr = cfg.turn.bind_addr.parse().map_err(|_| {
        crate::error::DaemonError::Turn(format!(
            "turn.bind_addr is not a valid socket address: {}",
            cfg.turn.bind_addr
        ))
    })?;
    let runtime_cfg = crate::turn_server::TurnRuntimeConfig {
        bind_addr,
        public_ip,
    };
    let handle = crate::turn_server::spawn(&runtime_cfg, &identity.public_key())
        .await
        .map_err(|e| {
            crate::error::DaemonError::Turn(format!("failed to spawn TURN server: {e}"))
        })?;
    let public_port = cfg.turn.public_port.unwrap_or(bind_addr.port());
    state.set_turn_endpoint(Some(openhost_core::pkarr_record::TurnEndpoint {
        ip: public_ip,
        port: public_port,
    }));
    tracing::info!(
        public_ip = %public_ip,
        public_port,
        "openhostd: TURN relay advertised in host record (v3)"
    );
    Ok(Some(handle))
}

/// Load the pairing DB into `state.allow`. Missing file = empty allow
/// list (not an error). Malformed file IS an error.
fn load_pair_db_into_state(path: &Path, state: &SharedState, cfg: &Config) -> Result<()> {
    let db = pairing::load(path)?;
    let hashes = db.compute_hashes(&state.salt());
    let count = hashes.len();
    state.replace_allow(hashes);
    tracing::info!(
        count,
        path = %path.display(),
        "openhostd: loaded pairing DB",
    );
    // Startup warn: enforce_allowlist=on + empty DB + non-empty
    // watched_clients is almost always a misconfiguration — operators
    // upgrading from PR #7a will otherwise see every connection
    // rejected without a clear explanation in the log.
    if cfg.pkarr.offer_poll.enforce_allowlist
        && count == 0
        && !cfg.pkarr.offer_poll.watched_clients.is_empty()
    {
        tracing::warn!(
            "openhostd: allowlist enforcement is on but the pair DB is empty; \
             no client offer will be accepted. Add clients with \
             `openhostd pair add <pubkey>` or set \
             `pkarr.offer_poll.enforce_allowlist = false` in the config.",
        );
    }
    Ok(())
}

/// Re-read the pairing DB + swap the allow list atomically. Used by
/// the SIGHUP handler. Returns the new entry count on success.
fn reload_pair_db(path: &Path, state: &SharedState) -> Result<usize> {
    let db = pairing::load(path)?;
    let hashes = db.compute_hashes(&state.salt());
    let count = hashes.len();
    state.replace_allow(hashes);
    Ok(count)
}

/// Shared handler for both reload paths (SIGHUP + file-watcher):
/// re-read the pair DB, swap the allow list, trigger a republish.
/// Never panics; a failed reload logs a `warn!` and leaves the
/// previous allow list in place.
fn reload_and_trigger(
    path: &Path,
    state: &SharedState,
    publisher: &PublishService,
    source: &'static str,
) {
    match reload_pair_db(path, state) {
        Ok(count) => {
            tracing::info!(
                count,
                source,
                "openhostd: pairing DB reloaded; republishing",
            );
            publisher.trigger();
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                source,
                "openhostd: pairing DB reload failed; keeping previous allow list",
            );
        }
    }
}

/// Install a global `tracing_subscriber` with the configured level filter.
/// Called once from `main` and from integration tests that want logs.
pub fn init_tracing(level: &str) {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(level))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt().with_env_filter(filter).try_init();
}
