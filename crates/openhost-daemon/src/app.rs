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
use crate::identity_store::{load_or_create, FsKeyStore, KeyStore};
use crate::listener::PassivePeer;
use crate::publish::{self, PublishService, SharedState};
use crate::signal::shutdown_signal;
use openhost_core::identity::SigningKey;
use openhost_pkarr::{InitialPublishOutcome, Transport};
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
}

impl App {
    /// Build the daemon against the real pkarr network.
    pub async fn build(cfg: Config) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let listener = build_listener(&cert, identity.clone(), state.clone()).await?;
        let publisher = publish::start(&cfg.pkarr, identity.clone(), state.clone()).await?;
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
            listener,
        })
    }

    /// Build the daemon with a caller-supplied [`Transport`]. Used by
    /// integration tests to swap in a fake that doesn't open sockets.
    pub async fn build_with_transport(cfg: Config, transport: Arc<dyn Transport>) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let listener = build_listener(&cert, identity.clone(), state.clone()).await?;
        let publisher =
            publish::start_with_transport(&cfg.pkarr, identity.clone(), state.clone(), transport);
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
            listener,
        })
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
    /// answer SDP. Mirrors what the offer-record poller will call in
    /// PR #7.
    pub async fn handle_offer(&self, offer_sdp: &str) -> Result<String> {
        self.listener
            .handle_offer(offer_sdp)
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
    pub async fn run(self) -> Result<()> {
        self.wait_for_initial_publish().await;
        tracing::info!(
            pubkey = %self.identity.public_key(),
            dtls_fp = %self.cert.fingerprint_colon_hex(),
            "openhostd: up",
        );
        shutdown_signal().await;
        tracing::info!("openhostd: shutdown signal received, stopping publisher");
        self.listener.shutdown().await;
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
) -> Result<Arc<PassivePeer>> {
    let peer = PassivePeer::new(cert.certificate.clone(), identity, state).await?;
    Ok(Arc::new(peer))
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
