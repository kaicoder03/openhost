//! Top-level daemon lifecycle.
//!
//! [`App::build`] loads the identity, generates/loads the DTLS cert,
//! constructs [`crate::publish::SharedState`], and spawns the pkarr
//! publisher. [`App::run`] blocks until a shutdown signal arrives and
//! then tears the publisher down cleanly.
//!
//! The binary's `main` is a thin shim over these two methods; integration
//! tests skip the binary and drive [`App`] directly with an injected
//! `Transport`.

use crate::config::{Config, IdentityStore};
use crate::dtls_cert::{self, DtlsCertificate};
use crate::error::Result;
use crate::identity_store::{load_or_create, FsKeyStore, KeyStore};
use crate::publish::{self, PublishService, SharedState};
use crate::signal::shutdown_signal;
use openhost_core::identity::SigningKey;
use openhost_pkarr::Transport;
use std::sync::Arc;

/// A fully-constructed daemon, ready to run.
///
/// Building an `App` already performed every side effect that can fail
/// without running the event loop: identity loaded or generated, DTLS cert
/// loaded or generated, initial publish request in flight.
pub struct App {
    identity: Arc<SigningKey>,
    cert: DtlsCertificate,
    state: Arc<SharedState>,
    publisher: PublishService,
}

impl App {
    /// Build the daemon against the real pkarr network.
    pub async fn build(cfg: Config) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let publisher = publish::start(&cfg.pkarr, identity.clone(), state.clone()).await?;
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
        })
    }

    /// Build the daemon with a caller-supplied [`Transport`]. Used by
    /// integration tests to swap in a fake that doesn't open sockets.
    pub async fn build_with_transport(cfg: Config, transport: Arc<dyn Transport>) -> Result<Self> {
        let (identity, cert, state) = init_common(&cfg).await?;
        let publisher =
            publish::start_with_transport(&cfg.pkarr, identity.clone(), state.clone(), transport);
        Ok(Self {
            identity,
            cert,
            state,
            publisher,
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

    /// Request an immediate republish.
    pub fn trigger_republish(&self) {
        self.publisher.trigger();
    }

    /// Block until a shutdown signal arrives, then shut the publisher
    /// down cleanly.
    pub async fn run(self) -> Result<()> {
        tracing::info!(
            pubkey = %self.identity.public_key(),
            dtls_fp = %self.cert.fingerprint_colon_hex(),
            "openhostd: up",
        );
        shutdown_signal().await;
        tracing::info!("openhostd: shutdown signal received, stopping publisher");
        self.publisher.shutdown().await;
        tracing::info!("openhostd: bye");
        Ok(())
    }

    /// Shut the publisher down without waiting for a signal. Intended for
    /// integration tests.
    pub async fn shutdown(self) {
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
        // TODO(M3.2): when PR #5 introduces the WebRTC listener, cert
        // rotation opens a window in which a client that resolved under
        // the old `fp` dials the new cert and fails the DTLS handshake.
        // Decide whether the listener keeps the previous cert alive for
        // N minutes after rotation, or clients simply retry on failure.
        // Neither requires changes this PR (no listener yet).
        tracing::info!("openhostd: DTLS certificate generated");
    }

    let state = Arc::new(SharedState::new(&identity, cert.fingerprint_sha256));

    Ok((Arc::new(identity), cert, state))
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
