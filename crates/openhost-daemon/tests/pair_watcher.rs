//! Integration test for PR #17: the pair-DB file watcher reloads the
//! allowlist in the running daemon without requiring SIGHUP.
//!
//! Boots the full `App` via `build_with_transport`, confirms the
//! initial allowlist is empty, writes a new pair entry to the DB on
//! disk, then waits for the watcher-driven reload to propagate into
//! `SharedState`. Success requires the watcher path — the test never
//! sends SIGHUP and runs identically on Unix and Windows (modulo
//! notify-backend timing).

mod support;

use openhost_core::identity::SigningKey;
use openhost_daemon::config::{
    Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, OfferPollConfig, PairingConfig,
    PkarrConfig,
};
use openhost_daemon::{pairing, App};
use std::sync::Arc;
use std::time::Duration;
use support::CaptureTransport;
use tempfile::TempDir;

fn build_config(tmp: &TempDir, pair_db_path: std::path::PathBuf) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: tmp.path().join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: vec![],
            republish_secs: 3600,
            offer_poll: OfferPollConfig {
                poll_secs: 1,
                watched_clients: vec![],
                per_client_throttle_secs: 0,
                enforce_allowlist: false,
                rate_limit_burst: 10,
                rate_limit_refill_secs: 1.0,
            },
        },
        dtls: DtlsConfig {
            cert_path: tmp.path().join("dtls.pem"),
            rotate_secs: 3600,
            allowed_binding_modes: vec![
                openhost_daemon::config::BindingModeConfig::Exporter,
                openhost_daemon::config::BindingModeConfig::CertFp,
            ],
        },
        forward: None,
        log: LogConfig::default(),
        pairing: PairingConfig {
            db_path: Some(pair_db_path),
            // Shorter debounce so the test doesn't wait a full default
            // 250 ms window on every modification.
            watch_debounce_ms: 50,
        },
        turn: Default::default(),
    }
}

/// Add a pubkey to the pair DB at `path` and wait for the daemon's
/// `SharedState.allow` to contain its expected hash. The watcher
/// must drive this reload; the test never sends SIGHUP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watcher_reloads_allowlist_without_sighup() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let tmp = TempDir::new().unwrap();
    let pair_db_path = tmp.path().join("allow.toml");
    let cfg = build_config(&tmp, pair_db_path.clone());
    let transport = Arc::new(CaptureTransport::default());
    let app = App::build_with_transport(cfg, transport)
        .await
        .expect("app builds");

    // Initial allow list is empty.
    assert_eq!(app.state().allow().len(), 0);

    // Drive the event loop concurrently so the watcher arm actually
    // fires. The test writes to the DB, the loop's select! picks up
    // the watcher event, `reload_and_trigger` runs, `SharedState`
    // updates — all without SIGHUP.
    let state = Arc::clone(app.state());
    let run_task = tokio::spawn(async move { app.run().await });

    // Allow the initial-publish wait + watcher arm to be armed.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Add a pubkey via the same `pairing::add` the CLI uses.
    let client_pk = SigningKey::generate_os_rng().public_key();
    pairing::add(&pair_db_path, &client_pk, Some("test-client".into()))
        .expect("pair add writes TOML");

    // Wait up to 3 s for the watcher → reload propagation.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let expected_hash = openhost_core::crypto::allowlist_hash(&state.salt(), &client_pk.to_bytes());
    loop {
        if state.is_client_allowed(&client_pk) {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let snapshot = state.allow();
            panic!(
                "watcher never propagated the new entry into SharedState; \
                 snapshot has {} entries, expected hash = {:?}",
                snapshot.len(),
                expected_hash,
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Abort the run task. We don't need an explicit shutdown here —
    // `App::run` owns everything and aborting releases it via Drop.
    run_task.abort();
    let _ = run_task.await;
}
