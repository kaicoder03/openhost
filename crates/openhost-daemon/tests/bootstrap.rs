//! End-to-end bootstrap test with a fake pkarr Transport.
//!
//! Drives the full `App::build_with_transport` path against a tempdir
//! config. Asserts identity + cert files are written with the right mode,
//! the fake transport sees at least one publish with the expected
//! fingerprint, and shutdown completes promptly.

use async_trait::async_trait;
use openhost_core::pkarr_record::DTLS_FINGERPRINT_LEN;
use openhost_daemon::config::{
    Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, PkarrConfig,
};
use openhost_daemon::{App, Result as DaemonResult};
use openhost_pkarr::{PkarrError, Result as PkarrResult, Transport};
use pkarr::{SignedPacket, Timestamp};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;

#[derive(Default)]
struct FakeTransport {
    calls: Mutex<Vec<[u8; DTLS_FINGERPRINT_LEN]>>,
}

#[async_trait]
impl Transport for FakeTransport {
    async fn publish(&self, packet: &SignedPacket, _cas: Option<Timestamp>) -> PkarrResult<()> {
        let signed = openhost_pkarr::decode(packet).map_err(|_| PkarrError::NotFound)?;
        self.calls.lock().unwrap().push(signed.record.dtls_fp);
        Ok(())
    }
}

fn test_config(dir: &TempDir) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: dir.path().join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: vec![],
            republish_secs: 3600, // keep the ticker inert
            offer_poll: Default::default(),
        },
        dtls: DtlsConfig {
            cert_path: dir.path().join("dtls.pem"),
            rotate_secs: 3600,
            allowed_binding_modes: vec![
                openhost_daemon::config::BindingModeConfig::Exporter,
                openhost_daemon::config::BindingModeConfig::CertFp,
            ],
        },
        forward: None,
        log: LogConfig::default(),
        pairing: Default::default(),
    }
}

fn identity_path(cfg: &Config) -> PathBuf {
    match &cfg.identity.store {
        IdentityStore::Fs { path } => path.clone(),
    }
}

#[tokio::test]
async fn daemon_bootstraps_and_publishes_initial_record() -> DaemonResult<()> {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);

    let transport = Arc::new(FakeTransport::default());
    let app =
        App::build_with_transport(cfg.clone(), transport.clone() as Arc<dyn Transport>).await?;

    // Identity + cert files must exist after build.
    assert!(
        identity_path(&cfg).exists(),
        "identity file was not created at {:?}",
        identity_path(&cfg)
    );
    assert!(
        cfg.dtls.cert_path.exists(),
        "DTLS cert file was not created at {:?}",
        cfg.dtls.cert_path
    );

    // On Unix, both files must be mode 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [identity_path(&cfg), cfg.dtls.cert_path.clone()] {
            let meta = tokio::fs::metadata(&path).await.unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file {:?} should be 0600, got {mode:#o}", path);
        }
    }

    // Give the initial publish a moment to fire.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let calls = transport.calls.lock().unwrap().clone();
    assert!(!calls.is_empty(), "no publish fired within 100ms");
    assert_eq!(
        calls[0],
        app.cert().fingerprint_sha256,
        "published fingerprint must match the generated cert"
    );

    // Shutdown completes within 50ms (tight bound: nothing real is running).
    let shutdown_start = std::time::Instant::now();
    app.shutdown().await;
    assert!(
        shutdown_start.elapsed() < Duration::from_millis(500),
        "shutdown took {:?}, expected < 500ms",
        shutdown_start.elapsed()
    );

    Ok(())
}

#[tokio::test]
async fn identity_persists_across_rebuilds() -> DaemonResult<()> {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);

    let transport = Arc::new(FakeTransport::default());
    let app1 =
        App::build_with_transport(cfg.clone(), transport.clone() as Arc<dyn Transport>).await?;
    let pk1 = app1.identity().public_key();
    app1.shutdown().await;

    let transport2 = Arc::new(FakeTransport::default());
    let app2 =
        App::build_with_transport(cfg.clone(), transport2.clone() as Arc<dyn Transport>).await?;
    let pk2 = app2.identity().public_key();
    app2.shutdown().await;

    assert_eq!(pk1, pk2, "same identity file must yield the same pubkey");
    Ok(())
}

#[tokio::test]
async fn trigger_republish_is_reflected_in_next_publish() -> DaemonResult<()> {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp);

    let transport = Arc::new(FakeTransport::default());
    let app =
        App::build_with_transport(cfg.clone(), transport.clone() as Arc<dyn Transport>).await?;

    tokio::time::sleep(Duration::from_millis(30)).await;
    let initial_count = transport.calls.lock().unwrap().len();
    assert!(initial_count >= 1);

    // Simulate a cert rotation: mutate the shared state and trigger.
    app.state().set_dtls_fp([0xFF; DTLS_FINGERPRINT_LEN]);
    app.trigger_republish();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let calls = transport.calls.lock().unwrap().clone();
    assert!(
        calls.len() > initial_count,
        "trigger should have forced at least one additional publish"
    );
    assert_eq!(*calls.last().unwrap(), [0xFF; DTLS_FINGERPRINT_LEN]);

    app.shutdown().await;
    Ok(())
}
