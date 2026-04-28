//! Real-network smoke test.
//!
//! Publishes to the bundled public Pkarr relays + the Mainline DHT, then
//! uses `openhost_pkarr::Resolver` to read the record back and confirms
//! the fingerprint round-trips.
//!
//! **Not on CI.** Public relays are shared and rate-limited; running this
//! test from a continuous job would be a bad neighbor. To run manually
//! before merging a change that touches the publish path:
//!
//! ```bash
//! cargo test -p openhost-daemon --features real-network -- --ignored
//! ```

#![cfg(feature = "real-network")]

use openhost_daemon::config::{
    Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, PkarrConfig,
};
use openhost_daemon::App;
use openhost_pkarr::{PkarrResolve, Resolver};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn real_config(dir: &TempDir) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: dir.path().join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: vec!["https://pkarr.pubky.app".to_string()],
            republish_secs: 3600,
            offer_poll: Default::default(),
        },
        dtls: DtlsConfig {
            cert_path: dir.path().join("dtls.pem"),
            rotate_secs: 3600,
            allowed_binding_modes: vec![],
        },
        forward: None,
        log: LogConfig::default(),
        pairing: Default::default(),
        turn: Default::default(),
    }
}

#[tokio::test]
#[ignore = "real-network: spawns publish + resolve against public relays"]
async fn publishes_and_resolves_over_public_relays() {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = real_config(&tmp);

    // Publish: spawn the daemon against the real pkarr network.
    let app = App::build(cfg.clone()).await.expect("daemon builds");
    let pubkey = app.identity().public_key();
    let expected_fp = app.cert().fingerprint_sha256;

    // Give the initial publish time to propagate to the relay.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Resolve via the same relay list + DHT.
    let mut builder = pkarr::Client::builder();
    builder
        .relays(&["https://pkarr.pubky.app"])
        .expect("relay URL valid");
    let client = Arc::new(builder.build().expect("pkarr client builds"));
    let resolver = Resolver::new(Arc::new(PkarrResolve::new(client)));

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("post-epoch")
        .as_secs();

    // Retry a few times — relay propagation is not instant.
    let mut last_err = None;
    let mut resolved = None;
    for attempt in 0..5 {
        match resolver.resolve(&pubkey, now_ts, None).await {
            Ok(r) => {
                resolved = Some(r);
                break;
            }
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(1 + attempt)).await;
            }
        }
    }

    app.shutdown().await;

    let signed = resolved.unwrap_or_else(|| {
        panic!(
            "resolver never returned a record; last error: {:?}",
            last_err
        )
    });

    assert_eq!(
        signed.record.dtls_fp, expected_fp,
        "fingerprint pinned in the resolved record must match the cert the daemon generated"
    );
}
