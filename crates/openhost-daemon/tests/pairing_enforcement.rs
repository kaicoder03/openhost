//! Integration tests for the PR #7b allowlist + rate-limit gates on
//! the offer poller.
//!
//! Reuses `support::ScriptedResolve` / `CaptureTransport` from PR #7a.
//! The setup pattern: stage a sealed offer under the client's zone;
//! tick the poller; assert whether the offer reached `handle_offer`
//! (observable via `app.listener().active_count()`) or was rejected.

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_daemon::config::{
    Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, OfferPollConfig, PairingConfig,
    PkarrConfig,
};
use openhost_daemon::{pairing, App, Result as DaemonResult};
use openhost_pkarr::{OfferPlaintext, OfferRecord, OFFER_TXT_PREFIX, OFFER_TXT_TTL};
use pkarr::dns::rdata::TXT;
use pkarr::dns::Name;
use pkarr::{Keypair, SignedPacket, Timestamp};
use rand::rngs::OsRng;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use support::{CaptureTransport, ScriptedResolve};
use tempfile::TempDir;
use zeroize::Zeroizing;

/// Build a daemon `Config` with the PR #7b knobs set explicitly. The
/// caller controls which clients are watched and whether the allowlist
/// is enforced; the pair-DB path is a tmpfile the test can pre-populate.
fn build_config(
    tmp: &TempDir,
    watched: &[PublicKey],
    enforce_allowlist: bool,
    rate_limit_burst: u32,
    rate_limit_refill_secs: f64,
    per_client_throttle_secs: u64,
    pair_db_path: Option<PathBuf>,
) -> Config {
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
                watched_clients: watched.iter().map(|pk| pk.to_zbase32()).collect(),
                per_client_throttle_secs,
                enforce_allowlist,
                rate_limit_burst,
                rate_limit_refill_secs,
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
            db_path: pair_db_path,
            ..PairingConfig::default()
        },
        turn: Default::default(),
    }
}

/// Synthetic v3 offer blob for negative-path tests that never need
/// the daemon to actually parse the SDP.
fn synthetic_offer_blob() -> openhost_pkarr::OfferBlob {
    openhost_pkarr::OfferBlob {
        ice_ufrag: "abcd".to_string(),
        ice_pwd: "0123456789abcdefghij!@".to_string(),
        setup: openhost_pkarr::SetupRole::Active,
        binding_mode: openhost_pkarr::BindingMode::Exporter,
        client_dtls_fp: [0xCDu8; openhost_pkarr::DTLS_FP_LEN],
        candidates: vec![],
    }
}

/// Build a pkarr `SignedPacket` under the client's key containing an
/// `_offer-<host-hash>` TXT sealed to the daemon. Post-compact-offer
/// the helper takes an [`openhost_pkarr::OfferBlob`] so negative-path
/// tests can ship a synthetic blob without a full webrtc-rs SDP.
async fn build_offer_packet(
    client_sk: &SigningKey,
    daemon_pk: &PublicKey,
    offer_blob: openhost_pkarr::OfferBlob,
    ts_secs: u64,
) -> SignedPacket {
    let plaintext = OfferPlaintext::new_v3(client_sk.public_key(), offer_blob);
    let mut rng = OsRng;
    let offer = OfferRecord::seal(&mut rng, daemon_pk, &plaintext).unwrap();
    let txt_value = URL_SAFE_NO_PAD.encode(&offer.sealed);
    let label = openhost_pkarr::host_hash_label(daemon_pk);
    let name = format!("{OFFER_TXT_PREFIX}{label}");

    let seed = Zeroizing::new(client_sk.to_bytes());
    let keypair = Keypair::from_secret_key(&seed);
    SignedPacket::builder()
        .txt(
            Name::new_unchecked(&name),
            TXT::try_from(txt_value.as_str()).unwrap(),
            OFFER_TXT_TTL,
        )
        .timestamp(Timestamp::from(ts_secs * 1_000_000))
        .sign(&keypair)
        .unwrap()
}

async fn real_client_offer_sdp() -> String {
    use webrtc::api::APIBuilder;
    use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
    use webrtc::peer_connection::configuration::RTCConfiguration;

    let api = APIBuilder::new().build();
    let pc = api
        .new_peer_connection(RTCConfiguration::default())
        .await
        .expect("client pc builds");
    let _dc = pc
        .create_data_channel("openhost", Some(RTCDataChannelInit::default()))
        .await
        .expect("create DC");
    let offer = pc.create_offer(None).await.expect("create_offer");
    pc.set_local_description(offer).await.expect("set local");
    // No `gathering_complete` wait — keeps the SDP small enough to fit.
    let sdp = pc.local_description().await.unwrap().sdp;
    let _ = pc.close().await;
    sdp
}

#[tokio::test]
async fn authorized_client_offer_is_processed() -> DaemonResult<()> {
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    let pair_db = tmp.path().join("allow.toml");
    pairing::add(&pair_db, &client_pk, Some("test".into())).unwrap();

    let cfg = build_config(&tmp, &[client_pk], true, 3, 5.0, 5, Some(pair_db));
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    let daemon_pk = app.identity().public_key();
    let offer_sdp = real_client_offer_sdp().await;
    let client_fp = openhost_pkarr::extract_sha256_fingerprint_from_sdp(&offer_sdp).expect("fp");
    let offer_blob = openhost_pkarr::sdp_to_offer_blob(
        &offer_sdp,
        &client_fp,
        openhost_pkarr::BindingMode::Exporter,
    )
    .expect("blob");
    let packet = build_offer_packet(&client_sk, &daemon_pk, offer_blob, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    // Wait until an answer lands in SharedState. (The BEP44 encoder may
    // evict it from the wire packet — documented in PR #7a — so we
    // assert against the queue, not the captured bytes.)
    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if app
            .state()
            .snapshot_answers()
            .iter()
            .any(|e| e.client_hash == expected_hash)
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("authorised client offer did not yield an answer");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn unauthorized_client_offer_is_skipped() -> DaemonResult<()> {
    // No pair added; enforce=on. Offer must be skipped.
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    let pair_db = tmp.path().join("allow.toml");
    let cfg = build_config(&tmp, &[client_pk], true, 3, 5.0, 5, Some(pair_db));
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    let daemon_pk = app.identity().public_key();
    // Not-paired client — daemon never reaches handle_offer.
    let packet = build_offer_packet(
        &client_sk,
        &daemon_pk,
        synthetic_offer_blob(),
        1_700_000_000,
    )
    .await;
    resolver.set_packet(&client_pk, &packet);

    // Wait a few poll cycles. No answer should ever be queued.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    assert!(
        !app.state()
            .snapshot_answers()
            .iter()
            .any(|e| e.client_hash == expected_hash),
        "unauthorised client MUST NOT have an answer queued"
    );
    assert_eq!(
        app.listener().active_count().await,
        0,
        "unauthorised client MUST NOT trigger handle_offer"
    );

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn enforce_disabled_preserves_pr7a_behavior() -> DaemonResult<()> {
    // enforce=off + empty pair DB: offer still gets processed (PR #7a
    // semantics preserved under the escape-hatch knob).
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    let cfg = build_config(&tmp, &[client_pk], false, 3, 5.0, 5, None);
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    let daemon_pk = app.identity().public_key();
    let offer_sdp = real_client_offer_sdp().await;
    let client_fp = openhost_pkarr::extract_sha256_fingerprint_from_sdp(&offer_sdp).expect("fp");
    let offer_blob = openhost_pkarr::sdp_to_offer_blob(
        &offer_sdp,
        &client_fp,
        openhost_pkarr::BindingMode::Exporter,
    )
    .expect("blob");
    let packet = build_offer_packet(&client_sk, &daemon_pk, offer_blob, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if app
            .state()
            .snapshot_answers()
            .iter()
            .any(|e| e.client_hash == expected_hash)
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("enforce=false should have let the offer through");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn rate_limit_caps_burst_of_distinct_offers() -> DaemonResult<()> {
    // Set burst = 2, refill = 3600s (effectively none over the test
    // window), per-client throttle = 0 so dedup doesn't gate. Publish
    // 5 distinct-ts offers across 6 poll ticks; only `burst` = 2
    // should reach handle_offer — the remaining 3 hit an empty bucket.
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    let pair_db = tmp.path().join("allow.toml");
    pairing::add(&pair_db, &client_pk, None).unwrap();

    let cfg = build_config(&tmp, &[client_pk], true, 2, 3600.0, 0, Some(pair_db));
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    let daemon_pk = app.identity().public_key();
    let base_ts: u64 = 1_700_000_000;

    // Publish 5 offers with strictly-increasing ts values, ~1.2s
    // apart (slightly longer than the 1 Hz poll tick so each tick
    // sees a distinct packet).
    for i in 0..5 {
        let offer_sdp = real_client_offer_sdp().await;
        let client_fp =
            openhost_pkarr::extract_sha256_fingerprint_from_sdp(&offer_sdp).expect("fp");
        let offer_blob = openhost_pkarr::sdp_to_offer_blob(
            &offer_sdp,
            &client_fp,
            openhost_pkarr::BindingMode::Exporter,
        )
        .expect("blob");
        let pkt = build_offer_packet(&client_sk, &daemon_pk, offer_blob, base_ts + i).await;
        resolver.set_packet(&client_pk, &pkt);
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }

    let count = app.listener().active_count().await;
    assert_eq!(
        count, 2,
        "rate limit should cap to burst=2 handle_offer calls, saw {count}",
    );

    app.shutdown().await;
    Ok(())
}

/// PR #39 — auto-watch paired clients. Config has an EMPTY
/// `watched_clients` list; the client is added only via
/// `pairing::add`. The daemon's offer-poller must still pick the
/// client up on its next tick (via the pair-DB union in
/// `resolved_watched_clients`) and process a real offer.
#[tokio::test]
async fn unlisted_but_paired_client_is_auto_watched() -> DaemonResult<()> {
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    let pair_db = tmp.path().join("allow.toml");
    pairing::add(&pair_db, &client_pk, Some("auto-watch".into())).unwrap();

    // Crucial bit: `watched = &[]` — config list empty, pair-DB
    // populated. Pre-PR-#39 behavior was `build_offer_poller` returns
    // None in this case and no polling happens at all.
    let cfg = build_config(&tmp, &[], true, 3, 5.0, 5, Some(pair_db));
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    let daemon_pk = app.identity().public_key();
    let offer_sdp = real_client_offer_sdp().await;
    let client_fp = openhost_pkarr::extract_sha256_fingerprint_from_sdp(&offer_sdp).expect("fp");
    let offer_blob = openhost_pkarr::sdp_to_offer_blob(
        &offer_sdp,
        &client_fp,
        openhost_pkarr::BindingMode::Exporter,
    )
    .expect("blob");
    let packet = build_offer_packet(&client_sk, &daemon_pk, offer_blob, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if app
            .state()
            .snapshot_answers()
            .iter()
            .any(|e| e.client_hash == expected_hash)
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("auto-watched (paired-only) client offer did not yield an answer");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    app.shutdown().await;
    Ok(())
}

/// PR #39 — removing a pubkey from the pair DB stops polling on the
/// next tick. Starts with the client paired, confirms an offer is
/// processed, then removes the pair and confirms a FRESH offer
/// (distinct ts) is NOT processed.
#[tokio::test]
async fn pair_remove_stops_auto_watch() -> DaemonResult<()> {
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    let pair_db = tmp.path().join("allow.toml");
    pairing::add(&pair_db, &client_pk, None).unwrap();

    let cfg = build_config(&tmp, &[], true, 3, 5.0, 0, Some(pair_db.clone()));
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    // Step 1: paired — first offer should process.
    let daemon_pk = app.identity().public_key();
    let offer_sdp = real_client_offer_sdp().await;
    let client_fp = openhost_pkarr::extract_sha256_fingerprint_from_sdp(&offer_sdp).expect("fp");
    let offer_blob = openhost_pkarr::sdp_to_offer_blob(
        &offer_sdp,
        &client_fp,
        openhost_pkarr::BindingMode::Exporter,
    )
    .expect("blob");
    let packet_a = build_offer_packet(&client_sk, &daemon_pk, offer_blob, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet_a);

    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if app
            .state()
            .snapshot_answers()
            .iter()
            .any(|e| e.client_hash == expected_hash)
        {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!("paired client's first offer did not yield an answer");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Step 2: remove pair — the poller's next tick should read the
    // updated DB and stop polling this client.
    pairing::remove(&pair_db, &client_pk).unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Stage a FRESH offer (different ts so it's not dedupe-skipped).
    let fresh_sdp = real_client_offer_sdp().await;
    let fresh_fp = openhost_pkarr::extract_sha256_fingerprint_from_sdp(&fresh_sdp).expect("fp");
    let fresh_blob = openhost_pkarr::sdp_to_offer_blob(
        &fresh_sdp,
        &fresh_fp,
        openhost_pkarr::BindingMode::Exporter,
    )
    .expect("blob");
    let packet_b = build_offer_packet(&client_sk, &daemon_pk, fresh_blob, 1_700_000_060).await;
    resolver.set_packet(&client_pk, &packet_b);

    let answers_before = app.state().snapshot_answers().len();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let answers_after = app.state().snapshot_answers().len();
    assert_eq!(
        answers_before, answers_after,
        "removed-pair client offer must NOT yield a new answer"
    );

    app.shutdown().await;
    Ok(())
}
