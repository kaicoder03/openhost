//! Integration tests for the PR #7a offer-record polling loop.
//!
//! The `support::ScriptedResolve` fake serves a staged `SignedPacket`
//! for a given pubkey; the `support::CaptureTransport` records every
//! packet the daemon publishes. Together they let us exercise the full
//! poll → unseal → handle_offer → seal answer → trigger publish cycle
//! without touching a real relay or the Mainline DHT.
//!
//! For the happy-path test the "offer" SDP is a real one produced by a
//! client-side `RTCPeerConnection` — `PassivePeer::handle_offer` needs
//! a well-formed SDP to succeed.

mod support;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openhost_core::identity::SigningKey;
use openhost_daemon::config::{
    Config, DtlsConfig, IdentityConfig, IdentityStore, LogConfig, OfferPollConfig, PkarrConfig,
};
use openhost_daemon::{App, Result as DaemonResult};
use openhost_pkarr::{
    decode_answer_from_packet, OfferPlaintext, OfferRecord, OFFER_TXT_PREFIX, OFFER_TXT_TTL,
};
use pkarr::dns::rdata::TXT;
use pkarr::dns::Name;
use pkarr::{Keypair, SignedPacket, Timestamp};
use rand::rngs::OsRng;
use std::sync::Arc;
use std::time::Duration;
use support::{CaptureTransport, ScriptedResolve};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::peer_connection::configuration::RTCConfiguration;
use zeroize::Zeroizing;

fn daemon_config(
    tmp: &tempfile::TempDir,
    watched: &[openhost_core::identity::PublicKey],
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
                per_client_throttle_secs: 5,
                // PR #7a semantics: tests here predate PR #7b's
                // allowlist gate. The PR #7b integration tests in
                // `tests/pairing_enforcement.rs` cover the enforced
                // path explicitly.
                enforce_allowlist: false,
                rate_limit_burst: 3,
                rate_limit_refill_secs: 5.0,
            },
        },
        dtls: DtlsConfig {
            cert_path: tmp.path().join("dtls.pem"),
            rotate_secs: 3600,
        },
        forward: None,
        log: LogConfig::default(),
        pairing: Default::default(),
    }
}

/// Build a pkarr `SignedPacket` under the client's key carrying a
/// `_offer-<host-hash>` TXT that seals `offer_sdp` to `daemon_pk`.
async fn build_client_offer_packet(
    client_sk: &SigningKey,
    daemon_pk: &openhost_core::identity::PublicKey,
    offer_sdp: &str,
    ts_secs: u64,
) -> SignedPacket {
    let plaintext = OfferPlaintext {
        client_pk: client_sk.public_key(),
        offer_sdp: offer_sdp.to_string(),
    };
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

/// Return a small but valid webrtc-rs offer SDP.
///
/// We deliberately do NOT wait for ICE gathering to complete — a fully
/// trickled offer with candidates routinely exceeds 1700 bytes and
/// blows past the BEP44 1000-byte cap. An offer without candidates
/// still lets `set_remote_description` succeed in webrtc-rs; trickle
/// candidates over pkarr is a future milestone.
async fn real_client_offer_sdp() -> String {
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
    // NOTE: no `gathering_complete_promise` wait — keeps the SDP small
    // enough to fit a BEP44 packet under the offer TXT.
    let sdp = pc.local_description().await.unwrap().sdp;
    let _ = pc.close().await;
    sdp
}

/// Wait until `predicate` returns `Some(T)` OR `deadline` expires.
async fn wait_until<T, F>(deadline: Duration, mut predicate: F) -> Option<T>
where
    F: FnMut() -> Option<T>,
{
    let end = std::time::Instant::now() + deadline;
    loop {
        if let Some(v) = predicate() {
            return Some(v);
        }
        if std::time::Instant::now() >= end {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn daemon_polls_scripted_offer_and_publishes_answer() -> DaemonResult<()> {
    // Test client's Ed25519 identity.
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    // Bring the daemon up with the test client in its watched list.
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = daemon_config(&tmp, &[client_pk]);

    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    // Stash the client's offer under its pkarr zone.
    let daemon_pk = app.identity().public_key();
    let offer_sdp = real_client_offer_sdp().await;
    let packet = build_client_offer_packet(&client_sk, &daemon_pk, &offer_sdp, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    // Wait until the daemon pushes an answer entry into SharedState.
    //
    // NOTE: we assert against `SharedState::snapshot_answers` rather
    // than against bytes in the captured pkarr packet. The current
    // `PassivePeer::handle_offer` awaits full ICE gathering before
    // returning the answer SDP, and the resulting SDP + sealed overhead
    // can exceed the remaining room under the BEP44 1000-byte cap
    // alongside the main `_openhost` record. In that case the encoder
    // evicts the answer and the test sees no `_answer` TXT on the wire.
    // Splitting ICE trickle into separate pkarr records is tracked as
    // post-v0.1 work — see `CHANGELOG.md` "Known limitations in 0.1.0"
    // and `spec/01-wire-format.md §3.3`.
    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    let got = wait_until(Duration::from_secs(10), || {
        app.state()
            .snapshot_answers()
            .into_iter()
            .find(|e| e.client_hash == expected_hash)
    })
    .await;

    let entry = got.expect("answer entry should appear in SharedState within 10 s");
    let opened = entry.open(&client_sk).expect("answer opens");
    assert_eq!(opened.daemon_pk, daemon_pk);
    assert_eq!(
        opened.offer_sdp_hash,
        openhost_pkarr::hash_offer_sdp(&offer_sdp)
    );
    assert!(
        opened.answer_sdp.contains("a=setup:passive"),
        "answer SDP must assert a=setup:passive; got: {}",
        opened.answer_sdp
    );
    // Belt-and-braces: at least ONE publish was captured. That publish
    // may or may not carry the answer TXT (see the eviction note above),
    // but the publisher trigger must have fired.
    assert!(
        !transport.snapshot().is_empty(),
        "poller should have triggered at least one publish after processing the offer",
    );

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn daemon_does_not_double_process_same_offer() -> DaemonResult<()> {
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = daemon_config(&tmp, &[client_pk]);
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
    let packet = build_client_offer_packet(&client_sk, &daemon_pk, &offer_sdp, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    // Let the poller tick a few times with the same offer.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // `active_count` on the listener is the most observable proxy for
    // "handle_offer was called N times"; each successful call stashes
    // one RTCPeerConnection.
    let count = app.listener().active_count().await;
    assert_eq!(
        count, 1,
        "expected exactly one PC tracked after dedup, got {count}"
    );

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn daemon_ignores_offer_sealed_to_different_daemon() -> DaemonResult<()> {
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();
    let other_daemon_pk = SigningKey::generate_os_rng().public_key();

    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = daemon_config(&tmp, &[client_pk]);
    let transport = Arc::new(CaptureTransport::default());
    let resolver = ScriptedResolve::new();

    let app = App::build_with_transport_and_resolve(
        cfg,
        transport.clone() as Arc<dyn openhost_pkarr::Transport>,
        resolver.clone() as Arc<dyn openhost_pkarr::Resolve>,
    )
    .await
    .expect("app builds");

    // Seal to the wrong recipient — our daemon can't decrypt it.
    let offer_sdp = "v=0\r\na=setup:active\r\n";
    let packet =
        build_client_offer_packet(&client_sk, &other_daemon_pk, offer_sdp, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    // Wait a few poll cycles. No answer should ever appear.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Inspect every published packet — none should carry an answer
    // addressed to this client.
    for raw in transport.snapshot() {
        if let Ok(pk) = SignedPacket::deserialize(&raw) {
            let decoded = decode_answer_from_packet(&pk, &app.state().salt(), &client_pk).unwrap();
            assert!(
                decoded.is_none(),
                "daemon must not publish an answer for an offer it couldn't unseal"
            );
        }
    }

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn daemon_rejects_inner_outer_client_pk_mismatch() -> DaemonResult<()> {
    // Publish an offer whose OUTER BEP44 signer is `client_pk_a` but
    // whose sealed plaintext claims `client_pk = client_pk_b`. The
    // daemon must detect the mismatch and NOT run `handle_offer`.
    let client_sk_a = SigningKey::generate_os_rng();
    let client_pk_a = client_sk_a.public_key();
    let client_sk_b = SigningKey::generate_os_rng();
    let client_pk_b = client_sk_b.public_key();

    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = daemon_config(&tmp, &[client_pk_a]);
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
    let offer_sdp = "v=0\r\na=setup:active\r\n";

    // Build the offer plaintext claiming client_pk_b and seal it to the
    // daemon. Then publish under client_pk_a's BEP44 zone (so the
    // outer signer is A).
    let plaintext = OfferPlaintext {
        client_pk: client_pk_b,
        offer_sdp: offer_sdp.to_string(),
    };
    let mut rng = OsRng;
    let offer = OfferRecord::seal(&mut rng, &daemon_pk, &plaintext).unwrap();
    let txt_value = URL_SAFE_NO_PAD.encode(&offer.sealed);
    let label = openhost_pkarr::host_hash_label(&daemon_pk);
    let name = format!("{OFFER_TXT_PREFIX}{label}");
    let seed = Zeroizing::new(client_sk_a.to_bytes());
    let keypair = Keypair::from_secret_key(&seed);
    let packet = SignedPacket::builder()
        .txt(
            Name::new_unchecked(&name),
            TXT::try_from(txt_value.as_str()).unwrap(),
            OFFER_TXT_TTL,
        )
        .timestamp(Timestamp::from(1_700_000_000 * 1_000_000))
        .sign(&keypair)
        .unwrap();
    resolver.set_packet(&client_pk_a, &packet);

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(
        app.listener().active_count().await,
        0,
        "offer with inner/outer client_pk mismatch must NOT reach handle_offer"
    );

    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn daemon_skips_offer_not_in_watched_list() -> DaemonResult<()> {
    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();
    let other_client_pk = SigningKey::generate_os_rng().public_key();

    let tmp = tempfile::TempDir::new().unwrap();
    // Only watch `other_client_pk`, NOT the one whose offer we stage.
    let cfg = daemon_config(&tmp, &[other_client_pk]);
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
    let offer_sdp = "v=0\r\na=setup:active\r\n";
    let packet = build_client_offer_packet(&client_sk, &daemon_pk, offer_sdp, 1_700_000_000).await;
    resolver.set_packet(&client_pk, &packet);

    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_eq!(
        app.listener().active_count().await,
        0,
        "unwatched client's offer must never reach the listener"
    );

    app.shutdown().await;
    Ok(())
}
