//! End-to-end regression guard for wire-level signalling.
//!
//! PR #15 introduced fragmented `_answer-<client-hash>-<idx>` TXT
//! records so the daemon can stop silently evicting answers that
//! overflow BEP44's 1000-byte `v` cap. This test injects a
//! synthetic, minimal sealed answer into `SharedState`, kicks the
//! publisher, and asserts that the dialer reassembles it on the
//! wire via `decode_answer_fragments_from_packet`.
//!
//! **Why a synthetic answer rather than a live `handle_offer`?** The
//! real webrtc-rs answer SDP seals to ≈450 bytes; even after
//! fragmentation the total packet size (main `_openhost` record +
//! all answer fragment RRs + their ~16-byte overheads) exceeds the
//! 1000-byte cap. Shrinking the WebRTC answer SDP itself, or
//! moving answers out of the main packet entirely, is a separate
//! post-v0.1 line item (see ROADMAP.md). This test covers the
//! fragmentation mechanism in isolation; the full offer→answer
//! daemon flow continues to be exercised end-to-end in
//! `crates/openhost-daemon/tests/offer_poll.rs`.

use bytes::Bytes;
use http_body_util::Full;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use openhost_client::{Dialer, DialerConfig, OpenhostUrl, SigningKey};
use openhost_daemon::config::{
    Config, DtlsConfig, ForwardConfig, IdentityConfig, IdentityStore, LogConfig, OfferPollConfig,
    PkarrConfig,
};
use openhost_daemon::App;
use openhost_pkarr::MemoryPkarrNetwork;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;

/// Spawn a trivial hyper upstream on `127.0.0.1:<ephemeral>` that
/// returns a fixed `200 OK` with body `hello-from-upstream`.
async fn spawn_static_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = server_http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "text/plain")
                                    .header("x-from", "upstream")
                                    .body(Full::new(Bytes::from_static(b"hello-from-upstream")))
                                    .unwrap(),
                            )
                        }),
                    )
                    .await;
            });
        }
    });
    port
}

fn daemon_config(tmp: &TempDir, watched: Vec<String>, upstream_port: Option<u16>) -> Config {
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
                watched_clients: watched,
                per_client_throttle_secs: 0,
                // Allowlist disabled for PR #8 end-to-end tests; the
                // pairing flow has its own coverage in
                // `tests/pairing_enforcement.rs`.
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
        forward: upstream_port.map(|p| ForwardConfig {
            target: Some(format!("http://127.0.0.1:{p}")),
            host_override: None,
            max_body_bytes: 1024 * 1024,
            websockets: None,
        }),
        log: LogConfig::default(),
        pairing: Default::default(),
    }
}

/// Fragment round-trip on the wire: push a synthetic small sealed
/// answer into `SharedState`, trigger a republish, resolve the
/// packet, and assert `decode_answer_fragments_from_packet`
/// reassembles byte-for-byte what the daemon queued. Closes the
/// v0.1 regression where the encoder evicted answers that wouldn't
/// fit the BEP44 cap.
#[tokio::test]
async fn dialer_reassembles_fragmented_answer_from_wire() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
    let net = MemoryPkarrNetwork::new();

    let client_sk = SigningKey::generate_os_rng();
    let client_pk = client_sk.public_key();

    let tmp = TempDir::new().unwrap();
    // No upstream needed; no offer poller needed (empty watched list).
    let cfg = daemon_config(&tmp, vec![], None);
    let app = App::build_with_transport_and_resolve(cfg, net.as_transport(), net.as_resolve())
        .await
        .expect("app builds");
    let daemon_pk = app.identity().public_key();
    let daemon_salt = app.state().salt();

    // Craft a minimal sealed answer. Small enough to fragment into
    // two records and still fit alongside the main `_openhost`
    // packet inside the BEP44 1000-byte cap.
    let sample_offer_sdp = "v=0\r\na=setup:active\r\n";
    let sample_blob = openhost_pkarr::AnswerBlob {
        ice_ufrag: "abcd".to_string(),
        ice_pwd: "0123456789abcdefghij!@".to_string(),
        setup: openhost_pkarr::SetupRole::Passive,
        candidates: vec![openhost_pkarr::BlobCandidate {
            typ: openhost_pkarr::CandidateType::Srflx,
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
            port: 51_820,
        }],
    };
    let plaintext = openhost_pkarr::AnswerPlaintext {
        daemon_pk,
        offer_sdp_hash: openhost_pkarr::hash_offer_sdp(sample_offer_sdp),
        answer: openhost_pkarr::AnswerPayload::V2Blob(sample_blob.clone()),
    };
    let mut rng = rand::rngs::OsRng;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let entry =
        openhost_pkarr::AnswerEntry::seal(&mut rng, &client_pk, &daemon_salt, &plaintext, now_secs)
            .expect("seal");

    app.state().push_answer(entry.clone());
    app.trigger_republish();

    // Poll the memory network until we see a packet carrying the
    // expected answer fragments. A short loop insulates from
    // publisher-tick scheduling without introducing a big fixed sleep.
    let resolver = net.as_resolve();
    let pk_bytes = daemon_pk.to_bytes();
    let pkarr_pk = pkarr::PublicKey::try_from(&pk_bytes).expect("pk");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let reassembled = loop {
        if std::time::Instant::now() >= deadline {
            panic!("publisher never emitted a packet carrying the answer fragments");
        }
        if let Some(packet) = resolver.resolve_most_recent(&pkarr_pk).await {
            if let Some(reassembled) = openhost_pkarr::decode_answer_fragments_from_packet(
                &packet,
                &daemon_salt,
                &client_pk,
            )
            .expect("wire fragments are well-formed")
            {
                break reassembled;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    assert_eq!(
        reassembled.sealed, entry.sealed,
        "wire-reassembled sealed bytes must byte-match the queued AnswerEntry",
    );
    let opened = reassembled.open(&client_sk).expect("answer opens");
    match opened.answer {
        openhost_pkarr::AnswerPayload::V2Blob(got) => assert_eq!(got, sample_blob),
        openhost_pkarr::AnswerPayload::V1Sdp(s) => panic!("expected V2Blob, got V1 SDP: {s}"),
    }
    assert_eq!(opened.daemon_pk, daemon_pk);

    app.shutdown().await;
}

/// End-to-end: the daemon produces a sealed answer for the dialer's
/// offer, fragments it into `_answer-<client-hash>-<idx>` records,
/// lands those fragments on the wire inside the BEP44 1000-byte
/// budget, AND the dial completes successfully (compact-answer-blob
/// PR).
///
/// Pre-compact-blob, `dial()` returned `PollAnswerTimeout` because the
/// sealed answer routinely blew past the BEP44 cap and was evicted by
/// `encode_with_answers`. With the compact blob, the sealed +
/// fragmented answer fits with ~300 bytes of headroom and the full
/// dial chain (ICE + DTLS + channel binding) runs to completion.
#[tokio::test]
async fn daemon_produces_sealed_answer_for_dialer_offer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();
    let net = MemoryPkarrNetwork::new();
    let upstream_port = spawn_static_upstream().await;

    let client_sk = Arc::new(SigningKey::generate_os_rng());
    let client_pk = client_sk.public_key();
    let client_pk_z32 = client_pk.to_zbase32();

    let tmp = TempDir::new().unwrap();
    let cfg = daemon_config(&tmp, vec![client_pk_z32], Some(upstream_port));
    let app = App::build_with_transport_and_resolve(cfg, net.as_transport(), net.as_resolve())
        .await
        .expect("app builds");
    // Pre-compact-blob, this test called
    // `set_skip_ice_gather_for_tests(true)` to keep the answer small
    // enough to fit the BEP44 cap. The compact blob closes that gap so
    // we let the daemon wait for full ICE gather — which the CI macOS
    // runners actually need, since their IPv6 resolver stalls long
    // enough that a skip-gather answer has zero candidates, leaving
    // the client with "no candidate pairs" and a guaranteed timeout.
    let daemon_pk = app.identity().public_key();
    let host_url: OpenhostUrl = format!("oh://{daemon_pk}/").parse().expect("url");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut dialer = Dialer::builder()
        .identity(Arc::clone(&client_sk))
        .host_url(host_url)
        .transport(net.as_transport())
        .resolver(net.as_resolve())
        .config(DialerConfig {
            // Bumped 5 → 20s: with full ICE gather on both sides (no
            // skip-gather shortcut), the STUN-binding round-trip plus
            // host-candidate gather on slow CI runners occasionally
            // needs 5-10s. 20s leaves headroom without inflating the
            // local-run time materially (~3s typical).
            dial_timeout: Duration::from_secs(20),
            answer_poll_interval: Duration::from_millis(250),
            webrtc_connect_timeout: Duration::from_secs(15),
            binding_timeout: Duration::from_secs(10),
        })
        .build()
        .expect("dialer builds");

    let _session = dialer.dial().await.expect(
        "dial must complete end-to-end now that the compact answer blob closes the BEP44 gap",
    );

    let expected_hash =
        openhost_core::crypto::allowlist_hash(&app.state().salt(), &client_pk.to_bytes());
    let answers = app.state().snapshot_answers();
    let entry = answers
        .iter()
        .find(|e| e.client_hash == expected_hash)
        .unwrap_or_else(|| {
            panic!(
                "daemon did not queue an answer for the dialer's offer; saw {} entries",
                answers.len()
            )
        });
    let opened = entry.open(&client_sk).expect("answer opens");
    assert_eq!(opened.daemon_pk, daemon_pk);
    match &opened.answer {
        openhost_pkarr::AnswerPayload::V2Blob(blob) => {
            assert_eq!(
                blob.setup,
                openhost_pkarr::SetupRole::Passive,
                "daemon answer blob must assert passive setup role"
            );
        }
        openhost_pkarr::AnswerPayload::V1Sdp(s) => {
            panic!("daemon must emit v2 compact blobs, got v1 SDP: {s}")
        }
    }

    // Compact-blob PR closed the residual BEP44 gap: sealed answer
    // drops from ~900B to ~220B sealed, with ~300B headroom in the
    // 1000-byte packet. The daemon's latest published packet now
    // carries the answer fragments for this client.
    let pk_bytes = daemon_pk.to_bytes();
    let pkarr_pk = pkarr::PublicKey::try_from(&pk_bytes).expect("pk");
    let resolver = net.as_resolve();
    let packet = resolver
        .resolve_most_recent(&pkarr_pk)
        .await
        .expect("daemon must have published at least one packet");
    assert!(
        packet.encoded_packet().len() <= openhost_pkarr::BEP44_MAX_V_BYTES,
        "daemon's signed packet exceeded the BEP44 1000-byte cap: got {}",
        packet.encoded_packet().len(),
    );
    let wire_entry = openhost_pkarr::decode_answer_fragments_from_packet(
        &packet,
        &app.state().salt(),
        &client_pk,
    )
    .expect("packet is well-formed");
    assert!(
        wire_entry.is_some(),
        "compact answer blob should fit on the wire alongside the main record",
    );

    app.shutdown().await;
}

#[tokio::test]
async fn dial_times_out_when_daemon_not_running() {
    let net = MemoryPkarrNetwork::new();
    let client_sk = Arc::new(SigningKey::generate_os_rng());
    let daemon_sk = SigningKey::generate_os_rng();
    let daemon_pk = daemon_sk.public_key();

    // Publish a signed host record into the memory net so
    // `resolve_host` succeeds — but NEVER start the daemon, so no
    // poller ever picks up the offer. The dialer must hit
    // `PollAnswerTimeout`.
    publish_fake_host_record(&net, &daemon_sk).await;

    let host_url: OpenhostUrl = format!("oh://{daemon_pk}/").parse().unwrap();
    let mut dialer = Dialer::builder()
        .identity(Arc::clone(&client_sk))
        .host_url(host_url)
        .transport(net.as_transport())
        .resolver(net.as_resolve())
        .config(DialerConfig {
            dial_timeout: Duration::from_secs(2),
            answer_poll_interval: Duration::from_millis(100),
            webrtc_connect_timeout: Duration::from_secs(10),
            binding_timeout: Duration::from_secs(10),
        })
        .build()
        .unwrap();

    let outcome = dialer.dial().await;
    match outcome {
        Ok(_) => panic!("dial must not succeed without a running daemon"),
        Err(openhost_client::ClientError::PollAnswerTimeout(_)) => {}
        Err(other) => panic!("expected PollAnswerTimeout, got {other:?}"),
    }
}

async fn publish_fake_host_record(net: &MemoryPkarrNetwork, daemon_sk: &SigningKey) {
    use openhost_core::pkarr_record::{
        OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };
    use openhost_pkarr::codec::encode;

    let record = OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        dtls_fp: [0x42; DTLS_FINGERPRINT_LEN],
        roles: "server".to_string(),
        salt: [0x11; SALT_LEN],
        disc: String::new(),
    };
    let signed = SignedRecord::sign(record, daemon_sk).unwrap();
    let packet = encode(&signed, daemon_sk).unwrap();
    net.as_transport().publish(&packet, None).await.unwrap();
}
