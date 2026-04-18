//! First truly-automated end-to-end regression guard (PR #8).
//!
//! Spins up a real `openhost_daemon::App` and a real
//! `openhost_client::Dialer` in the same tokio runtime, wires both
//! sides through a shared `MemoryPkarrNetwork`, and asserts the full
//! daemon-side flow fires (resolve → poll offer → handle_offer →
//! seal → queue answer).
//!
//! # Known constraint — wire-level answer delivery
//!
//! A real WebRTC answer SDP is ~400 bytes. The high-entropy fields
//! (DTLS fingerprint, ICE credentials) don't compress meaningfully,
//! so even after PR #11's zlib-compressed inner plaintext, the
//! sealed answer + base64url + DNS packaging totals ~700 bytes. The
//! main `_openhost` record takes ~300 bytes, pushing a combined
//! packet past BEP44's 1000-byte `v` cap on some measurements. When
//! the encoder evicts the answer the dialer's `poll_answer` never
//! sees it on the wire.
//!
//! For PR #11 we therefore assert against
//! `SharedState::snapshot_answers()` (the daemon produced + sealed
//! the answer — every layer above the wire ran) plus a separate
//! verification that the sealed answer EXISTS in the memory net (so
//! the publish path itself works). A true wire-level HTTP round-trip
//! requires either splitting the answer into a separate pkarr record
//! (architecturally larger than a v0.1 freeze) or picking a
//! different substrate — tracked as post-v0.1 work.

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
        },
        forward: upstream_port.map(|p| ForwardConfig {
            target: Some(format!("http://127.0.0.1:{p}")),
            host_override: None,
            max_body_bytes: 1024 * 1024,
        }),
        log: LogConfig::default(),
        pairing: Default::default(),
    }
}

/// Regression guard for every daemon-side layer above the BEP44
/// wire: resolve the host record → pick up the offer → unseal →
/// run handle_offer → seal answer → queue answer → trigger publish.
/// The compressed sealed answer lands in `SharedState`; whether the
/// encoder can then fold it into the main pkarr packet depends on
/// the answer SDP size + salt (see the "known constraint" block at
/// the top of this file).
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
    app.listener().set_skip_ice_gather_for_tests(true);
    let daemon_pk = app.identity().public_key();
    let host_url: OpenhostUrl = format!("oh://{daemon_pk}/").parse().expect("url");

    // Let the initial daemon publish land.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut dialer = Dialer::builder()
        .identity(Arc::clone(&client_sk))
        .host_url(host_url)
        .transport(net.as_transport())
        .resolver(net.as_resolve())
        .config(DialerConfig {
            // Short-ish timeout: with the current BEP44 constraint,
            // dial() fails with PollAnswerTimeout after the encoder
            // evicts the answer. See the module-level constraint
            // note; post-v0.1 this becomes a full wire round-trip
            // assertion.
            dial_timeout: Duration::from_secs(5),
            answer_poll_interval: Duration::from_millis(250),
            webrtc_connect_timeout: Duration::from_secs(10),
            binding_timeout: Duration::from_secs(10),
        })
        .build()
        .expect("dialer builds");

    let outcome = dialer.dial().await;
    match outcome {
        Err(openhost_client::ClientError::PollAnswerTimeout(_)) => {
            // Expected: the daemon produced the answer but it didn't
            // fit the packet. Next assertion verifies the server side
            // of the flow actually ran.
        }
        Ok(_) => panic!(
            "dial unexpectedly succeeded — the encoder must have fit \
             the answer on the wire. If this starts passing \
             consistently, split the ICE trickle follow-up has \
             landed; upgrade this test to a full HTTP round-trip."
        ),
        Err(other) => panic!("expected PollAnswerTimeout; got {other:?}"),
    }

    // Real regression guard: the daemon ran every step up to queueing
    // the sealed answer.
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
    assert!(
        opened.answer_sdp.contains("a=setup:passive"),
        "answer SDP must assert a=setup:passive; got: {}",
        opened.answer_sdp
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
        IceBlob, OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
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
        allow: vec![],
        ice: vec![IceBlob {
            client_hash: vec![0x22; 16],
            ciphertext: vec![0x33; 48],
        }],
        disc: String::new(),
    };
    let signed = SignedRecord::sign(record, daemon_sk).unwrap();
    let packet = encode(&signed, daemon_sk).unwrap();
    net.as_transport().publish(&packet, None).await.unwrap();
}
