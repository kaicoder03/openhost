//! Integration tests for `Client::resolve_url` against the canonical
//! `spec/test-vectors/pkarr_packet.json` fixture.
//!
//! Two distinct checks:
//!
//! 1. **Byte-level conformance gate** — decode the fixture's
//!    `packet_bytes_hex` through `Client` with the fixture's baked `ts`
//!    injected via [`ClientBuilder::now_fn`]. If this test ever fails,
//!    the client crate has drifted from the spec wire format.
//! 2. **Resigned round-trip** — re-sign the fixture's record with a
//!    fresh `ts = now()` and drive it through the client. Proves the
//!    end-to-end sign → encode → decode → validate path works with the
//!    system clock, independently of fixture freshness.

use async_trait::async_trait;
use openhost_client::Client;
use openhost_core::identity::SigningKey;
use openhost_pkarr::Resolve;
use pkarr::SignedPacket;
use serde_json::Value;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const VECTOR_PATH: &str = "../../spec/test-vectors/pkarr_packet.json";

fn load_vector_packet() -> (SigningKey, SignedPacket, u64) {
    let raw = fs::read_to_string(VECTOR_PATH).expect("read pkarr_packet.json");
    let v: Value = serde_json::from_str(&raw).unwrap();
    let vec = &v["vectors"][0];

    let seed_hex = vec["signing_seed_hex"].as_str().unwrap();
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let sk = SigningKey::from_bytes(&seed);

    let as_bytes = hex::decode(vec["packet_bytes_hex"].as_str().unwrap()).unwrap();
    // `SignedPacket::deserialize` expects `<8 bytes last_seen><as_bytes>`.
    let mut framed = Vec::with_capacity(8 + as_bytes.len());
    framed.extend_from_slice(&[0u8; 8]);
    framed.extend_from_slice(&as_bytes);

    let packet = SignedPacket::deserialize(&framed).expect("fixture deserializes");
    let fixture_ts = vec["record_ts"].as_u64().unwrap();

    (sk, packet, fixture_ts)
}

struct FixtureResolve {
    packet: std::sync::Mutex<Option<SignedPacket>>,
}

impl FixtureResolve {
    fn new(packet: SignedPacket) -> Self {
        Self {
            packet: std::sync::Mutex::new(Some(packet)),
        }
    }
}

#[async_trait]
impl Resolve for FixtureResolve {
    async fn resolve_most_recent(&self, _pk: &pkarr::PublicKey) -> Option<SignedPacket> {
        self.packet
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| SignedPacket::deserialize(&p.serialize()).unwrap())
    }
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Byte-level conformance gate: feed the *exact fixture packet bytes* to
/// `Client::resolve_url` with the fixture's baked `ts` injected as the
/// clock. Verifies that the wire-format bytes defined in `pkarr_packet.json`
/// decode through the client path without mutation.
#[tokio::test(start_paused = true)]
async fn client_decodes_fixture_bytes_directly() {
    let (sk, packet, fixture_ts) = load_vector_packet();

    let client = Client::builder()
        .grace_window(Duration::ZERO)
        .now_fn(move || fixture_ts)
        .build_with_resolve(Arc::new(FixtureResolve::new(packet)));

    let pk_zbase = sk.public_key().to_zbase32();
    let record = client
        .resolve_url(&format!("oh://{pk_zbase}/"), None)
        .await
        .expect("fixture bytes resolve through Client");

    // Spot-check fields from the fixture so a regression in the decoder
    // or the validator is immediately diagnosable. The v2 record dropped
    // `allow` and `ice` from the canonical bytes (PR #22) — those fields
    // are no longer on the wire.
    assert_eq!(record.record.ts, fixture_ts);
    assert_eq!(record.record.version, 2);
    assert_eq!(record.record.roles, "server");
    assert_eq!(record.record.disc, "dht=1; relay=pkarr.example");
}

/// Round-trip the fixture's record through sign → encode → Client against
/// a fresh `ts`. Exercises the full pipeline independently of fixture
/// freshness; catches regressions in re-signing that the static-bytes
/// test above would miss.
#[tokio::test(start_paused = true)]
async fn client_resolves_a_resigned_fixture_record() {
    let (sk, packet, _fixture_ts) = load_vector_packet();

    let ts = now_ts();
    let fresh_record = openhost_core::pkarr_record::OpenhostRecord {
        ts,
        ..decode_fixture_record(&packet)
    };
    let signed =
        openhost_core::pkarr_record::SignedRecord::sign(fresh_record, &sk).expect("resign");
    let resigned_packet = openhost_pkarr::encode(&signed, &sk).expect("re-encode");

    let client = Client::builder()
        .grace_window(Duration::ZERO)
        .build_with_resolve(Arc::new(FixtureResolve::new(resigned_packet)));

    let pk_zbase = sk.public_key().to_zbase32();
    let result = client
        .resolve_url(&format!("oh://{pk_zbase}/"), None)
        .await
        .expect("resolves resigned record");

    assert_eq!(result.record.roles, "server");
    assert_eq!(result.record.ts, ts);
}

fn decode_fixture_record(packet: &SignedPacket) -> openhost_core::pkarr_record::OpenhostRecord {
    openhost_pkarr::decode(packet)
        .expect("fixture decodes")
        .record
}

#[tokio::test(start_paused = true)]
async fn client_rejects_malformed_url() {
    let client = Client::builder()
        .grace_window(Duration::ZERO)
        .build_with_resolve(Arc::new(FixtureResolve::new(load_vector_packet().1)));

    let err = client
        .resolve_url("not-a-real-url", None)
        .await
        .expect_err("malformed URL must fail");
    // ClientError::UrlParse is `#[error(transparent)]` so the Display is
    // the inner CoreError's message ("missing oh:// scheme" or similar).
    assert!(
        matches!(err, openhost_client::ClientError::UrlParse(_)),
        "expected UrlParse variant, got: {err}"
    );
}
