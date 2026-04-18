//! Integration test: `Client::resolve_url` against a fake resolver that
//! replays the canonical `spec/test-vectors/pkarr_packet.json` fixture.
//!
//! This is the cross-implementation conformance gate for the client side:
//! any `SignedPacket` produced by a spec-conformant publisher MUST be
//! resolvable by this client.

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

fn load_vector_packet() -> (SigningKey, SignedPacket) {
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
    (sk, packet)
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

#[tokio::test(start_paused = true)]
async fn client_resolves_reference_fixture() {
    let (sk, packet) = load_vector_packet();

    // The fixture's record.ts is baked into the vector; `Resolver` rejects
    // records older than the 2-hour freshness window. To keep this test
    // deterministic against the system clock, we check with the fixture's
    // own ts rather than the system's ts. That means building the client
    // via `build_with_resolve` and using a *custom* resolver that passes
    // fixture_ts to verify — but our Client::resolve only uses the system
    // clock. Workaround: rebuild the packet with a fresh ts drawn from
    // now_ts() so the validator's freshness check passes. The outer
    // pkarr timestamp is re-signed below.
    //
    // For a strict fixture-bytes cross-check, see
    // `crates/openhost-pkarr/tests/round_trip.rs`.
    let ts = now_ts();
    let record = openhost_core::pkarr_record::OpenhostRecord {
        ts,
        ..decode_fixture_record(&packet)
    };
    let signed = openhost_core::pkarr_record::SignedRecord::sign(record, &sk).expect("resign");
    let packet = openhost_pkarr::encode(&signed, &sk).expect("re-encode");

    let client = Client::builder()
        .grace_window(Duration::ZERO)
        .build_with_resolve(Arc::new(FixtureResolve::new(packet)));

    let pk_zbase = sk.public_key().to_zbase32();
    let result = client
        .resolve_url(&format!("oh://{pk_zbase}/"), None)
        .await
        .expect("resolves fixture");

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
    // Build the client with a fake that would succeed if asked — we just
    // verify that URL parsing fails before any substrate is queried.
    let client = Client::builder()
        .grace_window(Duration::ZERO)
        .build_with_resolve(Arc::new(FixtureResolve::new(load_vector_packet().1)));

    let err = client
        .resolve_url("not-a-real-url", None)
        .await
        .expect_err("malformed URL must fail");
    assert!(
        format!("{err}").contains("invalid openhost URL"),
        "unexpected error: {err}"
    );
}
