//! Round-trip integration test against `spec/test-vectors/pkarr_packet.json`.
//!
//! A second implementation MUST be able to:
//!   1. Deserialize `packet_bytes_hex` back into its own `SignedPacket` type.
//!   2. Decode that into an openhost `SignedRecord`.
//!   3. Verify the inner Ed25519 signature against the referenced public key
//!      (at the record's own `ts` — we don't advance "now" here).
//!   4. Re-encode with the original signing key and produce the same
//!      `packet_bytes_hex` byte-for-byte.
//!
//! If any of the above breaks, the bridge has drifted from the spec.

use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{IceBlob, OpenhostRecord, SignedRecord};
use openhost_pkarr::{codec, decode, encode};
use pkarr::SignedPacket;
use serde_json::Value;
use std::fs;

const VECTOR_PATH: &str = "../../spec/test-vectors/pkarr_packet.json";

fn load_vectors() -> Value {
    let raw = fs::read_to_string(VECTOR_PATH).expect("read pkarr_packet.json");
    serde_json::from_str(&raw).expect("parse pkarr_packet.json")
}

fn reference_record() -> OpenhostRecord {
    let raw = fs::read_to_string("../../spec/test-vectors/pkarr_record.json")
        .expect("read pkarr_record.json");
    let v: Value = serde_json::from_str(&raw).unwrap();
    let r = &v["vectors"][0]["record"];

    let mut dtls_fp = [0u8; 32];
    dtls_fp.copy_from_slice(&hex::decode(r["dtls_fp_hex"].as_str().unwrap()).unwrap());

    let mut salt = [0u8; 32];
    salt.copy_from_slice(&hex::decode(r["salt_hex"].as_str().unwrap()).unwrap());

    let allow: Vec<[u8; 16]> = r["allow_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            let b = hex::decode(h.as_str().unwrap()).unwrap();
            let mut a = [0u8; 16];
            a.copy_from_slice(&b);
            a
        })
        .collect();

    let ice: Vec<IceBlob> = r["ice"]
        .as_array()
        .unwrap()
        .iter()
        .map(|blob| IceBlob {
            client_hash: hex::decode(blob["client_hash_hex"].as_str().unwrap()).unwrap(),
            ciphertext: hex::decode(blob["ciphertext_hex"].as_str().unwrap()).unwrap(),
        })
        .collect();

    OpenhostRecord {
        version: r["version"].as_u64().unwrap() as u8,
        ts: r["ts"].as_u64().unwrap(),
        dtls_fp,
        roles: r["roles"].as_str().unwrap().to_string(),
        salt,
        allow,
        ice,
        disc: r["disc"].as_str().unwrap().to_string(),
    }
}

fn deserialize_packet_bytes(as_bytes: &[u8]) -> SignedPacket {
    // `SignedPacket::deserialize` expects `<8 bytes last_seen><as_bytes>`.
    // We zero the `last_seen` prefix — it's a local cache hint and is not part
    // of the canonical wire form.
    let mut framed = Vec::with_capacity(8 + as_bytes.len());
    framed.extend_from_slice(&[0u8; 8]);
    framed.extend_from_slice(as_bytes);
    SignedPacket::deserialize(&framed).expect("valid signed packet bytes")
}

#[test]
fn reference_packet_round_trips() {
    let vectors = load_vectors();
    let v = &vectors["vectors"][0];

    let seed_hex = v["signing_seed_hex"].as_str().unwrap();
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let sk = SigningKey::from_bytes(&seed);

    let as_bytes = hex::decode(v["packet_bytes_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        as_bytes.len(),
        v["packet_bytes_len"].as_u64().unwrap() as usize
    );

    let packet = deserialize_packet_bytes(&as_bytes);

    let decoded = decode(&packet).expect("decode");
    assert_eq!(decoded.record, reference_record());

    decoded
        .verify(&sk.public_key(), decoded.record.ts)
        .expect("openhost signature verifies");

    // Re-encode and assert we get byte-identical output.
    let signed = SignedRecord::sign(decoded.record.clone(), &sk).unwrap();
    let re_encoded = encode(&signed, &sk).expect("re-encode");
    assert_eq!(
        hex::encode(re_encoded.as_bytes()),
        v["packet_bytes_hex"].as_str().unwrap(),
        "re-encoded packet must match fixture byte-for-byte"
    );
}

#[test]
fn fixture_declares_expected_blob_shape() {
    let vectors = load_vectors();
    let v = &vectors["vectors"][0];

    assert_eq!(
        v["openhost_txt_name"].as_str().unwrap(),
        codec::OPENHOST_TXT_NAME
    );
    assert_eq!(
        v["openhost_txt_ttl"].as_u64().unwrap() as u32,
        codec::OPENHOST_TXT_TTL
    );
    assert_eq!(
        v["pkarr_timestamp_micros"].as_u64().unwrap(),
        v["record_ts"].as_u64().unwrap() * codec::MICROS_PER_SECOND
    );
}

#[test]
fn tampering_canonical_bytes_fails_openhost_sig() {
    let vectors = load_vectors();
    let v = &vectors["vectors"][0];

    let seed_hex = v["signing_seed_hex"].as_str().unwrap();
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let sk = SigningKey::from_bytes(&seed);

    let as_bytes = hex::decode(v["packet_bytes_hex"].as_str().unwrap()).unwrap();
    let packet = deserialize_packet_bytes(&as_bytes);
    let mut decoded = decode(&packet).unwrap();
    decoded.record.dtls_fp[0] ^= 0x01;

    assert!(decoded.verify(&sk.public_key(), decoded.record.ts).is_err());
}
