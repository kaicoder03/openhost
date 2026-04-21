//! Consume `spec/test-vectors/pkarr_record.json` and verify canonical bytes and
//! the signature match the implementation bit-for-bit.
//!
//! The v2 schema drops `allow` and `ice` from the record; this test
//! enforces the new canonical layout.

use ed25519_dalek::Signature;
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_core::pkarr_record::{OpenhostRecord, SignedRecord};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    signing_seed_hex: String,
    public_key_hex: String,
    record: RecordFields,
    canonical_len: usize,
    canonical_hex: String,
    signature_hex: String,
}

#[derive(Debug, Deserialize)]
struct RecordFields {
    version: u8,
    ts: u64,
    dtls_fp_hex: String,
    roles: String,
    salt_hex: String,
    disc: String,
    #[serde(default)]
    turn_port: Option<u16>,
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).expect("hex");
    v.as_slice().try_into().expect("32 bytes")
}

fn build_record(r: &RecordFields) -> OpenhostRecord {
    OpenhostRecord {
        version: r.version,
        ts: r.ts,
        dtls_fp: decode_hex32(&r.dtls_fp_hex),
        roles: r.roles.clone(),
        salt: decode_hex32(&r.salt_hex),
        disc: r.disc.clone(),
        turn_port: r.turn_port,
    }
}

fn load() -> VectorFile {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/pkarr_record.json");
    let raw = std::fs::read_to_string(&path).expect("read pkarr_record.json");
    serde_json::from_str(&raw).expect("parse pkarr_record.json")
}

#[test]
fn canonical_bytes_and_signature_match() {
    for v in load().vectors {
        let seed = decode_hex32(&v.signing_seed_hex);
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(
            hex::encode(sk.public_key().to_bytes()),
            v.public_key_hex,
            "{}: public key derivation",
            v.name,
        );

        let record = build_record(&v.record);
        let canonical = record.canonical_signing_bytes().expect("canonical ok");
        assert_eq!(
            canonical.len(),
            v.canonical_len,
            "{}: canonical_len (got {:?})",
            v.name,
            hex::encode(&canonical),
        );
        assert_eq!(
            hex::encode(&canonical),
            v.canonical_hex,
            "{}: canonical_hex",
            v.name,
        );

        let signed = SignedRecord::sign(record.clone(), &sk).unwrap();
        assert_eq!(
            hex::encode(signed.signature.to_bytes()),
            v.signature_hex,
            "{}: signature_hex",
            v.name,
        );

        let expected_sig_bytes = hex::decode(&v.signature_hex).expect("sig hex");
        let parsed_sig = Signature::from_slice(&expected_sig_bytes).expect("sig parse");
        let pk = PublicKey::from_bytes(&decode_hex32(&v.public_key_hex)).expect("pk");
        let reconstructed = SignedRecord {
            record,
            signature: parsed_sig,
        };
        reconstructed
            .verify(&pk, v.record.ts)
            .expect("independent verification succeeds");
    }
}
