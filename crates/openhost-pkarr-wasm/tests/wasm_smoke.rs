//! Host-target smoke tests for the `openhost-pkarr-wasm` shim (PR #28.2).
//!
//! These tests exercise the `core` tier directly — the `#[wasm_bindgen]`
//! wrappers at crate root can only run inside a wasm runtime. The goal
//! is "does every decode wrapper return byte-identical data to what the
//! CLI dialer would see" so any future change to the underlying
//! openhost-pkarr decode path is caught here first.

use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{
    OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
};
use openhost_pkarr::{encode, encode_with_answers, AnswerEntry, AnswerPlaintext};
use openhost_pkarr_wasm::core;

const SEED: [u8; 32] = [0x42; 32];
const CLIENT_SEED: [u8; 32] = [0x33; 32];

fn sample_signed_record(ts: u64) -> (SigningKey, SignedRecord) {
    let sk = SigningKey::from_bytes(&SEED);
    let record = OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts,
        dtls_fp: [0x11; DTLS_FINGERPRINT_LEN],
        roles: "server".to_string(),
        salt: [0x22; SALT_LEN],
        disc: String::new(),
    };
    let signed = SignedRecord::sign(record, &sk).unwrap();
    (sk, signed)
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn decode_host_record_returns_fields_matching_the_source() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.serialize();

    let pk_z = sk.public_key().to_zbase32();
    let dto = core::decode_host_record(&bytes, &pk_z, ts).expect("decode succeeds");

    assert_eq!(dto.pubkey_zbase32, pk_z);
    assert_eq!(dto.version, PROTOCOL_VERSION);
    assert_eq!(dto.ts, ts);
    assert_eq!(dto.roles, "server");
    assert_eq!(dto.disc, "");
    assert_eq!(dto.dtls_fingerprint_hex, hex::encode([0x11u8; 32]));
    assert_eq!(dto.salt_hex, hex::encode([0x22u8; 32]));
    assert_eq!(dto.signature_hex.len(), 128);
}

#[test]
fn decode_host_record_rejects_invalid_pubkey() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.serialize();

    let err = core::decode_host_record(&bytes, "not-a-real-pubkey", ts).expect_err("must reject");
    let s = err.to_string();
    assert!(
        s.contains("zbase32"),
        "error message should mention zbase32, got: {s}"
    );
}

#[test]
fn verify_record_accepts_good_signature_rejects_tampered() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.serialize();

    let pk_z = sk.public_key().to_zbase32();
    let ok = core::verify_record(&bytes, &pk_z, ts).expect("verify runs");
    assert!(ok, "good packet must verify");

    // Verify against a *different* pubkey — the inner Ed25519 sig is
    // over canonical bytes signed by `sk`, so verification against
    // anyone else's pubkey must fail.
    let other_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let wrong_pk_z = other_sk.public_key().to_zbase32();
    let bad = core::verify_record(&bytes, &wrong_pk_z, ts).expect("verify runs for wrong pk");
    assert!(!bad, "wrong-pubkey verify must return false");
}

#[test]
fn decode_offer_returns_none_when_no_offer_txt_is_published() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.serialize();

    let daemon_pk_z = sk.public_key().to_zbase32();
    let out = core::decode_offer(&bytes, &daemon_pk_z).expect("runs");
    assert!(out.is_none());
}

#[test]
fn decode_answer_fragments_returns_none_when_no_fragments_are_published() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode_with_answers(&signed, &sk, &[]).unwrap();
    let bytes = packet.serialize();

    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let salt = [0x22u8; SALT_LEN];
    let client_pk_z = client_sk.public_key().to_zbase32();
    let out = core::decode_answer_fragments(&bytes, &salt, &client_pk_z).expect("runs");
    assert!(out.is_none());
}

#[test]
fn decode_answer_fragments_reassembles_published_fragments() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);

    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let client_pk = client_sk.public_key();
    let salt = [0x22u8; SALT_LEN];

    let plaintext = AnswerPlaintext {
        daemon_pk: sk.public_key(),
        offer_sdp_hash: openhost_pkarr::hash_offer_sdp("v=0\r\n"),
        answer_sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n".to_string(),
    };
    let mut rng = rand::rngs::OsRng;
    let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, ts).unwrap();
    let expected_sealed = entry.sealed.clone();
    let expected_hash_hex = hex::encode(entry.client_hash);

    let packet = encode_with_answers(&signed, &sk, std::slice::from_ref(&entry)).expect("encode");
    let bytes = packet.serialize();

    let client_pk_z = client_pk.to_zbase32();
    let out = core::decode_answer_fragments(&bytes, &salt, &client_pk_z).expect("runs");
    let dto = out.expect("fragments present");
    assert_eq!(dto.client_hash_hex, expected_hash_hex);

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let sealed_back = URL_SAFE_NO_PAD
        .decode(dto.sealed_base64url.as_bytes())
        .expect("base64url decodes");
    assert_eq!(sealed_back, expected_sealed);

    // Sanity: the reassembled ciphertext is actually openable by the
    // client identity — the shim preserved every byte, not just the
    // length.
    let rebuilt = AnswerEntry {
        client_hash: entry.client_hash,
        sealed: sealed_back,
        created_at: entry.created_at,
    };
    let opened = rebuilt.open(&client_sk).expect("sealed bytes open");
    assert_eq!(opened.answer_sdp, plaintext.answer_sdp);
}
