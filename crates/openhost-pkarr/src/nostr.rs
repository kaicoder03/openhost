//! Optional Nostr tertiary-substrate publishing (envelope construction only).
//!
//! Builds the NIP-78 kind-30078 parameterized-replaceable event that wraps an
//! already-encoded [`pkarr::SignedPacket`] for broadcast over public Nostr
//! relays. The event's `content` field carries `base64(SignedPacket::as_bytes())`
//! so a receiver reconstructs the exact same packet a Pkarr relay would have
//! served.
//!
//! Per `spec/03-pkarr-records.md §2.3`, the host's Ed25519 identity is *not*
//! promoted to a secp256k1 Nostr signing key; this envelope omits the NIP-01
//! `id` and `sig` fields entirely. Strict Nostr relays will reject events
//! without a valid Schnorr signature — that's expected and acceptable for an
//! optional, defense-in-depth substrate. openhost-aware consumers validate the
//! Ed25519 signature inside `content`, not the Nostr outer signature.
//!
//! This module is intentionally publish-only envelope construction. Actually
//! sending the event over a WebSocket is left to M3 and to external Nostr
//! client crates.

use crate::codec;
use crate::error::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::SignedRecord;
use serde_json::{json, Value};

/// NIP-78 parameterized-replaceable event kind used for openhost records.
pub const NOSTR_EVENT_KIND: u64 = 30078;

/// Build the Nostr event JSON envelope wrapping `signed` for broadcast.
///
/// The returned `serde_json::Value` is an object with `kind`, `tags`,
/// `content`, `pubkey`, and `created_at` fields. `id` and `sig` are
/// deliberately omitted — see module docs.
///
/// `signed.record.ts` is used verbatim as `created_at` so the envelope is
/// deterministic for a given signed record; publishers should ensure `ts` is
/// set to the current Unix-seconds time before signing the record (otherwise
/// Nostr relays may reject the event as back- or future-dated).
pub fn build_event(signed: &SignedRecord, signing_key: &SigningKey) -> Result<Value> {
    let packet = codec::encode(signed, signing_key)?;
    let content = STANDARD.encode(packet.as_bytes());
    let pubkey_hex = hex::encode(signing_key.public_key().to_bytes());

    Ok(json!({
        "kind": NOSTR_EVENT_KIND,
        "tags": [
            ["d", format!("openhost:{pubkey_hex}")],
            ["t", "openhost"],
            ["openhost-v", "1"],
        ],
        "content": content,
        "pubkey": pubkey_hex,
        "created_at": signed.record.ts,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::crypto::allowlist_hash;
    use openhost_core::pkarr_record::{
        IceBlob, OpenhostRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn sample_signed() -> (SigningKey, SignedRecord) {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let salt = [0x11u8; SALT_LEN];
        let hash = allowlist_hash(&salt, &[0xAA; 32]);
        let record = OpenhostRecord {
            version: PROTOCOL_VERSION,
            ts: 1_700_000_000,
            dtls_fp: [0x42u8; DTLS_FINGERPRINT_LEN],
            roles: "server".to_string(),
            salt,
            allow: vec![hash],
            ice: vec![IceBlob {
                client_hash: hash.to_vec(),
                ciphertext: vec![0xEE; 72],
            }],
            disc: String::new(),
        };
        let signed = SignedRecord::sign(record, &sk).unwrap();
        (sk, signed)
    }

    #[test]
    fn envelope_has_required_nip78_shape() {
        let (sk, signed) = sample_signed();
        let event = build_event(&signed, &sk).unwrap();

        assert_eq!(event["kind"], NOSTR_EVENT_KIND);
        assert_eq!(event["created_at"], signed.record.ts);

        let expected_pubkey_hex = hex::encode(sk.public_key().to_bytes());
        assert_eq!(event["pubkey"].as_str().unwrap(), expected_pubkey_hex);

        assert!(event.get("id").is_none(), "id must be omitted");
        assert!(event.get("sig").is_none(), "sig must be omitted");

        let tags = event["tags"].as_array().expect("tags array");
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0][0], "d");
        assert_eq!(
            tags[0][1].as_str().unwrap(),
            format!("openhost:{expected_pubkey_hex}")
        );
        assert_eq!(tags[1], json!(["t", "openhost"]));
        assert_eq!(tags[2], json!(["openhost-v", "1"]));
    }

    #[test]
    fn content_decodes_to_a_valid_signed_packet() {
        let (sk, signed) = sample_signed();
        let event = build_event(&signed, &sk).unwrap();
        let blob = STANDARD
            .decode(event["content"].as_str().unwrap())
            .expect("base64 decodes");

        let mut framed = Vec::with_capacity(8 + blob.len());
        framed.extend_from_slice(&[0u8; 8]);
        framed.extend_from_slice(&blob);
        let packet =
            pkarr::SignedPacket::deserialize(&framed).expect("embedded packet deserializes");

        let decoded = codec::decode(&packet).unwrap();
        assert_eq!(decoded.record, signed.record);
        assert_eq!(decoded.signature.to_bytes(), signed.signature.to_bytes());
    }

    #[test]
    fn build_event_is_deterministic_for_same_input() {
        let (sk, signed) = sample_signed();
        let a = build_event(&signed, &sk).unwrap();
        let b = build_event(&signed, &sk).unwrap();
        assert_eq!(a, b);
    }
}
