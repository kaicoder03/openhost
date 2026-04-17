//! Consume `spec/test-vectors/identity.json` and verify every vector still matches
//! the implementation. Any drift between spec and code fails the build.

use ed25519_dalek::Signature;
use openhost_core::identity::{OpenhostUrl, PublicKey, SigningKey};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    vectors: Vec<Vector>,
    negative_vectors: Vec<NegativeVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Vector {
    name: String,
    #[serde(default)]
    signing_seed_hex: Option<String>,
    #[serde(default)]
    public_key_hex: Option<String>,
    public_key_zbase32: String,
    #[serde(default)]
    message_hex: Option<String>,
    #[serde(default)]
    signature_hex: Option<String>,
    #[serde(default)]
    url_input: Option<String>,
    #[serde(default)]
    url_normalized: Option<String>,
    #[serde(default)]
    expected_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NegativeVector {
    name: String,
    #[serde(default)]
    public_key_zbase32: Option<String>,
    #[serde(default)]
    url_input: Option<String>,
}

fn load() -> VectorFile {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/identity.json");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&raw).expect("identity.json parses")
}

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn all_positive_vectors_agree_with_implementation() {
    for v in load().vectors {
        // Signing / public-key derivation consistency
        if let (Some(seed_hex), Some(pk_hex)) = (&v.signing_seed_hex, &v.public_key_hex) {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&decode_hex(seed_hex));
            let sk = SigningKey::from_bytes(&seed);
            let pk = sk.public_key();
            assert_eq!(
                hex::encode(pk.to_bytes()),
                pk_hex.as_str(),
                "{}: public_key_hex mismatch",
                v.name,
            );
            assert_eq!(
                pk.to_zbase32(),
                v.public_key_zbase32,
                "{}: public_key_zbase32 mismatch",
                v.name,
            );

            // Signing roundtrip — message_hex may be empty.
            if let (Some(msg_hex), Some(sig_hex)) = (&v.message_hex, &v.signature_hex) {
                let msg = decode_hex(msg_hex);
                let expected_sig = decode_hex(sig_hex);
                let sig = sk.sign(&msg);
                assert_eq!(
                    sig.to_bytes().as_slice(),
                    expected_sig.as_slice(),
                    "{}: signature bytes diverge from RFC 8032 vector",
                    v.name,
                );
                let parsed_sig = Signature::from_slice(&expected_sig).expect("valid sig bytes");
                pk.verify(&msg, &parsed_sig)
                    .unwrap_or_else(|e| panic!("{}: verify failed: {e}", v.name));
            }
        }

        // Pure z-base-32 parsing consistency
        let pk = PublicKey::from_zbase32(&v.public_key_zbase32)
            .unwrap_or_else(|e| panic!("{}: parse zbase32: {e}", v.name));
        assert_eq!(pk.to_zbase32(), v.public_key_zbase32);

        // URL parse + normalize
        if let (Some(url_in), Some(url_norm), Some(expected_path)) =
            (&v.url_input, &v.url_normalized, &v.expected_path)
        {
            let parsed = OpenhostUrl::parse(url_in)
                .unwrap_or_else(|e| panic!("{}: url parse failed: {e}", v.name));
            assert_eq!(parsed.path, *expected_path, "{}: path mismatch", v.name);
            assert_eq!(
                parsed.to_string(),
                *url_norm,
                "{}: normalized URL mismatch",
                v.name,
            );
        }
    }
}

#[test]
fn all_negative_vectors_are_rejected() {
    for v in load().negative_vectors {
        if let Some(z) = &v.public_key_zbase32 {
            assert!(
                PublicKey::from_zbase32(z).is_err(),
                "{}: expected rejection but parse succeeded",
                v.name,
            );
        }
        if let Some(u) = &v.url_input {
            assert!(
                OpenhostUrl::parse(u).is_err(),
                "{}: expected rejection but parse succeeded",
                v.name,
            );
        }
    }
}
