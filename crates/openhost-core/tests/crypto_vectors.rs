//! Consume `spec/test-vectors/crypto.json` and verify every vector matches the
//! implementation bit-for-bit.

use openhost_core::crypto::{
    allowlist_hash, auth_bytes, public_key_to_x25519, sealed_box_open, sealed_box_seal,
    signing_key_to_x25519,
};
use openhost_core::identity::SigningKey;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    allowlist_hmac: Vec<AllowlistVector>,
    channel_binding: Vec<ChannelBindingVector>,
    x25519_from_ed25519: Vec<X25519Vector>,
}

#[derive(Debug, Deserialize)]
struct AllowlistVector {
    name: String,
    #[serde(default)]
    salt_hex: Option<String>,
    #[serde(default)]
    salt_ascii: Option<String>,
    pubkey_hex: String,
    hash_hex: String,
}

#[derive(Debug, Deserialize)]
struct ChannelBindingVector {
    name: String,
    tls_exporter_secret_hex: String,
    auth_bytes_hex: String,
}

#[derive(Debug, Deserialize)]
struct X25519Vector {
    name: String,
    ed25519_seed_hex: String,
}

fn load() -> VectorFile {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/crypto.json");
    let raw = std::fs::read_to_string(&path).expect("read crypto.json");
    serde_json::from_str(&raw).expect("parse crypto.json")
}

fn salt_bytes(v: &AllowlistVector) -> Vec<u8> {
    if let Some(h) = &v.salt_hex {
        hex::decode(h).expect("salt hex")
    } else if let Some(a) = &v.salt_ascii {
        a.as_bytes().to_vec()
    } else {
        panic!("vector {:?} has neither salt_hex nor salt_ascii", v.name);
    }
}

#[test]
fn allowlist_hmac_vectors() {
    for v in load().allowlist_hmac {
        let salt = salt_bytes(&v);
        let pk_bytes = hex::decode(&v.pubkey_hex).expect("pubkey hex");
        let pk: [u8; 32] = pk_bytes.as_slice().try_into().expect("32 bytes");
        let hash = allowlist_hash(&salt, &pk);
        assert_eq!(
            hex::encode(hash),
            v.hash_hex,
            "{}: allowlist_hash mismatch",
            v.name,
        );
    }
}

#[test]
fn channel_binding_vectors() {
    for v in load().channel_binding {
        let secret = hex::decode(&v.tls_exporter_secret_hex).expect("secret hex");
        let ab = auth_bytes(&secret).expect("valid length");
        assert_eq!(
            hex::encode(ab),
            v.auth_bytes_hex,
            "{}: auth_bytes mismatch",
            v.name,
        );
    }
}

#[test]
fn x25519_from_ed25519_vectors() {
    for v in load().x25519_from_ed25519 {
        let seed_bytes = hex::decode(&v.ed25519_seed_hex).expect("seed hex");
        let seed: [u8; 32] = seed_bytes.as_slice().try_into().expect("32 bytes");
        let sk = SigningKey::from_bytes(&seed);
        let pk = sk.public_key();

        let x_sk = signing_key_to_x25519(&sk);
        let x_pk_from_pk = public_key_to_x25519(&pk).expect("Ed pk converts");

        assert_eq!(
            x_sk.public_key().to_bytes(),
            x_pk_from_pk.to_bytes(),
            "{}: public-key-derivation consistency failed",
            v.name,
        );

        // Sealed-box roundtrip at a range of plaintext lengths.
        let mut rng = rand::rngs::OsRng;
        for plaintext in [b"".as_slice(), b"short".as_slice(), &vec![0xA5; 600]] {
            let ct = sealed_box_seal(&mut rng, &x_pk_from_pk, plaintext);
            let pt = sealed_box_open(&x_sk, &ct).expect("unseal");
            assert_eq!(pt, plaintext, "{}: sealed-box roundtrip failed", v.name);
        }
    }
}
