//! Shared test fixtures for `openhost-pkarr` unit tests.
//!
//! Kept behind `#[cfg(test)]` in `lib.rs` so it never ships in the crate's
//! public surface. Integration tests under `tests/` have their own fixtures
//! driven from the JSON spec vectors.

use openhost_core::crypto::allowlist_hash;
use openhost_core::pkarr_record::{
    IceBlob, OpenhostRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
};

/// RFC 8032 Ed25519 test-vector seed. Reused everywhere we need a
/// deterministic `SigningKey`.
pub(crate) const RFC_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// A minimal-but-valid [`OpenhostRecord`] at the given `ts`.
///
/// Matches the shape used by the pre-existing per-module sample fixtures so
/// tests that previously hand-rolled records keep the same semantics after
/// switching over.
pub(crate) fn sample_record(ts: u64) -> OpenhostRecord {
    let salt = [0x11u8; SALT_LEN];
    let client_pk = [0xAAu8; 32];
    let hash = allowlist_hash(&salt, &client_pk);
    OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts,
        dtls_fp: [0x42u8; DTLS_FINGERPRINT_LEN],
        roles: "server".to_string(),
        salt,
        allow: vec![hash],
        ice: vec![IceBlob {
            client_hash: hash.to_vec(),
            ciphertext: vec![0xEE; 72],
        }],
        disc: String::new(),
    }
}
