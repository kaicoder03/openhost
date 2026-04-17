//! HMAC-SHA256 truncated to 16 bytes — the allowlist hash per spec §2.
//!
//! A host publishes `_allow` entries as the HMAC-SHA256 of a paired client's 32-byte
//! Ed25519 public key, keyed by a daemon-local random salt that is itself published
//! (in plaintext) within the `@` record. The salt rotates when the daemon rotates its
//! DTLS certificate, so previously-observed hashes do not link sessions together.
//!
//! Truncating to 16 bytes reflects the collision budget (2^64 for HMAC, far more than
//! is practical) while keeping the signed record small.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Length, in bytes, of one allowlist hash entry.
pub const ALLOWLIST_HASH_LEN: usize = 16;

/// Compute the allowlist hash for a client public key under a given salt.
///
/// Panics only on an internal HMAC key-length error, which cannot occur here
/// because HMAC-SHA256 accepts arbitrary-length keys.
#[must_use]
pub fn allowlist_hash(salt: &[u8], client_public_key: &[u8; 32]) -> [u8; ALLOWLIST_HASH_LEN] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(salt).expect("HMAC-SHA256 accepts any key length");
    mac.update(client_public_key);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; ALLOWLIST_HASH_LEN];
    out.copy_from_slice(&full[..ALLOWLIST_HASH_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_inputs() {
        let salt = b"openhost-salt-v1";
        let pk = [0xABu8; 32];
        let a = allowlist_hash(salt, &pk);
        let b = allowlist_hash(salt, &pk);
        assert_eq!(a, b);
    }

    #[test]
    fn different_salts_produce_different_hashes() {
        let pk = [0xCDu8; 32];
        let a = allowlist_hash(b"salt-a", &pk);
        let b = allowlist_hash(b"salt-b", &pk);
        assert_ne!(a, b);
    }

    #[test]
    fn different_pubkeys_produce_different_hashes() {
        let salt = b"openhost-salt-v1";
        let a = allowlist_hash(salt, &[0x00u8; 32]);
        let b = allowlist_hash(salt, &[0xFFu8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn empty_salt_still_works() {
        let pk = [0x42u8; 32];
        let a = allowlist_hash(&[], &pk);
        let b = allowlist_hash(&[], &pk);
        assert_eq!(a, b);
    }
}
