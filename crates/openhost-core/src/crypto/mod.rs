//! Cryptographic primitives used by the openhost protocol.
//!
//! - [`sealed_box`] — libsodium-compatible `crypto_box_seal` (X25519 + XSalsa20-Poly1305),
//!   used to encrypt per-client ICE candidate blobs inside Pkarr records.
//! - [`allowlist_hmac`] — HMAC-SHA256 truncated to 16 bytes, used to hash client public
//!   keys in the Pkarr `_allow` record so observers cannot enumerate pairings.
//! - [`channel_binding`] — the RFC 8844-mitigating `auth_bytes` construction derived from
//!   the TLS exporter secret plus both pubkeys and a daemon nonce (spec §8.3 step 9).
//! - [`x25519_from_ed25519`] — convert an Ed25519 identity key to the matching X25519
//!   keypair via the Edwards→Montgomery form, so a single Ed25519 identity suffices for
//!   both signing and sealed-box recipient roles.
//!
//! All types and functions here are deterministic — any randomness comes from an RNG
//! the caller supplies. Test vectors fix both inputs and expected outputs.

pub mod allowlist_hmac;
pub mod channel_binding;
pub mod sealed_box;

pub use allowlist_hmac::{allowlist_hash, ALLOWLIST_HASH_LEN};
pub use channel_binding::{auth_bytes, AUTH_BYTES_LEN, AUTH_CONTEXT_LABEL, AUTH_HKDF_SALT};
pub use sealed_box::{
    open as sealed_box_open, seal as sealed_box_seal, XPublicKey, XSecretKey, XPUBLIC_KEY_LEN,
    XSECRET_KEY_LEN,
};

/// Convert an Ed25519 identity keypair to the matching X25519 keypair via the
/// Edwards-to-Montgomery conversion (libsodium `crypto_sign_ed25519_pk_to_curve25519` /
/// `crypto_sign_ed25519_sk_to_curve25519`).
///
/// This lets an openhost participant hold a single Ed25519 identity and still participate
/// in X25519-based sealed-box exchanges.
pub mod x25519_from_ed25519 {
    use super::{XPublicKey, XSecretKey};
    use crate::{identity, Error, Result};
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use sha2::{Digest, Sha512};
    use zeroize::Zeroize;

    /// Derive the X25519 public key corresponding to an Ed25519 public key.
    ///
    /// Returns `Err(Error::InvalidKey)` only if the Ed25519 point fails to decompress
    /// — which cannot happen for a `PublicKey` obtained via [`identity::PublicKey::from_bytes`],
    /// but the error path is retained for defense in depth.
    pub fn public_key_to_x25519(pk: &identity::PublicKey) -> Result<XPublicKey> {
        let bytes = pk.to_bytes();
        let compressed = CompressedEdwardsY(bytes);
        let edwards = compressed
            .decompress()
            .ok_or(Error::InvalidKey("Ed25519 point does not decompress"))?;
        let montgomery = edwards.to_montgomery();
        Ok(XPublicKey::from_bytes(montgomery.to_bytes()))
    }

    /// Derive the X25519 secret key corresponding to an Ed25519 signing key.
    ///
    /// Mirrors libsodium's `crypto_sign_ed25519_sk_to_curve25519`: SHA-512 of the 32-byte
    /// Ed25519 seed, take the first 32 bytes, then apply the X25519 clamping (clear bits
    /// 0, 1, 2 of the first byte; clear bit 7 and set bit 6 of the last byte).
    pub fn signing_key_to_x25519(sk: &identity::SigningKey) -> XSecretKey {
        let mut seed = sk.to_bytes();
        let hash: [u8; 64] = Sha512::digest(seed).into();
        let mut clamped = [0u8; 32];
        clamped.copy_from_slice(&hash[..32]);
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;

        // Zeroize scratch buffers before returning.
        let out = XSecretKey::from_bytes(&clamped);
        seed.zeroize();
        let mut hash_copy = hash;
        hash_copy.zeroize();
        clamped.zeroize();
        out
    }
}

pub use x25519_from_ed25519::{public_key_to_x25519, signing_key_to_x25519};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::SigningKey;

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[test]
    fn identity_to_x25519_pair_roundtrips_sealed_box() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let x_sk = signing_key_to_x25519(&sk);
        let x_pk_from_sk = x_sk.public_key();
        let x_pk_from_pk = public_key_to_x25519(&sk.public_key()).expect("Ed25519 pubkey converts");

        // The two derivations must agree.
        assert_eq!(x_pk_from_sk.to_bytes(), x_pk_from_pk.to_bytes());

        // And the resulting keypair must work with sealed box.
        let mut rng = rand::rngs::OsRng;
        let ct = sealed_box_seal(&mut rng, &x_pk_from_pk, b"hello openhost");
        let pt = sealed_box_open(&x_sk, &ct).expect("unseal succeeds");
        assert_eq!(pt, b"hello openhost");
    }
}
