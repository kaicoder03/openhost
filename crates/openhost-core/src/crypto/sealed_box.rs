//! libsodium-compatible sealed-box encryption (X25519 + XSalsa20-Poly1305).
//!
//! The wire format is:
//!
//! ```text
//! sealed_box_output = ephemeral_x25519_pk (32 bytes)
//!                     || XSalsa20-Poly1305_encrypt(
//!                            key   = Salsa20 KDF of X25519(ephemeral_sk, recipient_pk),
//!                            nonce = Blake2b-24(ephemeral_pk || recipient_pk),
//!                            plaintext)
//! ```
//!
//! Matches libsodium's `crypto_box_seal` byte-for-byte. Implementations in other
//! languages that use libsodium, NaCl, or any `crypto_box`-compatible library
//! interoperate directly.

use crate::{Error, Result};
use rand_core::CryptoRngCore;

/// Length of an X25519 public key in bytes.
pub const XPUBLIC_KEY_LEN: usize = 32;

/// Length of an X25519 secret key in bytes.
pub const XSECRET_KEY_LEN: usize = 32;

/// Extra bytes prepended to the plaintext when sealed: the ephemeral public key plus
/// the Poly1305 authentication tag. `sealed.len() == plaintext.len() + SEAL_OVERHEAD`.
pub const SEAL_OVERHEAD: usize = 32 + 16;

/// An X25519 public key used as a sealed-box recipient.
#[derive(Clone, PartialEq, Eq)]
pub struct XPublicKey(crypto_box::PublicKey);

impl XPublicKey {
    /// Construct from raw 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; XPUBLIC_KEY_LEN]) -> Self {
        Self(crypto_box::PublicKey::from(bytes))
    }

    /// Raw 32 bytes of the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XPUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    pub(crate) fn as_dalek(&self) -> &crypto_box::PublicKey {
        &self.0
    }
}

impl core::fmt::Debug for XPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "XPublicKey({})", hex::encode(self.to_bytes()))
    }
}

/// An X25519 secret key used to open sealed-box ciphertext.
///
/// Zeroized on drop (via the inner `crypto_box::SecretKey`'s own `Drop` impl).
/// Does not implement `Clone` / `Serialize`.
pub struct XSecretKey(crypto_box::SecretKey);

impl XSecretKey {
    /// Construct from raw 32 bytes. The bytes are **not** clamped by this constructor;
    /// callers are expected to have clamped if their source required it (e.g.,
    /// [`super::x25519_from_ed25519::signing_key_to_x25519`] handles clamping already).
    #[must_use]
    pub fn from_bytes(bytes: &[u8; XSECRET_KEY_LEN]) -> Self {
        Self(crypto_box::SecretKey::from(*bytes))
    }

    /// Generate a fresh random secret key from the supplied CSPRNG.
    #[must_use]
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self(crypto_box::SecretKey::generate(rng))
    }

    /// Raw 32 bytes of the secret key. Caller is responsible for zeroizing the copy.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; XSECRET_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn public_key(&self) -> XPublicKey {
        XPublicKey(self.0.public_key())
    }

    pub(crate) fn as_dalek(&self) -> &crypto_box::SecretKey {
        &self.0
    }
}

impl core::fmt::Debug for XSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XSecretKey(<redacted>)")
    }
}

/// Seal `plaintext` to `recipient`.
///
/// Uses the provided CSPRNG to generate an ephemeral sender keypair. The resulting
/// ciphertext is self-contained: the recipient needs only their own secret key
/// to open it.
pub fn seal<R: CryptoRngCore>(rng: &mut R, recipient: &XPublicKey, plaintext: &[u8]) -> Vec<u8> {
    // crypto_box::PublicKey::seal cannot fail in the current implementation — the
    // aead::Error path is only reached by constructions that require additional
    // associated data, which sealed boxes do not permit.
    recipient
        .as_dalek()
        .seal(rng, plaintext)
        .expect("crypto_box_seal must not fail with empty AAD")
}

/// Open a sealed-box ciphertext addressed to `recipient`.
///
/// Returns [`Error::DecryptionFailed`] on any parse or authentication failure,
/// including wrong recipient, tampered ciphertext, or truncated input.
pub fn open(recipient: &XSecretKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    recipient
        .as_dalek()
        .unseal(ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_short_message() {
        let mut rng = rand::rngs::OsRng;
        let sk = XSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let plaintext = b"hello openhost";
        let ct = seal(&mut rng, &pk, plaintext);
        assert_eq!(ct.len(), plaintext.len() + SEAL_OVERHEAD);
        let pt = open(&sk, &ct).expect("unseal");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn roundtrip_empty_message() {
        let mut rng = rand::rngs::OsRng;
        let sk = XSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let ct = seal(&mut rng, &pk, b"");
        assert_eq!(ct.len(), SEAL_OVERHEAD);
        let pt = open(&sk, &ct).expect("unseal");
        assert!(pt.is_empty());
    }

    #[test]
    fn wrong_recipient_fails() {
        let mut rng = rand::rngs::OsRng;
        let sk = XSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let other_sk = XSecretKey::generate(&mut rng);
        let ct = seal(&mut rng, &pk, b"for correct recipient only");
        assert!(open(&other_sk, &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let mut rng = rand::rngs::OsRng;
        let sk = XSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let mut ct = seal(&mut rng, &pk, b"the quick brown fox");
        // Flip a bit somewhere in the body (past the ephemeral pubkey prefix).
        ct[40] ^= 0x01;
        assert!(open(&sk, &ct).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let mut rng = rand::rngs::OsRng;
        let sk = XSecretKey::generate(&mut rng);
        let pk = sk.public_key();
        let ct = seal(&mut rng, &pk, b"small");
        assert!(open(&sk, &ct[..10]).is_err());
        assert!(open(&sk, &[]).is_err());
    }

    #[test]
    fn secret_key_roundtrip_bytes() {
        let mut rng = rand::rngs::OsRng;
        let sk = XSecretKey::generate(&mut rng);
        let bytes = sk.to_bytes();
        let sk2 = XSecretKey::from_bytes(&bytes);
        assert_eq!(sk.public_key().to_bytes(), sk2.public_key().to_bytes());
    }
}
