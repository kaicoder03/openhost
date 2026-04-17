//! Ed25519 identities for openhost.
//!
//! An openhost identity is an Ed25519 keypair:
//!
//! - [`PublicKey`] — a 32-byte `ed25519-dalek` verifying key.
//! - [`SigningKey`] — a 32-byte `ed25519-dalek` signing key that zeroizes on drop.
//!
//! Public keys are displayed and embedded in URLs as 52-character [z-base-32] strings.
//!
//! The canonical URL form is `oh://<zbase32-pubkey>[/path...]`, parsed and emitted by
//! [`OpenhostUrl`].
//!
//! [z-base-32]: https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt

use crate::{Error, Result};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Number of raw bytes in an Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Number of raw bytes in an Ed25519 private (signing) key.
pub const SIGNING_KEY_LEN: usize = 32;

/// Length of a z-base-32 encoded public key: `ceil(256 / 5) = 52`.
pub const PUBLIC_KEY_ZBASE32_LEN: usize = 52;

/// An openhost public key — a 32-byte Ed25519 verifying key.
///
/// Display, equality, hashing, and serde all use the canonical z-base-32 encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    /// Parse a public key from its raw 32 bytes.
    ///
    /// Rejects non-canonical encodings (per RFC 8032 strict verification).
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidKey("Ed25519 public key is not a canonical point"))
    }

    /// Parse a public key from a z-base-32 string.
    ///
    /// The string must decode to exactly [`PUBLIC_KEY_LEN`] bytes.
    pub fn from_zbase32(s: &str) -> Result<Self> {
        if s.len() != PUBLIC_KEY_ZBASE32_LEN {
            return Err(Error::InvalidIdentityEncoding(
                "z-base-32 public key must be exactly 52 characters",
            ));
        }
        let raw = zbase32::decode_full_bytes_str(s).map_err(|_| {
            Error::InvalidIdentityEncoding("z-base-32 public key contains invalid characters")
        })?;
        if raw.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidIdentityEncoding(
                "z-base-32 public key did not decode to 32 bytes",
            ));
        }
        let mut arr = [0u8; PUBLIC_KEY_LEN];
        arr.copy_from_slice(&raw);
        Self::from_bytes(&arr)
    }

    /// Raw 32 bytes of the public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Canonical z-base-32 encoding of this key.
    #[must_use]
    pub fn to_zbase32(&self) -> String {
        zbase32::encode_full_bytes(&self.to_bytes())
    }

    /// Verify an Ed25519 signature over `message` with strict canonicalization.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.0
            .verify_strict(message, signature)
            .map_err(|_| Error::BadSignature)
    }

    /// The underlying `ed25519-dalek` verifying key, for interop with that crate.
    #[must_use]
    pub fn as_dalek(&self) -> &VerifyingKey {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_zbase32())
    }
}

impl core::str::FromStr for PublicKey {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_zbase32(s)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> core::result::Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_zbase32())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> core::result::Result<Self, D::Error> {
        let s = <&str>::deserialize(de)?;
        Self::from_zbase32(s).map_err(serde::de::Error::custom)
    }
}

/// An openhost signing key — a 32-byte Ed25519 private key that zeroizes on drop.
///
/// This type deliberately does *not* implement `Display`, `Debug` (beyond an opaque
/// placeholder), `Serialize`, or `Clone`. Key material escapes the struct only via the
/// explicit `to_bytes` method on a consuming reference, which requires the caller to
/// accept responsibility for zeroizing the copied bytes.
#[derive(ZeroizeOnDrop)]
pub struct SigningKey(DalekSigningKey);

impl SigningKey {
    /// Generate a fresh signing key from the supplied CSPRNG.
    ///
    /// For production code, use [`SigningKey::generate_os_rng`] unless you have a very
    /// specific reason to inject an RNG (e.g., deterministic tests).
    pub fn generate<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self(DalekSigningKey::generate(rng))
    }

    /// Generate a fresh signing key from the operating system's CSPRNG.
    #[must_use]
    pub fn generate_os_rng() -> Self {
        use rand::rngs::OsRng;
        Self::generate(&mut OsRng)
    }

    /// Parse a signing key from its raw 32 bytes.
    ///
    /// The bytes become the seed; the corresponding public key is derived deterministically.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SIGNING_KEY_LEN]) -> Self {
        Self(DalekSigningKey::from_bytes(bytes))
    }

    /// Raw 32 bytes of the signing seed. The caller is responsible for zeroizing the
    /// returned array when done.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_LEN] {
        self.0.to_bytes()
    }

    /// Derive the matching public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Sign a message with strict canonicalization.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.0.sign(message)
    }

    /// The underlying `ed25519-dalek` signing key, for interop with that crate.
    #[must_use]
    pub fn as_dalek(&self) -> &DalekSigningKey {
        &self.0
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

impl Zeroize for SigningKey {
    fn zeroize(&mut self) {
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
        self.0 = DalekSigningKey::from_bytes(&[0u8; SIGNING_KEY_LEN]);
    }
}

/// A parsed `oh://<pubkey>[/path]` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenhostUrl {
    /// The host public key identifier.
    pub pubkey: PublicKey,
    /// The path component, **with** its leading `/`. Always non-empty — a URL without an
    /// explicit path is normalized to `/`.
    pub path: String,
}

impl OpenhostUrl {
    /// Parse an `oh://<pubkey>[/path]` URL.
    ///
    /// Queries and fragments are not accepted; they must be carried at the HTTP layer,
    /// not in the openhost URL itself.
    pub fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("oh://")
            .ok_or(Error::InvalidUrl("missing oh:// scheme"))?;

        if rest.contains('?') || rest.contains('#') {
            return Err(Error::InvalidUrl(
                "openhost URLs must not carry query or fragment components",
            ));
        }

        let (host, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        let pubkey = PublicKey::from_zbase32(host)?;
        Ok(Self {
            pubkey,
            path: path.to_string(),
        })
    }
}

impl fmt::Display for OpenhostUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "oh://{}{}", self.pubkey, self.path)
    }
}

impl core::str::FromStr for OpenhostUrl {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic signing key for reproducible test vectors. Never use in production.
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    // Expected public key for TEST_SEED (RFC 8032 test vector #1).
    const TEST_PUBKEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn test_signing_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    #[test]
    fn rfc8032_vector1_pubkey() {
        let sk = test_signing_key();
        let pk = sk.public_key();
        let got = hex::encode(pk.to_bytes());
        assert_eq!(
            got, TEST_PUBKEY_HEX,
            "public key matches RFC 8032 vector #1"
        );
    }

    #[test]
    fn zbase32_roundtrip_length() {
        let pk = test_signing_key().public_key();
        let z = pk.to_zbase32();
        assert_eq!(z.len(), PUBLIC_KEY_ZBASE32_LEN);
        let decoded = PublicKey::from_zbase32(&z).expect("roundtrip");
        assert_eq!(decoded, pk);
    }

    #[test]
    fn zbase32_rejects_wrong_length() {
        assert!(PublicKey::from_zbase32("tooshort").is_err());
        // 53 chars — one too many.
        let padded = format!("{}x", test_signing_key().public_key().to_zbase32());
        assert!(PublicKey::from_zbase32(&padded).is_err());
    }

    #[test]
    fn zbase32_rejects_non_alphabet_character() {
        // '|' is not in the z-base-32 alphabet.
        let bad = "|".repeat(PUBLIC_KEY_ZBASE32_LEN);
        assert!(PublicKey::from_zbase32(&bad).is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = test_signing_key();
        let pk = sk.public_key();
        let msg = b"openhost test message";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).expect("valid signature verifies");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let sk = test_signing_key();
        let pk = sk.public_key();
        let sig = sk.sign(b"hello");
        assert!(pk.verify(b"world", &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        use rand::SeedableRng;
        let sk = test_signing_key();
        let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
        let other = SigningKey::generate(&mut rng).public_key();
        let sig = sk.sign(b"hello");
        assert!(other.verify(b"hello", &sig).is_err());
    }

    #[test]
    fn url_parse_minimal() {
        let pk = test_signing_key().public_key();
        let url = format!("oh://{pk}");
        let parsed = OpenhostUrl::parse(&url).expect("parse");
        assert_eq!(parsed.pubkey, pk);
        assert_eq!(parsed.path, "/");
        assert_eq!(parsed.to_string(), format!("oh://{pk}/"));
    }

    #[test]
    fn url_parse_with_path() {
        let pk = test_signing_key().public_key();
        let url = format!("oh://{pk}/library/items/42");
        let parsed = OpenhostUrl::parse(&url).expect("parse");
        assert_eq!(parsed.path, "/library/items/42");
    }

    #[test]
    fn url_rejects_missing_scheme() {
        let pk = test_signing_key().public_key();
        assert!(OpenhostUrl::parse(&format!("https://{pk}")).is_err());
    }

    #[test]
    fn url_rejects_query_or_fragment() {
        let pk = test_signing_key().public_key();
        assert!(OpenhostUrl::parse(&format!("oh://{pk}/?x=1")).is_err());
        assert!(OpenhostUrl::parse(&format!("oh://{pk}/#top")).is_err());
    }

    #[test]
    fn url_rejects_bad_pubkey() {
        assert!(OpenhostUrl::parse("oh://not-a-real-pubkey/").is_err());
    }

    #[test]
    fn pubkey_serde_roundtrip() {
        let pk = test_signing_key().public_key();
        let json = serde_json::to_string(&pk).expect("serialize");
        assert_eq!(json, format!("\"{pk}\""));
        let back: PublicKey = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, pk);
    }
}
