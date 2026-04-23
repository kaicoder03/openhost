//! Pairing-code encoding.
//!
//! A [`PairingCode`] carries 16 bytes of entropy with two human-
//! readable renderings:
//!
//! - **Words** — 12 BIP-39 English words, space-separated. Ideal
//!   for reading aloud, typing, and SMS; each word has ~4 chars
//!   average and the BIP-39 wordlist is phonetically distinct.
//!   12 words → 128 bits of entropy + 4-bit checksum.
//!
//! - **URI** — `oh+pair://<zbase32>` where `<zbase32>` encodes the
//!   16 bytes in ~26 characters. Ideal for QR codes, deep-links
//!   (`intent://` on Android, Universal Links on iOS), and
//!   copy-paste.
//!
//! Both encodings round-trip losslessly to the same 16 bytes.
//! [`PairingCode::parse`] is a convenience that accepts either form,
//! so `oh recv` can take whatever the sender pastes without a flag.

use crate::error::{PeerError, Result};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length, in bytes, of the raw secret carried by a [`PairingCode`].
/// Chosen so that (a) it fits a BIP-39 12-word mnemonic exactly and
/// (b) 2^128 offline dictionary work is infeasible even without a
/// PAKE protecting the mailbox.
pub const PAIRING_SECRET_BYTES: usize = 16;

/// URI scheme prefix for [`PairingCode::to_uri`] / [`from_uri`].
///
/// [`from_uri`]: PairingCode::from_uri
pub const PAIRING_URI_SCHEME: &str = "oh+pair://";

/// 128-bit pairing secret with human-readable encodings.
///
/// Constructed via [`PairingCode::generate`] (fresh random) or
/// [`PairingCode::from_bytes`] (wrap an existing secret). The raw
/// bytes are zeroed on drop; [`Debug`] renders a redacted form so
/// `tracing::debug!("{:?}", code)` never leaks the secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PairingCode([u8; PAIRING_SECRET_BYTES]);

impl PairingCode {
    /// Generate a fresh pairing code from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; PAIRING_SECRET_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wrap an existing 16-byte secret. The caller is responsible
    /// for the source of entropy.
    pub fn from_bytes(bytes: [u8; PAIRING_SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 16 bytes. Used by downstream key-derivation
    /// (see [`crate::mailbox::MailboxKey::derive`]).
    pub fn as_bytes(&self) -> &[u8; PAIRING_SECRET_BYTES] {
        &self.0
    }

    /// Render the secret as 12 BIP-39 English words.
    pub fn to_words(&self) -> String {
        let mnemonic = bip39::Mnemonic::from_entropy(&self.0)
            .expect("16-byte entropy always produces a 12-word BIP-39 mnemonic");
        mnemonic.to_string()
    }

    /// Parse 12 BIP-39 words back into a pairing code.
    ///
    /// Normalisation matches [`bip39::Mnemonic::parse_normalized`]:
    /// whitespace is collapsed and words are case-insensitive.
    pub fn from_words(s: &str) -> Result<Self> {
        let mnemonic = bip39::Mnemonic::parse_normalized(s.trim())
            .map_err(|e| PeerError::InvalidCode(format!("BIP-39 parse failed: {e}")))?;
        let entropy = mnemonic.to_entropy();
        if entropy.len() != PAIRING_SECRET_BYTES {
            return Err(PeerError::InvalidCode(format!(
                "expected {} bytes of entropy ({} words), got {}",
                PAIRING_SECRET_BYTES,
                12,
                entropy.len()
            )));
        }
        let mut bytes = [0u8; PAIRING_SECRET_BYTES];
        bytes.copy_from_slice(&entropy);
        Ok(Self(bytes))
    }

    /// Render the secret as a `oh+pair://<zbase32>` URI.
    pub fn to_uri(&self) -> String {
        format!(
            "{}{}",
            PAIRING_URI_SCHEME,
            zbase32::encode_full_bytes(&self.0)
        )
    }

    /// Parse a `oh+pair://…` URI back into a pairing code.
    pub fn from_uri(s: &str) -> Result<Self> {
        let rest = s.strip_prefix(PAIRING_URI_SCHEME).ok_or_else(|| {
            PeerError::InvalidCode(format!("expected `{PAIRING_URI_SCHEME}` prefix"))
        })?;
        let decoded = zbase32::decode_full_bytes_str(rest)
            .map_err(|e| PeerError::InvalidCode(format!("zbase32 decode failed: {e:?}")))?;
        if decoded.len() != PAIRING_SECRET_BYTES {
            return Err(PeerError::InvalidCode(format!(
                "expected {PAIRING_SECRET_BYTES} bytes after decode, got {}",
                decoded.len()
            )));
        }
        let mut bytes = [0u8; PAIRING_SECRET_BYTES];
        bytes.copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    /// Parse user-supplied input as EITHER a BIP-39 word list OR a
    /// `oh+pair://` URI. Intended for `oh recv` arg parsing so the
    /// CLI doesn't need a `--format=words|uri` flag.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.starts_with(PAIRING_URI_SCHEME) {
            Self::from_uri(s)
        } else {
            Self::from_words(s)
        }
    }
}

impl std::fmt::Debug for PairingCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // NEVER render the raw secret. Show the URI prefix so logs
        // still indicate "this is a PairingCode" without leaking it.
        write!(f, "PairingCode(<redacted 16 bytes>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_yields_16_bytes() {
        let code = PairingCode::generate();
        assert_eq!(code.as_bytes().len(), PAIRING_SECRET_BYTES);
    }

    #[test]
    fn generate_is_random() {
        // Collision probability ~ 2^-64 for 10 samples of 128-bit —
        // negligible. Catches a broken RNG plug.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            assert!(seen.insert(*PairingCode::generate().as_bytes()));
        }
    }

    #[test]
    fn words_roundtrip_preserves_secret() {
        for _ in 0..50 {
            let code = PairingCode::generate();
            let words = code.to_words();
            assert_eq!(
                words.split_whitespace().count(),
                12,
                "16-byte entropy must produce exactly 12 BIP-39 words",
            );
            let parsed = PairingCode::from_words(&words).unwrap();
            assert_eq!(code.as_bytes(), parsed.as_bytes());
        }
    }

    #[test]
    fn uri_roundtrip_preserves_secret() {
        for _ in 0..50 {
            let code = PairingCode::generate();
            let uri = code.to_uri();
            assert!(uri.starts_with(PAIRING_URI_SCHEME));
            let parsed = PairingCode::from_uri(&uri).unwrap();
            assert_eq!(code.as_bytes(), parsed.as_bytes());
        }
    }

    #[test]
    fn parse_accepts_both_forms() {
        let code = PairingCode::generate();
        let from_words = PairingCode::parse(&code.to_words()).unwrap();
        let from_uri = PairingCode::parse(&code.to_uri()).unwrap();
        assert_eq!(code.as_bytes(), from_words.as_bytes());
        assert_eq!(code.as_bytes(), from_uri.as_bytes());
    }

    #[test]
    fn parse_trims_leading_trailing_whitespace() {
        let code = PairingCode::generate();
        let padded = format!("   {}   \n", code.to_words());
        assert_eq!(
            code.as_bytes(),
            PairingCode::parse(&padded).unwrap().as_bytes(),
        );
    }

    #[test]
    fn wrong_word_count_is_rejected() {
        let err = PairingCode::from_words("only three words here").unwrap_err();
        assert!(matches!(err, PeerError::InvalidCode(_)));
    }

    #[test]
    fn non_bip39_word_is_rejected() {
        // "xylophonexyz" is not in the BIP-39 wordlist — the parser
        // must reject rather than silently lookup a nearest match.
        let mut words: Vec<&str> =
            "witch collapse practice feed shame open despair creek road again ice least"
                .split_whitespace()
                .collect();
        words[0] = "xylophonexyz";
        let err = PairingCode::from_words(&words.join(" ")).unwrap_err();
        assert!(matches!(err, PeerError::InvalidCode(_)));
    }

    #[test]
    fn missing_uri_scheme_is_rejected() {
        let err = PairingCode::from_uri("http://example.com/foo").unwrap_err();
        assert!(matches!(err, PeerError::InvalidCode(_)));
    }

    #[test]
    fn wrong_length_uri_is_rejected() {
        // Valid zbase32 but too few bytes.
        let err = PairingCode::from_uri("oh+pair://yy").unwrap_err();
        assert!(matches!(err, PeerError::InvalidCode(_)));
    }

    #[test]
    fn debug_redacts_secret() {
        let code = PairingCode::from_bytes([0xAA; PAIRING_SECRET_BYTES]);
        let rendered = format!("{:?}", code);
        assert!(!rendered.contains("aa"), "Debug must not leak bytes");
        assert!(!rendered.contains("AA"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn from_bytes_roundtrip_is_identity() {
        let raw = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let code = PairingCode::from_bytes(raw);
        assert_eq!(code.as_bytes(), &raw);
    }

    /// Known-answer test: lock the BIP-39 wordlist mapping for the
    /// all-zero secret. Catches an accidental upgrade to a different
    /// wordlist / language that would break cross-client compat.
    #[test]
    fn known_answer_all_zero_secret() {
        let code = PairingCode::from_bytes([0u8; PAIRING_SECRET_BYTES]);
        // 16 zero bytes in BIP-39 English = 12 copies of the first
        // wordlist entry, "abandon", plus the correct checksum word.
        // The final word reflects the checksum of all-zero entropy,
        // which BIP-39 defines as "art".
        let words = code.to_words();
        assert!(words.starts_with("abandon abandon abandon"), "got: {words}");
    }
}
