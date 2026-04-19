//! openhost v1 signed DNS record schema.
//!
//! This module defines the *semantic* record that a host publishes — the fields,
//! their constraints, a canonical deterministic byte representation suitable for
//! signing, and the signature envelope that binds those bytes to the host's
//! Ed25519 identity.
//!
//! The *on-the-wire* DNS packet produced by the Pkarr layer is constructed in
//! `openhost-pkarr` (M2). Translating between the two formats is that crate's
//! responsibility; this crate's job is to define what the record says and to sign
//! over a byte string a second implementation can reproduce bit-for-bit.

use crate::identity::{PublicKey, SigningKey};
use crate::{Error, Result};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

/// openhost protocol version carried in the record. Incremented on breaking
/// changes. v2 (PR #22) drops the `allow` and `ice` fields from the canonical
/// bytes; v2 records are a hard break from v1.
pub const PROTOCOL_VERSION: u8 = 2;

/// Maximum permitted age of a signed record in seconds. Verifiers reject records
/// whose internal timestamp is further from "now" than this window.
pub const MAX_RECORD_AGE_SECS: u64 = 7200;

/// Length of the per-host salt used to key the allowlist HMAC.
pub const SALT_LEN: usize = 32;

/// Length of a client-identifying truncated HMAC-SHA256 used by the offer
/// poller (per-client record naming) and the in-process allowlist check.
pub const CLIENT_HASH_LEN: usize = 16;

/// Legacy alias — the v1 record carried a published `allow` field whose
/// entries were this length. v2 drops the field from the wire; the
/// constant is retained because other crates still use it for internal
/// SharedState hashes.
pub const ALLOW_ENTRY_LEN: usize = CLIENT_HASH_LEN;

/// The sha256-fingerprint of a DTLS certificate, 32 bytes.
pub const DTLS_FINGERPRINT_LEN: usize = 32;

/// Maximum length of the `disc` substrate-hints string (informational).
pub const MAX_DISC_LEN: usize = 256;

/// The semantic openhost record published by a host (v2 schema).
///
/// PR #22 removed the v1 `allow` and `ice` fields. The host's allow list
/// is now strictly private state: the daemon checks it internally on the
/// offer-poll path and does not publish it. ICE blobs were unused in
/// production; the field is gone along with the `IceBlob` type that
/// carried them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenhostRecord {
    /// Protocol version. Must equal [`PROTOCOL_VERSION`] for a v2 record.
    pub version: u8,
    /// Unix timestamp (seconds) at which the host published this record.
    pub ts: u64,
    /// SHA-256 fingerprint of the daemon's DTLS certificate.
    pub dtls_fp: [u8; DTLS_FINGERPRINT_LEN],
    /// Host's declared role (e.g. "server"). UTF-8, up to 255 bytes.
    pub roles: String,
    /// Per-host random salt used to key the allowlist HMAC.
    pub salt: [u8; SALT_LEN],
    /// Substrate discovery hints (informational). UTF-8, up to [`MAX_DISC_LEN`] bytes.
    pub disc: String,
}

impl OpenhostRecord {
    /// Validate the record's self-consistency and freshness.
    ///
    /// `now_ts` is the verifier's current Unix timestamp (seconds).
    pub fn validate(&self, now_ts: u64) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(Error::InvalidRecord("unsupported protocol version"));
        }
        // 2-hour window on either side.
        let delta = now_ts.abs_diff(self.ts);
        if delta > MAX_RECORD_AGE_SECS {
            return Err(Error::StaleRecord {
                record_ts: self.ts,
                now_ts,
                max_age_secs: MAX_RECORD_AGE_SECS,
            });
        }
        if self.roles.is_empty() {
            return Err(Error::InvalidRecord("roles must be non-empty"));
        }
        if self.roles.len() > 255 {
            return Err(Error::InvalidRecord("roles exceeds 255 bytes"));
        }
        if self.disc.len() > MAX_DISC_LEN {
            return Err(Error::InvalidRecord("disc hints exceed maximum length"));
        }
        Ok(())
    }

    /// Produce the canonical byte representation used for signing and verification.
    ///
    /// The v2 encoding is explicit and stable:
    ///
    /// ```text
    /// canonical = 0x01                        (legacy encoding tag; unchanged)
    ///          || "openhost1"                 (9 ASCII bytes, legacy domain separator)
    ///          || version (1 byte, equals PROTOCOL_VERSION = 2)
    ///          || ts (8 bytes, u64 big-endian)
    ///          || dtls_fp (32 bytes)
    ///          || roles_len (1 byte)    || roles_bytes
    ///          || salt (32 bytes)
    ///          || disc_len (2 bytes BE) || disc_bytes
    /// ```
    ///
    /// The v1 schema inserted `allow_count || allow_entries || ice_count || ice_blobs`
    /// between `salt` and `disc`. v2 drops those fields entirely; the `version`
    /// byte is the sole discriminator for readers.
    ///
    /// Returns `Err` only when the record fails `validate(now_ts=self.ts)` — i.e.
    /// when the record is ill-formed. Otherwise the returned buffer is deterministic.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate(self.ts)?;

        let mut out = Vec::new();
        out.push(0x01); // encoding-format version tag (legacy; unchanged)
        out.extend_from_slice(b"openhost1");
        out.push(self.version);
        out.extend_from_slice(&self.ts.to_be_bytes());
        out.extend_from_slice(&self.dtls_fp);

        let roles_bytes = self.roles.as_bytes();
        out.push(u8::try_from(roles_bytes.len()).expect("validated <= 255"));
        out.extend_from_slice(roles_bytes);

        out.extend_from_slice(&self.salt);

        let disc_bytes = self.disc.as_bytes();
        let disc_len = u16::try_from(disc_bytes.len()).expect("validated <= MAX_DISC_LEN");
        out.extend_from_slice(&disc_len.to_be_bytes());
        out.extend_from_slice(disc_bytes);

        Ok(out)
    }
}

/// An [`OpenhostRecord`] together with the host's Ed25519 signature over its
/// [`OpenhostRecord::canonical_signing_bytes`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecord {
    /// The signed record contents.
    pub record: OpenhostRecord,
    /// Ed25519 signature over `record.canonical_signing_bytes()`.
    pub signature: Signature,
}

impl SignedRecord {
    /// Sign `record` with `signing_key`.
    pub fn sign(record: OpenhostRecord, signing_key: &SigningKey) -> Result<Self> {
        let msg = record.canonical_signing_bytes()?;
        let signature = signing_key.sign(&msg);
        Ok(Self { record, signature })
    }

    /// Verify the signature against `public_key` and the record's own constraints
    /// (version, freshness, internal consistency).
    ///
    /// `now_ts` is the verifier's current Unix timestamp (seconds).
    pub fn verify(&self, public_key: &PublicKey, now_ts: u64) -> Result<()> {
        self.record.validate(now_ts)?;
        let msg = self.record.canonical_signing_bytes()?;
        public_key.verify(&msg, &self.signature)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::allowlist_hash;
    use crate::identity::SigningKey;

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn sample_record(ts: u64) -> OpenhostRecord {
        let salt = [0x11u8; SALT_LEN];
        // Exercise `allowlist_hash` via an import (the helper is no longer
        // used inside OpenhostRecord, but downstream crates still rely on
        // it; keep the link loud so removals elsewhere show up here).
        let _ = allowlist_hash(&salt, &[0xAAu8; 32]);
        OpenhostRecord {
            version: PROTOCOL_VERSION,
            ts,
            dtls_fp: [0x42u8; DTLS_FINGERPRINT_LEN],
            roles: "server".to_string(),
            salt,
            disc: "dht=1; relay=pkarr.example".to_string(),
        }
    }

    #[test]
    fn canonical_bytes_stable_across_calls() {
        let r = sample_record(1_700_000_000);
        let a = r.canonical_signing_bytes().unwrap();
        let b = r.canonical_signing_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let pk = sk.public_key();
        let record = sample_record(1_700_000_000);
        let signed = SignedRecord::sign(record.clone(), &sk).unwrap();
        signed
            .verify(&pk, record.ts)
            .expect("fresh record verifies");
    }

    #[test]
    fn verify_rejects_tampered_record() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let pk = sk.public_key();
        let mut record = sample_record(1_700_000_000);
        let signed = SignedRecord::sign(record.clone(), &sk).unwrap();
        record.dtls_fp[0] ^= 0x01;
        let tampered = SignedRecord {
            record,
            signature: signed.signature,
        };
        assert!(matches!(
            tampered.verify(&pk, 1_700_000_000),
            Err(Error::BadSignature)
        ));
    }

    #[test]
    fn verify_rejects_stale_record() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let pk = sk.public_key();
        let record = sample_record(1_700_000_000);
        let signed = SignedRecord::sign(record.clone(), &sk).unwrap();
        let now = record.ts + MAX_RECORD_AGE_SECS + 1;
        assert!(matches!(
            signed.verify(&pk, now),
            Err(Error::StaleRecord { .. })
        ));
    }

    #[test]
    fn verify_rejects_future_dated_record() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let pk = sk.public_key();
        let record = sample_record(1_700_000_000);
        let signed = SignedRecord::sign(record.clone(), &sk).unwrap();
        let now = record.ts - MAX_RECORD_AGE_SECS - 1;
        assert!(matches!(
            signed.verify(&pk, now),
            Err(Error::StaleRecord { .. })
        ));
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let mut r = sample_record(1_700_000_000);
        r.version = 99;
        assert!(matches!(r.validate(r.ts), Err(Error::InvalidRecord(_))));
    }

    #[test]
    fn validate_rejects_empty_roles() {
        let mut r = sample_record(1_700_000_000);
        r.roles = String::new();
        assert!(matches!(r.validate(r.ts), Err(Error::InvalidRecord(_))));
    }

    #[test]
    fn canonical_bytes_change_with_any_field() {
        let base = sample_record(1_700_000_000)
            .canonical_signing_bytes()
            .unwrap();

        let mut r = sample_record(1_700_000_000);
        r.ts += 1;
        assert_ne!(r.canonical_signing_bytes().unwrap(), base);

        let mut r = sample_record(1_700_000_000);
        r.dtls_fp[5] ^= 0x80;
        assert_ne!(r.canonical_signing_bytes().unwrap(), base);

        let mut r = sample_record(1_700_000_000);
        r.roles = "server2".to_string();
        assert_ne!(r.canonical_signing_bytes().unwrap(), base);

        let mut r = sample_record(1_700_000_000);
        r.salt[0] ^= 0xFF;
        assert_ne!(r.canonical_signing_bytes().unwrap(), base);

        let mut r = sample_record(1_700_000_000);
        r.disc.push_str(" extra");
        assert_ne!(r.canonical_signing_bytes().unwrap(), base);
    }

    /// Measure the wire size of a v2 main record after base64url wrapping
    /// (the outer BEP44 `v` is `base64url(signature || canonical)`). With
    /// the v1 allow+ice fields dropped, a realistic record should encode
    /// under 220 base64 chars; this asserts a generous ceiling so a future
    /// field addition that quietly bloats the record can't silently
    /// recreate the pre-PR-22 BEP44 overflow regression.
    #[test]
    fn v2_main_record_base64_fits_under_ceiling() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let sk = SigningKey::from_bytes(&RFC_SEED);
        let signed = SignedRecord::sign(sample_record(1_700_000_000), &sk).unwrap();
        let canonical = signed.record.canonical_signing_bytes().unwrap();
        let mut blob = Vec::with_capacity(64 + canonical.len());
        blob.extend_from_slice(&signed.signature.to_bytes());
        blob.extend_from_slice(&canonical);
        let b64 = URL_SAFE_NO_PAD.encode(&blob);
        // Realistic v2 record with a non-empty `disc` measures ~243
        // chars (v1 with 1 allow + 1 ice blob was ~392). Ceiling at
        // 260 leaves a little slack for disc tweaks while still
        // catching a regression that re-bloats the record.
        assert!(
            b64.len() < 260,
            "v2 main record base64 is {} chars; keep under 260 so fragmented answers fit the BEP44 budget",
            b64.len(),
        );
    }
}
