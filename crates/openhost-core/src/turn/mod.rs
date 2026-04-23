//! TURN credentials and quota tokens for relay-fallback ICE.
//!
//! See [`spec/05-turn-credentials.md`](https://github.com/kaicoder03/openhost/blob/main/spec/05-turn-credentials.md)
//! for the normative protocol.
//!
//! This module provides the data types and Ed25519 sign/verify routines used
//! when a client cannot establish a direct WebRTC path and must traverse a
//! TURN relay. The relay never observes plaintext — see `spec/04-security.md`
//! §1 for the supporting invariants — but it does observe ciphertext volume,
//! which is why credentials are scoped to a subject pubkey and quota tokens
//! cap relayed bytes per window.
//!
//! The module is intentionally infrastructure-agnostic: it defines the
//! credential and token *envelope*, not the issuer's REST API and not the
//! client's RTCConfiguration plumbing. Those land in follow-up PRs that wire
//! `openhost-client::Dialer` and `openhost-daemon::Config` to consume the
//! types defined here.

use crate::identity::{PublicKey, SigningKey, PUBLIC_KEY_LEN};
use crate::{Error, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SIGNATURE_LENGTH};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum permitted lifetime of a [`TurnCredential`] — `expires_at - issued_at`
/// MUST NOT exceed this value.
///
/// One hour matches `spec/05-turn-credentials.md` §4. Issuers typically mint
/// credentials valid for ≤ 5 minutes; the one-hour ceiling is a hard cap so
/// verifiers can reject obvious mis-issuance without per-issuer policy.
pub const MAX_CREDENTIAL_LIFETIME_SECS: u64 = 3_600;

/// Maximum permitted lifetime of a [`QuotaToken`] — `expires_at - issued_at`
/// MUST NOT exceed this value.
///
/// 15 minutes per `spec/05-turn-credentials.md` §5. Quota tokens are
/// refreshed frequently so the issuer can update `consumed_bytes` as traffic
/// accrues; a long-lived quota token defeats the point of the substrate.
pub const MAX_QUOTA_TOKEN_LIFETIME_SECS: u64 = 900;

/// Maximum permitted `window_secs` on a [`QuotaToken`] (~31 days).
///
/// Quota windows longer than a calendar month would let an issuer mint a
/// single token covering arbitrary future traffic, which contradicts the
/// freshness assumption baked into [`MAX_QUOTA_TOKEN_LIFETIME_SECS`].
pub const MAX_QUOTA_WINDOW_SECS: u64 = 31 * 86_400;

/// Encoding tag prefixed to TURN canonical signing bytes.
///
/// Distinct from `pkarr_record`'s `0x01` tag so a signature lifted from one
/// context cannot be replayed into the other.
pub const TURN_ENCODING_TAG: u8 = 0x02;

/// Domain separator for [`TurnCredential::canonical_signing_bytes`].
pub const CREDENTIAL_DOMAIN: &[u8] = b"openhost-turn-credential-v1";

/// Domain separator for [`QuotaToken::canonical_signing_bytes`].
pub const QUOTA_DOMAIN: &[u8] = b"openhost-turn-quota-v1";

/// A single TURN server entry — feeds 1:1 into `webrtc::ice_transport::ice_server::RTCIceServer`.
///
/// Field semantics match RFC 7065 (URL syntax) and RFC 8489 (long-term
/// credential mechanism). `urls` MAY contain multiple entries for the same
/// underlying server in different transports (e.g. `turn:` UDP + `turns:` TLS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnServer {
    /// `turn:` or `turns:` URLs. Plain `stun:` URLs do not belong here.
    pub urls: Vec<String>,
    /// RFC 8489 long-term credential username.
    pub username: String,
    /// RFC 8489 long-term credential password.
    pub credential: String,
}

impl TurnServer {
    fn validate(&self) -> Result<()> {
        if self.urls.is_empty() {
            return Err(Error::InvalidTurnCredential("server has no URLs"));
        }
        if self.urls.len() > u8::MAX as usize {
            return Err(Error::InvalidTurnCredential(
                "server has more URLs than the wire format allows (255)",
            ));
        }
        for url in &self.urls {
            if !(url.starts_with("turn:") || url.starts_with("turns:")) {
                return Err(Error::InvalidTurnCredential(
                    "TURN URL must begin with turn: or turns:",
                ));
            }
            if url.len() > u16::MAX as usize {
                return Err(Error::InvalidTurnCredential("URL exceeds 65535 bytes"));
            }
        }
        if self.username.len() > u16::MAX as usize {
            return Err(Error::InvalidTurnCredential("username exceeds 65535 bytes"));
        }
        if self.credential.len() > u16::MAX as usize {
            return Err(Error::InvalidTurnCredential(
                "credential exceeds 65535 bytes",
            ));
        }
        Ok(())
    }

    fn extend_canonical(&self, out: &mut Vec<u8>) {
        // url_count fits in a byte by validate().
        out.push(self.urls.len() as u8);
        for url in &self.urls {
            let bytes = url.as_bytes();
            out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        let user = self.username.as_bytes();
        out.extend_from_slice(&(user.len() as u16).to_be_bytes());
        out.extend_from_slice(user);
        let cred = self.credential.as_bytes();
        out.extend_from_slice(&(cred.len() as u16).to_be_bytes());
        out.extend_from_slice(cred);
    }
}

/// Issuer-signed bundle naming a subject pubkey and the TURN servers it may use.
///
/// See `spec/05-turn-credentials.md` §4 for the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TurnCredential {
    /// Pubkey authorised to use these servers.
    pub subject: PublicKey,
    /// TURN servers (≥ 1).
    pub servers: Vec<TurnServer>,
    /// Unix seconds — credential valid from.
    pub issued_at: u64,
    /// Unix seconds — credential expires at.
    pub expires_at: u64,
    /// Pubkey of the issuer.
    pub issuer: PublicKey,
    /// Ed25519 signature by `issuer` over [`Self::canonical_signing_bytes`].
    pub signature: SignatureBytes,
}

impl TurnCredential {
    /// Validate structural invariants independent of any signature check.
    ///
    /// Called from [`Self::canonical_signing_bytes`] and from
    /// [`Self::verify`]. Exposed so issuers can sanity-check inputs before
    /// signing.
    pub fn validate(&self) -> Result<()> {
        if self.servers.is_empty() {
            return Err(Error::InvalidTurnCredential("empty server list"));
        }
        if self.servers.len() > u16::MAX as usize {
            return Err(Error::InvalidTurnCredential(
                "more than 65535 servers in credential",
            ));
        }
        if self.expires_at < self.issued_at {
            return Err(Error::InvalidTurnCredential(
                "expires_at is earlier than issued_at",
            ));
        }
        let lifetime = self.expires_at - self.issued_at;
        if lifetime > MAX_CREDENTIAL_LIFETIME_SECS {
            return Err(Error::OverlongTurnCredential {
                lifetime_secs: lifetime,
                max_secs: MAX_CREDENTIAL_LIFETIME_SECS,
            });
        }
        for server in &self.servers {
            server.validate()?;
        }
        Ok(())
    }

    /// Canonical byte representation used for signing and verification.
    ///
    /// See `spec/05-turn-credentials.md` §4.1 for the layout.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(128);
        out.push(TURN_ENCODING_TAG);
        out.extend_from_slice(CREDENTIAL_DOMAIN);
        out.extend_from_slice(&self.subject.to_bytes());
        out.extend_from_slice(&self.issuer.to_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(self.servers.len() as u16).to_be_bytes());
        for server in &self.servers {
            server.extend_canonical(&mut out);
        }
        Ok(out)
    }

    /// Sign an unsigned-shaped credential with `issuer_sk`, populating the
    /// returned credential's `signature` field.
    pub fn sign(
        subject: PublicKey,
        servers: Vec<TurnServer>,
        issued_at: u64,
        expires_at: u64,
        issuer_sk: &SigningKey,
    ) -> Result<Self> {
        let issuer = issuer_sk.public_key();
        let mut cred = Self {
            subject,
            servers,
            issued_at,
            expires_at,
            issuer,
            // Sentinel: overwritten before return. We do NOT sign over a
            // zero signature — `canonical_signing_bytes` never includes
            // the signature field — so the placeholder is safe.
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let msg = cred.canonical_signing_bytes()?;
        let sig = issuer_sk.sign(&msg);
        cred.signature = SignatureBytes(sig.to_bytes());
        Ok(cred)
    }

    /// Verify the credential against `now_ts` and `trusted_issuers`.
    ///
    /// Returns `Ok(())` if and only if every check in
    /// `spec/05-turn-credentials.md` §4.2 passes against `verifier_subject`
    /// (which MUST be the local pubkey).
    ///
    /// `now_ts` is the verifier's current Unix timestamp in seconds.
    pub fn verify(
        &self,
        verifier_subject: &PublicKey,
        trusted_issuers: &[PublicKey],
        now_ts: u64,
    ) -> Result<()> {
        if !trusted_issuers.iter().any(|p| p == &self.issuer) {
            return Err(Error::UntrustedTurnIssuer);
        }
        if self.expires_at < now_ts {
            return Err(Error::ExpiredTurnCredential {
                expires_at: self.expires_at,
                now_ts,
            });
        }
        // validate() also catches expires_at < issued_at and overlong
        // lifetime; ordering it after the cheap checks above keeps the
        // common error paths fast.
        let msg = self.canonical_signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature.0);
        self.issuer.verify(&msg, &sig)?;
        if &self.subject != verifier_subject {
            return Err(Error::TurnSubjectMismatch);
        }
        Ok(())
    }
}

/// Issuer-signed assertion of a relayed-byte cap for a subject pubkey.
///
/// See `spec/05-turn-credentials.md` §5 for the wire format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaToken {
    /// Subject pubkey the quota applies to.
    pub subject: PublicKey,
    /// Unix seconds — start of the quota window.
    pub window_start: u64,
    /// Window duration in seconds (≤ [`MAX_QUOTA_WINDOW_SECS`]).
    pub window_secs: u64,
    /// Cap on relayed bytes within the window.
    pub cap_bytes: u64,
    /// Bytes already relayed in the window at issuance time.
    pub consumed_bytes: u64,
    /// Unix seconds — token valid from.
    pub issued_at: u64,
    /// Unix seconds — token expires at.
    pub expires_at: u64,
    /// Pubkey of the issuer.
    pub issuer: PublicKey,
    /// Ed25519 signature by `issuer` over [`Self::canonical_signing_bytes`].
    pub signature: SignatureBytes,
}

impl QuotaToken {
    /// Validate structural invariants independent of any signature check.
    pub fn validate(&self) -> Result<()> {
        if self.window_secs == 0 {
            return Err(Error::InvalidTurnCredential("window_secs must be > 0"));
        }
        if self.window_secs > MAX_QUOTA_WINDOW_SECS {
            return Err(Error::InvalidTurnCredential("window_secs exceeds 31 days"));
        }
        if self.consumed_bytes > self.cap_bytes {
            return Err(Error::InvalidTurnCredential(
                "consumed_bytes exceeds cap_bytes",
            ));
        }
        if self.expires_at < self.issued_at {
            return Err(Error::InvalidTurnCredential(
                "expires_at is earlier than issued_at",
            ));
        }
        let lifetime = self.expires_at - self.issued_at;
        if lifetime > MAX_QUOTA_TOKEN_LIFETIME_SECS {
            return Err(Error::OverlongTurnCredential {
                lifetime_secs: lifetime,
                max_secs: MAX_QUOTA_TOKEN_LIFETIME_SECS,
            });
        }
        Ok(())
    }

    /// Canonical byte representation used for signing and verification.
    ///
    /// See `spec/05-turn-credentials.md` §5.1 for the layout.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(128);
        out.push(TURN_ENCODING_TAG);
        out.extend_from_slice(QUOTA_DOMAIN);
        out.extend_from_slice(&self.subject.to_bytes());
        out.extend_from_slice(&self.issuer.to_bytes());
        out.extend_from_slice(&self.window_start.to_be_bytes());
        out.extend_from_slice(&self.window_secs.to_be_bytes());
        out.extend_from_slice(&self.cap_bytes.to_be_bytes());
        out.extend_from_slice(&self.consumed_bytes.to_be_bytes());
        out.extend_from_slice(&self.issued_at.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        Ok(out)
    }

    /// Sign an unsigned-shaped quota token with `issuer_sk`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        subject: PublicKey,
        window_start: u64,
        window_secs: u64,
        cap_bytes: u64,
        consumed_bytes: u64,
        issued_at: u64,
        expires_at: u64,
        issuer_sk: &SigningKey,
    ) -> Result<Self> {
        let issuer = issuer_sk.public_key();
        let mut tok = Self {
            subject,
            window_start,
            window_secs,
            cap_bytes,
            consumed_bytes,
            issued_at,
            expires_at,
            issuer,
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let msg = tok.canonical_signing_bytes()?;
        let sig = issuer_sk.sign(&msg);
        tok.signature = SignatureBytes(sig.to_bytes());
        Ok(tok)
    }

    /// Verify the quota token. See `spec/05-turn-credentials.md` §5.2.
    pub fn verify(
        &self,
        verifier_subject: &PublicKey,
        trusted_issuers: &[PublicKey],
        now_ts: u64,
    ) -> Result<()> {
        if !trusted_issuers.iter().any(|p| p == &self.issuer) {
            return Err(Error::UntrustedTurnIssuer);
        }
        if self.expires_at < now_ts {
            return Err(Error::ExpiredTurnCredential {
                expires_at: self.expires_at,
                now_ts,
            });
        }
        let msg = self.canonical_signing_bytes()?;
        let sig = Signature::from_bytes(&self.signature.0);
        self.issuer.verify(&msg, &sig)?;
        if &self.subject != verifier_subject {
            return Err(Error::TurnSubjectMismatch);
        }
        Ok(())
    }

    /// Bytes still available against the cap, given the verifier's local
    /// counter of bytes relayed since `consumed_bytes` was issued.
    ///
    /// Returns `0` when the local counter has caught up to or exceeded the
    /// remaining headroom — callers MUST stop relaying when this is `0`.
    #[must_use]
    pub fn remaining_bytes(&self, locally_consumed_since_issue: u64) -> u64 {
        self.cap_bytes
            .saturating_sub(self.consumed_bytes)
            .saturating_sub(locally_consumed_since_issue)
    }

    /// `true` if relaying `additional` more bytes would cross the cap.
    #[must_use]
    pub fn would_exceed(&self, locally_consumed_since_issue: u64, additional: u64) -> bool {
        self.consumed_bytes
            .saturating_add(locally_consumed_since_issue)
            .saturating_add(additional)
            > self.cap_bytes
    }
}

/// Newtype around the raw 64-byte Ed25519 signature with base64url-no-pad
/// JSON serialization.
///
/// Wire format intentionally matches the sealed-offer TXT encoding in
/// `spec/03-pkarr-records.md` §3.3 so implementations can share base64
/// helpers across both call sites.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignatureBytes(pub [u8; SIGNATURE_LENGTH]);

impl SignatureBytes {
    /// Raw 64 bytes of the signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }

    /// Construct from a base64url-no-pad string.
    pub fn from_base64url(s: &str) -> Result<Self> {
        let raw = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| Error::InvalidTurnCredential("signature is not valid base64url"))?;
        if raw.len() != SIGNATURE_LENGTH {
            return Err(Error::InvalidTurnCredential(
                "signature did not decode to 64 bytes",
            ));
        }
        let mut arr = [0u8; SIGNATURE_LENGTH];
        arr.copy_from_slice(&raw);
        Ok(Self(arr))
    }

    /// Encode as a base64url-no-pad string.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl core::fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Don't dump 64 bytes of sig into Debug output — the b64url form is
        // shorter and matches what appears on the wire.
        write!(f, "SignatureBytes({})", self.to_base64url())
    }
}

impl Serialize for SignatureBytes {
    fn serialize<S: Serializer>(&self, ser: S) -> core::result::Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_base64url())
    }
}

impl<'de> Deserialize<'de> for SignatureBytes {
    fn deserialize<D: Deserializer<'de>>(de: D) -> core::result::Result<Self, D::Error> {
        let s = <&str>::deserialize(de)?;
        Self::from_base64url(s).map_err(serde::de::Error::custom)
    }
}

// Compile-time assert: `PUBLIC_KEY_LEN` is part of the canonical bytes
// layout. If the upstream constant ever changes, every TURN signature in
// existence is invalidated — fail the build instead of silently accepting
// re-encoded signatures.
const _: () = assert!(PUBLIC_KEY_LEN == 32);

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER_SEED: [u8; 32] = [0x11u8; 32];
    const SUBJECT_SEED: [u8; 32] = [0x22u8; 32];
    const OTHER_SEED: [u8; 32] = [0x33u8; 32];

    fn issuer_sk() -> SigningKey {
        SigningKey::from_bytes(&ISSUER_SEED)
    }

    fn subject_pk() -> PublicKey {
        SigningKey::from_bytes(&SUBJECT_SEED).public_key()
    }

    fn other_pk() -> PublicKey {
        SigningKey::from_bytes(&OTHER_SEED).public_key()
    }

    fn sample_servers() -> Vec<TurnServer> {
        vec![TurnServer {
            urls: vec![
                "turn:relay.oh-send.dev:3478?transport=udp".to_string(),
                "turns:relay.oh-send.dev:5349?transport=tcp".to_string(),
            ],
            username: "1700000000:47pjoycn…".to_string(),
            credential: "deadbeefcafef00d".to_string(),
        }]
    }

    fn sample_credential() -> TurnCredential {
        TurnCredential::sign(
            subject_pk(),
            sample_servers(),
            1_700_000_000,
            1_700_000_300,
            &issuer_sk(),
        )
        .expect("sign sample credential")
    }

    fn sample_quota() -> QuotaToken {
        QuotaToken::sign(
            subject_pk(),
            1_700_000_000,
            30 * 86_400,
            5 * 1024 * 1024 * 1024,
            1024 * 1024 * 1024,
            1_700_000_000,
            1_700_000_600,
            &issuer_sk(),
        )
        .expect("sign sample quota")
    }

    #[test]
    fn credential_canonical_bytes_stable_across_calls() {
        let c = sample_credential();
        let a = c.canonical_signing_bytes().unwrap();
        let b = c.canonical_signing_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn credential_signs_and_verifies() {
        let issuer_pk = issuer_sk().public_key();
        let cred = sample_credential();
        cred.verify(&subject_pk(), &[issuer_pk], 1_700_000_100)
            .expect("fresh credential verifies");
    }

    #[test]
    fn credential_rejects_unknown_issuer() {
        let cred = sample_credential();
        let stranger = other_pk();
        let err = cred
            .verify(&subject_pk(), &[stranger], 1_700_000_100)
            .unwrap_err();
        assert!(matches!(err, Error::UntrustedTurnIssuer), "got: {err:?}");
    }

    #[test]
    fn credential_rejects_expired() {
        let issuer_pk = issuer_sk().public_key();
        let cred = sample_credential();
        let err = cred
            .verify(&subject_pk(), &[issuer_pk], cred.expires_at + 1)
            .unwrap_err();
        assert!(
            matches!(err, Error::ExpiredTurnCredential { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn credential_rejects_overlong_lifetime() {
        // Construct directly to bypass sign(); validate() catches the
        // overlong window.
        let issuer_pk = issuer_sk().public_key();
        let cred = TurnCredential {
            subject: subject_pk(),
            servers: sample_servers(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_000 + MAX_CREDENTIAL_LIFETIME_SECS + 1,
            issuer: issuer_pk,
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let err = cred.canonical_signing_bytes().unwrap_err();
        assert!(
            matches!(err, Error::OverlongTurnCredential { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn credential_rejects_wrong_subject() {
        let issuer_pk = issuer_sk().public_key();
        let cred = sample_credential();
        let err = cred
            .verify(&other_pk(), &[issuer_pk], 1_700_000_100)
            .unwrap_err();
        assert!(matches!(err, Error::TurnSubjectMismatch), "got: {err:?}");
    }

    #[test]
    fn credential_rejects_tampered_server() {
        let issuer_pk = issuer_sk().public_key();
        let mut cred = sample_credential();
        cred.servers[0].credential = "tampered".to_string();
        let err = cred
            .verify(&subject_pk(), &[issuer_pk], 1_700_000_100)
            .unwrap_err();
        assert!(matches!(err, Error::BadSignature), "got: {err:?}");
    }

    #[test]
    fn credential_rejects_tampered_signature() {
        let issuer_pk = issuer_sk().public_key();
        let mut cred = sample_credential();
        cred.signature.0[0] ^= 0x01;
        let err = cred
            .verify(&subject_pk(), &[issuer_pk], 1_700_000_100)
            .unwrap_err();
        assert!(matches!(err, Error::BadSignature), "got: {err:?}");
    }

    #[test]
    fn credential_rejects_empty_servers() {
        let cred = TurnCredential {
            subject: subject_pk(),
            servers: vec![],
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            issuer: issuer_sk().public_key(),
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let err = cred.canonical_signing_bytes().unwrap_err();
        assert!(
            matches!(err, Error::InvalidTurnCredential(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn credential_rejects_non_turn_url() {
        let cred = TurnCredential {
            subject: subject_pk(),
            servers: vec![TurnServer {
                urls: vec!["stun:stun.example:3478".to_string()],
                username: "u".into(),
                credential: "p".into(),
            }],
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
            issuer: issuer_sk().public_key(),
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let err = cred.canonical_signing_bytes().unwrap_err();
        assert!(
            matches!(err, Error::InvalidTurnCredential(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn credential_json_roundtrip() {
        let cred = sample_credential();
        let json = serde_json::to_string(&cred).expect("serialize");
        let back: TurnCredential = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cred, back);
        // Round-trip preserves the signature, so the deserialized form
        // verifies under the same issuer.
        let issuer_pk = issuer_sk().public_key();
        back.verify(&subject_pk(), &[issuer_pk], 1_700_000_100)
            .expect("roundtripped credential verifies");
    }

    #[test]
    fn credential_json_rejects_unknown_field() {
        let cred = sample_credential();
        let mut value: serde_json::Value = serde_json::to_value(&cred).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::Value::Bool(true));
        let json = serde_json::to_string(&value).unwrap();
        let res: core::result::Result<TurnCredential, _> = serde_json::from_str(&json);
        assert!(res.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn quota_signs_and_verifies() {
        let issuer_pk = issuer_sk().public_key();
        let tok = sample_quota();
        tok.verify(&subject_pk(), &[issuer_pk], 1_700_000_100)
            .expect("fresh quota verifies");
    }

    #[test]
    fn quota_rejects_consumed_over_cap() {
        let tok = QuotaToken {
            subject: subject_pk(),
            window_start: 0,
            window_secs: 86_400,
            cap_bytes: 1_000,
            consumed_bytes: 1_001,
            issued_at: 0,
            expires_at: 600,
            issuer: issuer_sk().public_key(),
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let err = tok.canonical_signing_bytes().unwrap_err();
        assert!(
            matches!(err, Error::InvalidTurnCredential(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn quota_rejects_overlong_lifetime() {
        let tok = QuotaToken {
            subject: subject_pk(),
            window_start: 0,
            window_secs: 86_400,
            cap_bytes: 1_000,
            consumed_bytes: 0,
            issued_at: 0,
            expires_at: MAX_QUOTA_TOKEN_LIFETIME_SECS + 1,
            issuer: issuer_sk().public_key(),
            signature: SignatureBytes([0u8; SIGNATURE_LENGTH]),
        };
        let err = tok.canonical_signing_bytes().unwrap_err();
        assert!(
            matches!(err, Error::OverlongTurnCredential { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn quota_remaining_bytes_saturates_to_zero() {
        let tok = sample_quota();
        // consumed_bytes = 1 GiB, cap = 5 GiB → 4 GiB headroom.
        let four_gib = 4 * 1024 * 1024 * 1024;
        assert_eq!(tok.remaining_bytes(0), four_gib);
        // Burn through the headroom plus a billion bytes — the function
        // saturates rather than panicking on underflow.
        assert_eq!(tok.remaining_bytes(four_gib + 1_000_000_000), 0);
    }

    #[test]
    fn quota_would_exceed_at_exact_boundary() {
        let tok = sample_quota();
        let four_gib = 4 * 1024 * 1024 * 1024_u64;
        // Right at the cap is *not* an exceedance.
        assert!(!tok.would_exceed(four_gib, 0));
        assert!(!tok.would_exceed(four_gib - 1, 1));
        // One byte over.
        assert!(tok.would_exceed(four_gib, 1));
    }

    #[test]
    fn quota_json_roundtrip() {
        let tok = sample_quota();
        let json = serde_json::to_string(&tok).expect("serialize");
        let back: QuotaToken = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(tok, back);
    }

    #[test]
    fn signature_bytes_base64url_roundtrip() {
        let sb = SignatureBytes([0xABu8; SIGNATURE_LENGTH]);
        let s = sb.to_base64url();
        let back = SignatureBytes::from_base64url(&s).unwrap();
        assert_eq!(sb, back);
    }

    #[test]
    fn signature_bytes_base64url_rejects_wrong_length() {
        // 4 bytes of base64url (3 raw bytes) cannot be a 64-byte sig.
        let err = SignatureBytes::from_base64url("AAAA").unwrap_err();
        assert!(
            matches!(err, Error::InvalidTurnCredential(_)),
            "got: {err:?}"
        );
    }

    #[test]
    fn credential_canonical_domain_separator_differs_from_quota() {
        let c = sample_credential();
        let q = sample_quota();
        let cb = c.canonical_signing_bytes().unwrap();
        let qb = q.canonical_signing_bytes().unwrap();
        // The first byte (encoding tag) is identical, but the domain
        // string immediately afterward MUST differ — that is what makes
        // a signature uniquely bind to its artifact type.
        assert_ne!(&cb[1..1 + CREDENTIAL_DOMAIN.len()], QUOTA_DOMAIN);
        assert_ne!(&qb[1..1 + QUOTA_DOMAIN.len()], CREDENTIAL_DOMAIN);
    }
}
