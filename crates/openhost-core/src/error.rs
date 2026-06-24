//! Error types for openhost-core.
//!
//! Every fallible operation in this crate returns [`Result<T, Error>`].

use core::fmt;

/// A convenience alias for `Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// The umbrella error type for every operation in `openhost-core`.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A z-base-32 encoded string could not be decoded, or produced bytes of the wrong length.
    InvalidIdentityEncoding(&'static str),

    /// A URL is not a valid `oh://<pubkey>/<path>` URL.
    InvalidUrl(&'static str),

    /// An Ed25519 or X25519 key failed to parse from its bytes.
    InvalidKey(&'static str),

    /// An Ed25519 signature failed verification.
    BadSignature,

    /// A wire frame's header is malformed (unknown type code, length overflow, etc.).
    MalformedFrame(&'static str),

    /// A wire frame exceeded the maximum permitted payload length.
    OversizedFrame {
        /// Bytes requested by the frame header.
        requested: usize,
        /// Maximum permitted payload length.
        limit: usize,
    },

    /// A sealed-box open operation failed — ciphertext corrupt, wrong recipient, or truncated.
    DecryptionFailed,

    /// A Pkarr record's internal timestamp is outside the acceptance window.
    StaleRecord {
        /// Unix timestamp carried inside the signed record.
        record_ts: u64,
        /// Unix timestamp the verifier used as "now".
        now_ts: u64,
        /// Maximum permitted delta, in seconds.
        max_age_secs: u64,
    },

    /// A Pkarr record's TXT body does not match the openhost v1 schema.
    InvalidRecord(&'static str),

    /// Channel-binding verification failed.
    ChannelBindingMismatch,

    /// Buffer was too short to hold the requested operation output.
    BufferTooSmall {
        /// Bytes actually provided.
        have: usize,
        /// Bytes needed.
        need: usize,
    },

    /// A TURN credential or quota token failed structural validation.
    InvalidTurnCredential(&'static str),

    /// A TURN credential or quota token has expired (`expires_at < now_ts`).
    ExpiredTurnCredential {
        /// `expires_at` carried inside the artifact.
        expires_at: u64,
        /// Verifier's current Unix timestamp.
        now_ts: u64,
    },

    /// A TURN credential or quota token's lifetime exceeds the protocol cap.
    OverlongTurnCredential {
        /// `expires_at - issued_at` from the artifact.
        lifetime_secs: u64,
        /// Maximum permitted lifetime in seconds.
        max_secs: u64,
    },

    /// A TURN credential or quota token is signed by a pubkey the verifier does not trust.
    UntrustedTurnIssuer,

    /// A TURN credential or quota token's `subject` does not match the verifier's pubkey.
    TurnSubjectMismatch,

    /// A TURN quota would be exceeded by the requested relayed-byte allocation.
    TurnQuotaExceeded {
        /// `cap_bytes` from the quota token.
        cap_bytes: u64,
        /// Total bytes that would be relayed if the request proceeded.
        would_consume: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidIdentityEncoding(ctx) => {
                write!(f, "invalid identity encoding: {ctx}")
            }
            Error::InvalidUrl(ctx) => write!(f, "invalid openhost URL: {ctx}"),
            Error::InvalidKey(ctx) => write!(f, "invalid key material: {ctx}"),
            Error::BadSignature => f.write_str("Ed25519 signature verification failed"),
            Error::MalformedFrame(ctx) => write!(f, "malformed wire frame: {ctx}"),
            Error::OversizedFrame { requested, limit } => write!(
                f,
                "oversized wire frame: {requested} bytes requested, limit is {limit}"
            ),
            Error::DecryptionFailed => f.write_str("sealed-box decryption failed"),
            Error::StaleRecord {
                record_ts,
                now_ts,
                max_age_secs,
            } => write!(
                f,
                "stale Pkarr record: ts={record_ts}, now={now_ts}, max_age_secs={max_age_secs}"
            ),
            Error::InvalidRecord(ctx) => write!(f, "invalid Pkarr record: {ctx}"),
            Error::ChannelBindingMismatch => {
                f.write_str("channel-binding HMAC did not match expected value")
            }
            Error::BufferTooSmall { have, need } => {
                write!(f, "buffer too small: have {have} bytes, need {need}")
            }
            Error::InvalidTurnCredential(ctx) => {
                write!(f, "invalid TURN credential: {ctx}")
            }
            Error::ExpiredTurnCredential { expires_at, now_ts } => write!(
                f,
                "expired TURN credential: expires_at={expires_at}, now={now_ts}"
            ),
            Error::OverlongTurnCredential {
                lifetime_secs,
                max_secs,
            } => write!(
                f,
                "TURN credential lifetime {lifetime_secs}s exceeds max {max_secs}s"
            ),
            Error::UntrustedTurnIssuer => {
                f.write_str("TURN credential issuer is not in the trusted set")
            }
            Error::TurnSubjectMismatch => {
                f.write_str("TURN credential subject does not match verifier pubkey")
            }
            Error::TurnQuotaExceeded {
                cap_bytes,
                would_consume,
            } => write!(
                f,
                "TURN quota exceeded: cap={cap_bytes} bytes, would_consume={would_consume} bytes"
            ),
        }
    }
}

impl std::error::Error for Error {}
