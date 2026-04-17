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
        }
    }
}

impl std::error::Error for Error {}
