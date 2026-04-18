//! Errors raised by `openhost-pkarr`.

use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, PkarrError>;

/// Errors raised by the `openhost-pkarr` adapter.
#[derive(Debug, Error)]
pub enum PkarrError {
    /// The openhost-core layer reported an error (record validation, signing,
    /// canonical encoding).
    #[error(transparent)]
    Core(#[from] openhost_core::Error),

    /// The upstream pkarr crate failed to build a `SignedPacket` from the records
    /// we supplied.
    #[error("pkarr build error: {0}")]
    Build(#[from] pkarr::errors::SignedPacketBuildError),

    /// The upstream pkarr crate rejected a serialized packet.
    #[error("pkarr verify error: {0}")]
    Verify(#[from] pkarr::errors::SignedPacketVerifyError),

    /// The DNS packet produced by the encoder exceeded the 1000-byte BEP44
    /// mutable-item payload limit.
    #[error("signed packet payload is {size} bytes, exceeding the BEP44 1000-byte limit")]
    PacketTooLarge {
        /// Size of the encoded packet payload.
        size: usize,
    },

    /// The decoded `_openhost` TXT blob was shorter than the minimum 64-byte
    /// signature prefix.
    #[error("_openhost blob is {got} bytes, expected at least {min}")]
    BlobTooShort {
        /// Number of bytes actually present.
        got: usize,
        /// Minimum number of bytes required (64 for the signature prefix).
        min: usize,
    },

    /// The `_openhost` TXT record was missing from the packet.
    #[error("signed packet is missing the `_openhost` TXT record")]
    MissingOpenhostRecord,

    /// The base64url payload of the `_openhost` TXT record failed to decode.
    #[error("failed to base64url-decode the _openhost blob: {0}")]
    Base64(#[from] base64::DecodeError),

    /// The packet's BEP44 timestamp (in seconds) disagrees with the openhost
    /// record's internal `ts` field beyond the permitted 1-second drift.
    #[error("pkarr timestamp {packet_ts} drifts more than 1s from record.ts {record_ts}")]
    TimestampDrift {
        /// Timestamp reported by the pkarr packet header (seconds).
        packet_ts: u64,
        /// Timestamp embedded inside the openhost record (seconds).
        record_ts: u64,
    },

    /// The resolver was given a cached `seq` that is newer than what the
    /// substrate returned — the record has gone backwards.
    #[error("seq regression: record.ts={record_ts} < cached_seq={cached_seq}")]
    SeqRegression {
        /// Sequence number (record.ts) of the returned packet.
        record_ts: u64,
        /// Sequence number last observed by the caller.
        cached_seq: u64,
    },

    /// No substrate returned a packet for the requested public key.
    #[error("no signed packet found for the requested public key")]
    NotFound,

    /// The trailing canonical bytes inside the `_openhost` blob failed to parse
    /// into an `OpenhostRecord`.
    #[error("canonical bytes are malformed: {0}")]
    MalformedCanonical(&'static str),

    /// A TXT record we parsed was not valid UTF-8.
    #[error("TXT record is not valid UTF-8")]
    InvalidUtf8,

    /// An upstream pkarr publish failed (relays + DHT all reported errors or
    /// a compare-and-swap conflict rejected the write).
    #[error("pkarr publish error: {0}")]
    Publish(#[from] pkarr::errors::PublishError),
}
