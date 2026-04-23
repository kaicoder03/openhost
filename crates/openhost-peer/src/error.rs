//! Error type for `openhost-peer`.

use thiserror::Error;

/// Alias for `Result<T, PeerError>`.
pub type Result<T> = std::result::Result<T, PeerError>;

/// Errors surfaced by the peer-pairing layer.
#[derive(Debug, Error)]
pub enum PeerError {
    /// A pairing code supplied by the user could not be parsed.
    /// The wrapped message is safe to surface to users — it
    /// describes the FORMAT problem, not the secret itself.
    #[error("invalid pairing code: {0}")]
    InvalidCode(String),

    /// An AEAD seal / open step failed. Intentionally opaque — we do
    /// not leak the underlying reason to avoid padding / timing
    /// oracles on the envelope.
    #[error("crypto: {0}")]
    Crypto(&'static str),
}
