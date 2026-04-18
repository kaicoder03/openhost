//! Errors raised by `openhost-client`.

use openhost_core::Error as CoreError;
use openhost_pkarr::PkarrError;
use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, ClientError>;

/// Errors raised by the client library.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Input `oh://…` URL failed to parse, or parsed but its host
    /// component isn't a canonical 32-byte Ed25519 public key.
    ///
    /// The embedded [`CoreError`] distinguishes between structural
    /// problems (`InvalidUrl("missing oh:// scheme")`) and cryptographic
    /// ones (`InvalidKey("Ed25519 public key is not a canonical point")`).
    /// Callers that only care about usage-vs-programming-error framing
    /// can treat the whole variant as "bad input."
    ///
    /// `#[error(transparent)]` so `Display` delegates to the inner error
    /// and `anyhow`'s source chain doesn't emit a duplicate.
    #[error(transparent)]
    UrlParse(#[from] CoreError),

    /// Underlying `openhost-pkarr` error — includes `NotFound`, stale
    /// records, seq regression, timestamp drift, and signature failures.
    #[error(transparent)]
    Pkarr(#[from] PkarrError),

    /// The pkarr crate failed to build a `Client` from the configured
    /// relays. Typically a malformed relay URL.
    #[error("failed to build pkarr client: {0}")]
    ClientBuild(String),
}
