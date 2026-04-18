//! Errors raised by `openhost-client`.

use openhost_core::Error as CoreError;
use openhost_pkarr::PkarrError;
use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, ClientError>;

/// Errors raised by the client library.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Input `oh://…` URL failed to parse.
    #[error("invalid openhost URL: {0}")]
    InvalidUrl(#[from] CoreError),

    /// Underlying `openhost-pkarr` error — includes `NotFound`, stale
    /// records, seq regression, timestamp drift, and signature failures.
    #[error(transparent)]
    Pkarr(#[from] PkarrError),

    /// The pkarr crate failed to build a `Client` from the configured
    /// relays. Typically a malformed relay URL.
    #[error("failed to build pkarr client: {0}")]
    ClientBuild(String),
}
