//! Errors raised by `openhost-daemon`.
//!
//! Each module owns a sub-error variant so the surface that a binary `main`
//! sees collapses to a single [`DaemonError`] enum.

use std::path::PathBuf;
use thiserror::Error;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, DaemonError>;

/// Top-level error for the openhost daemon.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// Config file could not be loaded or validated.
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// The identity keystore failed.
    #[error(transparent)]
    KeyStore(#[from] KeyStoreError),

    /// DTLS certificate generation or load failed.
    #[error(transparent)]
    Cert(#[from] CertError),

    /// The pkarr publisher failed.
    #[error(transparent)]
    Publish(#[from] PublishError),

    /// Low-level I/O failure not caught by a more specific variant.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Config-loading failures.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Could not open or read the config file.
    #[error("failed to read config at {path}: {source}")]
    Read {
        /// Path we tried to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// TOML parse error.
    #[error("failed to parse config at {path}: {source}")]
    Parse {
        /// Path we tried to parse.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },

    /// Required field is absent or a value is nonsensical.
    #[error("invalid config: {0}")]
    Invalid(&'static str),

    /// A relay URL in `pkarr.relays` was not parseable.
    #[error("invalid relay URL {url:?}: must start with https://")]
    InvalidRelayUrl {
        /// The offending URL.
        url: String,
    },
}

/// Identity keystore failures.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// Generic I/O error while reading or writing the identity file.
    #[error("keystore io error: {0}")]
    Io(#[from] std::io::Error),

    /// The on-disk identity file was the wrong size.
    #[error("identity file has {got} bytes, expected 32")]
    WrongSize {
        /// Byte count we actually read.
        got: usize,
    },
}

/// DTLS certificate failures.
#[derive(Debug, Error)]
pub enum CertError {
    /// `rcgen` failed to generate a keypair or self-sign the cert.
    #[error("rcgen error: {0}")]
    Rcgen(#[from] rcgen::Error),

    /// I/O error while reading or writing the cert file.
    #[error("cert io error: {0}")]
    Io(#[from] std::io::Error),

    /// Persisted cert file did not contain both a PRIVATE KEY and a CERTIFICATE
    /// PEM block.
    #[error("cert file is missing a {0} PEM block")]
    MissingPemBlock(&'static str),
}

/// Publisher failures.
#[derive(Debug, Error)]
pub enum PublishError {
    /// Underlying `openhost-pkarr` error.
    #[error(transparent)]
    Pkarr(#[from] openhost_pkarr::PkarrError),

    /// The pkarr crate failed to build a `Client` from the configured relays.
    #[error("failed to build pkarr client: {0}")]
    ClientBuild(String),

    /// Publisher state mutex was poisoned.
    #[error("publisher shared-state lock was poisoned")]
    Poisoned,
}
