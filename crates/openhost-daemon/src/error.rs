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

    /// The WebRTC listener failed.
    #[error(transparent)]
    Listener(#[from] ListenerError),

    /// The localhost forwarder failed.
    #[error(transparent)]
    Forward(#[from] ForwardError),

    /// The offer-record poller failed.
    #[error(transparent)]
    OfferPoll(#[from] OfferPollError),

    /// Pairing-database operation failed.
    #[error(transparent)]
    Pairing(#[from] crate::pairing::PairingError),

    /// Pair-DB file-watcher spawn or run failed (PR #17).
    #[error(transparent)]
    PairWatcher(#[from] PairWatcherError),

    /// Low-level I/O failure not caught by a more specific variant.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Embedded TURN relay spawn or misconfiguration (PR #42.2).
    #[error("turn relay error: {0}")]
    Turn(String),
}

/// Pair-DB file-watcher failures.
#[derive(Debug, Error)]
pub enum PairWatcherError {
    /// The pair-DB path is structurally unusable (no parent directory,
    /// no filename).
    #[error("pair-DB path is invalid: {0}")]
    BadPath(&'static str),

    /// I/O error while preparing the watcher (creating the parent
    /// directory, stat, etc.).
    #[error("pair watcher io: {0}")]
    Io(#[from] std::io::Error),

    /// The backend (inotify / FSEvents / ReadDirectoryChangesW) refused
    /// to set up a watch.
    #[error("pair watcher backend refused {path}: {source}")]
    Backend {
        /// Path the backend was asked to watch.
        path: PathBuf,
        /// Underlying notify error.
        #[source]
        source: notify_debouncer_mini::notify::Error,
    },

    /// Could not spawn the sync-to-async bridge thread.
    #[error("pair watcher thread spawn: {0}")]
    ThreadSpawn(std::io::Error),
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

    /// `webrtc` rejected the PEM bundle or failed to wrap a `rcgen::KeyPair`.
    #[error("webrtc cert error: {0}")]
    Webrtc(String),

    /// `RTCCertificate::get_fingerprints()` did not return a sha-256 entry,
    /// or the entry wasn't 32 bytes after colon-hex decode.
    #[error("DTLS cert sha-256 fingerprint is malformed or missing")]
    BadFingerprint,
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
}

/// Localhost forwarder failures.
#[derive(Debug, Error)]
pub enum ForwardError {
    /// The configured `forward.target` could not be parsed as an HTTP URI.
    #[error("forward.target is not a valid http:// URL: {0}")]
    TargetParse(String),

    /// Inbound `REQUEST_HEAD` payload is malformed (not valid HTTP/1.1
    /// text, unsupported method, wrong HTTP version, etc.).
    #[error("inbound request head is malformed: {0}")]
    HeadParse(&'static str),

    /// Inbound request body exceeded the configured
    /// `forward.max_body_bytes` cap.
    #[error("request body exceeded {cap} byte cap")]
    BodyTooLarge {
        /// The configured maximum in bytes.
        cap: usize,
    },

    /// Request asserts `Upgrade: websocket` but no `[forward.websockets]`
    /// allowlist is configured, or the target path is not on it. Operators
    /// who want to allow WebSocket upgrades per spec §4.2 must add the
    /// path (or `"*"`) to `forward.websockets.allowed_paths`.
    #[error("Upgrade: websocket rejected — target path not on forward.websockets.allowed_paths")]
    WebSocketUnsupported,

    /// Upstream refused the connection, timed out, or returned an
    /// unrecoverable protocol error.
    #[error("upstream request failed: {0}")]
    UpstreamUnreachable(String),

    /// Upstream response is something the forwarder cannot translate
    /// into the openhost frame codec (e.g. a `101 Switching Protocols`
    /// where we don't support the upgrade, or a response head that
    /// exceeds `MAX_PAYLOAD_LEN` after sanitisation).
    #[error("upstream response cannot be forwarded: {0}")]
    UpstreamResponse(&'static str),
}

/// WebRTC listener failures.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// `RTCCertificate::from_pem` rejected our persisted PEM bundle.
    /// Indicates the PEM bundle was corrupted after `dtls_cert::load_or_generate`
    /// validated it — very unlikely in practice.
    #[error("failed to load DTLS certificate: {0}")]
    CertLoad(String),

    /// Inbound offer SDP wasn't parseable at the text layer. The spec
    /// requires `a=setup:active` on client-side SDP; anything else is
    /// rejected here without ever building a `RTCPeerConnection`.
    #[error("offer SDP is malformed: {0}")]
    OfferParse(&'static str),

    /// Inbound offer asserted a DTLS role other than `setup:active`.
    /// Per `spec/01-wire-format.md §3.1`, the client **MUST** assert
    /// `a=setup:active` and receivers **MUST** reject mismatches.
    #[error("inbound offer asserts a=setup:{found:?} but spec mandates a=setup:active")]
    SetupRoleMismatch {
        /// The value we saw on the offer (`passive`, `actpass`, etc.).
        found: String,
    },

    /// Underlying `webrtc` crate error (SDP apply, ICE, DTLS handshake).
    #[error("webrtc error: {0}")]
    Webrtc(#[from] webrtc::Error),

    /// `handle_offer` exceeded its timeout budget — usually a peer that
    /// stopped trickling ICE candidates mid-handshake.
    #[error("handle_offer timed out after {secs} s")]
    Timeout {
        /// Budget, in seconds.
        secs: u64,
    },
}

/// Offer-record poller failures (PR #7a).
#[derive(Debug, Error)]
pub enum OfferPollError {
    /// Decrypting a sealed offer failed — the record was not addressed
    /// to this daemon or was corrupted by a substrate.
    #[error("failed to open sealed offer: {0}")]
    Decrypt(String),

    /// Building or sealing an answer entry failed.
    #[error("failed to build answer record: {0}")]
    AnswerBuild(String),

    /// The underlying `openhost-pkarr` layer reported an error.
    #[error(transparent)]
    Pkarr(#[from] openhost_pkarr::PkarrError),

    /// `PassivePeer::handle_offer` rejected the SDP.
    #[error(transparent)]
    Handshake(#[from] ListenerError),
}
