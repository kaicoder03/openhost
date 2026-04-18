//! Errors raised by `openhost-client`.

use crate::binding::ClientBindingError;
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

    /// Host pubkey could not be resolved — no pkarr record found or the
    /// decoded record failed validation. (`Pkarr` covers substrate-level
    /// failures; this variant is for higher-level "we couldn't get a
    /// usable record" errors from `Dialer::resolve_host`.)
    #[error("resolving host: {0}")]
    ResolveHost(&'static str),

    /// Publishing the sealed offer to the client's own pkarr zone
    /// failed. Typically an encoding issue or a `Transport` error.
    #[error("publishing offer: {0}")]
    PublishOffer(String),

    /// The daemon did not publish an `_answer-<client-hash>` TXT for
    /// this client within the configured timeout.
    #[error("no answer from host within {0} s")]
    PollAnswerTimeout(u64),

    /// The daemon published an answer packet but it failed to decode.
    #[error("answer decode failed: {0}")]
    AnswerDecode(String),

    /// The answer decoded but its inner `daemon_pk` or
    /// `offer_sdp_hash` didn't match what the client expected.
    /// Indicates a hostile substrate or a splice attempt.
    #[error("answer did not match the offer it claimed to respond to: {0}")]
    AnswerBindingMismatch(&'static str),

    /// The underlying `webrtc` crate rejected our setup or handshake.
    #[error("webrtc error: {0}")]
    WebRtcSetup(String),

    /// Channel-binding handshake failed on the client side.
    #[error(transparent)]
    ChannelBinding(#[from] ClientBindingError),

    /// The HTTP round-trip on the authenticated data channel failed —
    /// malformed response frames, SCTP send errors, or an `ERROR`
    /// frame from the host.
    #[error("http round-trip: {0}")]
    HttpRoundTrip(String),
}
