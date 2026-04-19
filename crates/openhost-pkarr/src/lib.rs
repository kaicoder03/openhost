#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! Pkarr integration for openhost.
//!
//! Wraps the upstream `pkarr` crate with openhost-specific record schemas,
//! relay/DHT fan-out, and (optional) Nostr tertiary-substrate publishing.
//!
//! Module map:
//!
//! - [`codec`] — translate between
//!   [`openhost_core::pkarr_record::SignedRecord`] and [`pkarr::SignedPacket`].
//! - [`publisher`] — sign + encode + fan out to relays and the Mainline DHT on
//!   a 30-minute republish schedule.
//! - [`resolver`] — race relays + DHT, decode, verify freshness and
//!   `seq` monotonicity.
//! - [`relays`] — bundled default list of public Pkarr HTTP relays.
//! - `nostr` (feature `nostr`) — optional NIP-78 envelope builder for the
//!   tertiary Nostr substrate. Envelope-only; no WebSocket publish.
//! - [`error`] — crate-wide error type.

pub mod codec;
pub mod error;
#[cfg(feature = "nostr")]
pub mod nostr;
pub mod offer;
#[cfg(feature = "full")]
pub mod publisher;
pub mod relays;
#[cfg(feature = "full")]
pub mod resolver;

#[cfg(test)]
pub(crate) mod test_support;

/// In-memory pkarr substrate for end-to-end tests (PR #8). Gated
/// behind the `test-fakes` feature so it never ships in release
/// builds.
#[cfg(any(test, feature = "test-fakes"))]
pub mod test_fakes;

#[cfg(any(test, feature = "test-fakes"))]
pub use test_fakes::MemoryPkarrNetwork;

#[cfg(feature = "full")]
pub use codec::encode;
pub use codec::{
    decode, packet_public_key, BEP44_MAX_V_BYTES, MICROS_PER_SECOND, OPENHOST_TXT_NAME,
    OPENHOST_TXT_TTL,
};
// Re-export the pkarr types callers need to invoke `decode` + the
// offer/answer decoders. Saves downstream crates (notably
// `openhost-pkarr-wasm`) from having to pin `pkarr` as a direct dep
// just to name the `SignedPacket` parameter type.
pub use error::{PkarrError, Result};
pub use offer::{
    answer_blob_to_sdp, answer_txt_chunk_name, answer_txt_name, client_hash_label,
    decode_answer_fragments_from_packet, decode_offer_from_packet, encode_answer_blob,
    encode_offer_blob, encode_with_answers, extract_sha256_fingerprint_from_sdp, hash_offer_sdp,
    host_hash, host_hash_label, offer_blob_to_sdp, offer_txt_name, parse_answer_blob,
    parse_offer_blob, sdp_to_offer_blob, AnswerBlob, AnswerEntry, AnswerPayload, AnswerPlaintext,
    BindingMode, BlobCandidate, CandidateType, OfferBlob, OfferPayload, OfferPlaintext,
    OfferRecord, SetupRole, ANSWER_INNER_DOMAIN_V1, ANSWER_INNER_DOMAIN_V2, ANSWER_TXT_PREFIX,
    CLIENT_HASH_LEN, DTLS_FP_LEN, HOST_HASH_LEN, MAX_ANSWER_BLOB_LEN, MAX_BLOB_CANDIDATES,
    MAX_FRAGMENT_PAYLOAD_BYTES, MAX_FRAGMENT_TOTAL, MAX_OFFER_BLOB_LEN, OFFER_INNER_DOMAIN_V1,
    OFFER_INNER_DOMAIN_V2, OFFER_INNER_DOMAIN_V3, OFFER_SDP_HASH_LEN, OFFER_TXT_PREFIX,
    OFFER_TXT_TTL,
};
pub use pkarr::SignedPacket;
#[cfg(feature = "full")]
pub use publisher::{
    AnswerSource, InitialPublishOutcome, PkarrTransport, Publisher, PublisherHandle, RecordSource,
    Transport, INITIAL_PUBLISH_ATTEMPTS, INITIAL_PUBLISH_BACKOFF, REPUBLISH_INTERVAL,
};
pub use relays::DEFAULT_RELAYS;
#[cfg(feature = "full")]
pub use resolver::{PkarrResolve, Resolve, Resolver, GRACE_WINDOW};
