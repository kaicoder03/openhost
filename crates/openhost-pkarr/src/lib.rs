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
pub mod publisher;
pub mod relays;
pub mod resolver;

pub use codec::{
    decode, encode, packet_public_key, BEP44_MAX_V_BYTES, MICROS_PER_SECOND, OPENHOST_TXT_NAME,
    OPENHOST_TXT_TTL,
};
pub use error::{PkarrError, Result};
pub use publisher::{
    PkarrTransport, Publisher, PublisherHandle, RecordSource, Transport, REPUBLISH_INTERVAL,
};
pub use relays::DEFAULT_RELAYS;
pub use resolver::{PkarrResolve, Resolve, Resolver};
