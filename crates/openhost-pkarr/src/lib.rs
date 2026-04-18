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
//! - [`relays`] — bundled default list of public Pkarr HTTP relays.
//! - [`error`] — crate-wide error type.

pub mod codec;
pub mod error;
pub mod publisher;
pub mod relays;

pub use codec::{
    decode, encode, packet_public_key, BEP44_MAX_V_BYTES, MICROS_PER_SECOND, OPENHOST_TXT_NAME,
    OPENHOST_TXT_TTL,
};
pub use error::{PkarrError, Result};
pub use publisher::{
    PkarrTransport, Publisher, PublisherHandle, RecordSource, Transport, REPUBLISH_INTERVAL,
};
pub use relays::DEFAULT_RELAYS;
