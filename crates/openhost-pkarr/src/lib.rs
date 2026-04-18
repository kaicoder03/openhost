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
//! - [`error`] — crate-wide error type.
//!
//! Additional modules (`publisher`, `resolver`, `relays`, optional `nostr`) are
//! added in subsequent M2 commits.

pub mod codec;
pub mod error;

pub use codec::{
    decode, encode, packet_public_key, BEP44_MAX_V_BYTES, MICROS_PER_SECOND, OPENHOST_TXT_NAME,
    OPENHOST_TXT_TTL,
};
pub use error::{PkarrError, Result};
