#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Pkarr integration for openhost.
//!
//! Wraps the upstream `pkarr` crate with openhost-specific record schemas,
//! relay/DHT fan-out, and (optional) Nostr tertiary-substrate publishing.
//! Populated in M2.
