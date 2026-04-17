#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! Core types, wire format, and cryptographic primitives for the openhost protocol.
//!
//! This crate is runtime-agnostic: it does not touch sockets, filesystems, or the system
//! keychain. Higher-level crates (`openhost-daemon`, `openhost-client`, etc.) layer the
//! appropriate platform glue on top.
//!
//! Module map:
//!
//! - [`identity`] — Ed25519 keypairs, z-base-32 encoding, and `oh://` URL parsing.
//! - [`crypto`] — HKDF, sealed-box encryption, HMAC, and the RFC 8844 channel-binding
//!   construction used by the handshake.
//! - [`wire`] — HTTP-over-DataChannel framing as specified in `spec/01-wire-format.md` §4.
//! - [`pkarr_record`] — openhost v1 signed DNS record schema on top of Pkarr.
//!
//! Every module has matching test vectors under `spec/test-vectors/`. Implementations in
//! other languages are expected to pass the same vectors verbatim.

pub mod crypto;
pub mod error;
pub mod identity;
pub mod pkarr_record;
pub mod wire;

pub use error::{Error, Result};
