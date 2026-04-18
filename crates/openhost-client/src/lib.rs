#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! openhost client library.
//!
//! High-level API for reading openhost host records, consumed by the
//! browser extension (via WASM), the native apps (via `openhost-ffi`),
//! and the `openhost-resolve` debug CLI bundled in this crate under the
//! `cli` feature.
//!
//! PR #4 / M4.1 scope is **read-only**: [`Client::resolve`] takes an
//! `oh://…` URL and returns the decoded, validated [`SignedRecord`]. The
//! WebRTC offerer, ICE candidate decryption, and channel binding are
//! PR #8 work.
//!
//! Module map:
//!
//! - [`client`] — [`Client`] + [`ClientBuilder`], the public API.
//! - [`error`] — crate-wide error enum.

pub mod binding;
#[cfg(feature = "cli")]
pub mod cli;
pub mod client;
pub mod dialer;
pub mod error;
pub mod session;
mod webrtc_helpers;

pub use binding::{ClientBinder, ClientBindingError};
pub use client::{Client, ClientBuilder};
pub use dialer::{Dialer, DialerBuilder, DialerConfig};
pub use error::{ClientError, Result};
pub use session::{ClientResponse, OpenhostSession};

// Re-export identity types so callers don't have to pull
// `openhost-core` directly for the common case.
pub use openhost_core::identity::{OpenhostUrl, PublicKey, SigningKey};
pub use openhost_pkarr::DEFAULT_RELAYS;
