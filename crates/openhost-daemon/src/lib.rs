#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! `openhost-daemon` — the host-side openhost process.
//!
//! This crate is the library backing the `openhostd` binary. Splitting the
//! two lets integration tests (and, later, embedding hosts like a macOS
//! menu-bar app) drive the daemon without shelling out.
//!
//! Module map:
//!
//! - [`config`] — TOML configuration schema + loader.
//! - [`identity_store`] — Ed25519 keypair persistence.
//! - [`dtls_cert`] — self-signed ECDSA P-256 cert for DTLS.
//! - [`publish`] — bridge to `openhost-pkarr::Publisher`.
//! - [`error`] — crate-wide error enum.
//!
//! Later PRs add `app` (top-level lifecycle), `signal` (graceful
//! shutdown), and a full WebRTC stack on top of this foundation.

pub mod app;
pub mod channel_binding;
pub mod config;
pub mod dtls_cert;
pub mod error;
pub mod forward;
pub mod identity_store;
pub mod listener;
pub mod publish;
pub mod signal;

pub use app::{init_tracing, App};
pub use channel_binding::{ChannelBinder, ChannelBindingError};
pub use config::Config;
pub use error::{DaemonError, Result};
pub use forward::{ForwardResponse, Forwarder};
pub use listener::PassivePeer;
