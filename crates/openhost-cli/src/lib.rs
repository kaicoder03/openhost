//! `openhost-cli` — the `oh` command-line interface for peer-to-peer
//! file transfer over openhost.
//!
//! Binary is at `src/bin/oh.rs`; library modules keep the send and
//! recv paths testable in isolation.

#![deny(unsafe_code)]

pub mod display;
pub mod file_server;
pub mod recv;
pub mod send;
