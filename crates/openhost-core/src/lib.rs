#![deny(unsafe_code)]
#![warn(missing_docs)]
//! Core types, wire format, and cryptographic primitives for the openhost protocol.
//!
//! Module layout (populated in M1):
//!
//! - [`identity`] — Ed25519 keypair generation and z-base-32 encoding.
//! - [`crypto`] — HKDF, sealed-box, channel-binding primitives.
//! - [`pkarr_record`] — signed DNS packet construction and verification.
//! - [`wire`] — HTTP-over-DataChannel framing.

pub mod identity {
    //! Ed25519 identity types. Populated in M1.
}

pub mod crypto {
    //! Cryptographic primitives used by the openhost protocol. Populated in M1.
}

pub mod pkarr_record {
    //! Pkarr record serialization, signing, and verification. Populated in M1.
}

pub mod wire {
    //! HTTP-over-DataChannel framing as specified in `spec/01-wire-format.md`. Populated in M1.
}
