#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

//! wasm-bindgen shim over the resolver-side decode functions in
//! [`openhost_pkarr`].
//!
//! The browser extension's service worker fetches pkarr packets via the
//! browser's native [`fetch`][mdn-fetch] API (relays are served over
//! plain HTTPS, so JS handles TLS, CORS, and HTTP/2 without help), then
//! hands the returned bytes to one of the four exports below for pure
//! sync parsing + crypto verification. No tokio, no `reqwest`, no
//! `pkarr::Client` — every import resolves under the `resolver-only`
//! feature of `openhost-pkarr`.
//!
//! [mdn-fetch]: https://developer.mozilla.org/en-US/docs/Web/API/fetch
//!
//! # Two-tier layout
//!
//! The crate is split into two tiers to keep host-target tests
//! callable without a wasm runtime:
//!
//! - [`core`] (private module) — plain Rust functions returning
//!   plain Rust DTOs. No `JsValue`, no `wasm-bindgen`. This is where
//!   the actual decode/verify logic lives and where the unit tests
//!   plug in.
//! - The `#[wasm_bindgen]` exports at crate root — thin wrappers that
//!   translate the core tier's DTOs into `JsValue`. Off-target these
//!   wrappers panic (wasm-bindgen's intrinsics aren't available), so
//!   tests call the core tier directly.
//!
//! # Exports
//!
//! - [`decode_host_record`] — parse + shape-check the main `_openhost`
//!   record. Does NOT verify the signature; callers get the raw
//!   decoded fields back and can present them to the user before
//!   paying the crypto-verify cost.
//! - [`verify_record`] — deterministic Ed25519 verify. Returns `true`
//!   on a good signature + fresh `ts`, `false` otherwise. Separated
//!   from decode so JS can stage the two without re-parsing.
//! - [`decode_offer`] — pull a sealed offer record out of a daemon's
//!   packet (used by the dialer's offer-poll loop).
//! - [`decode_answer_fragments`] — reassemble + return the fragmented
//!   `_answer-<client-hash>-<idx>` records published by a daemon for
//!   this client (PR #15's fragment codec). Returns raw sealed bytes;
//!   the WASM shim is not trusted to see the client's X25519 key.

pub mod core;

use serde::Serialize;
use wasm_bindgen::prelude::*;

fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|e| JsError::new(&format!("JS serialization failed: {e}")))
}

/// Decode a pkarr packet into its `_openhost` main record.
///
/// `packet_bytes` — raw bytes returned by a relay (the HTTP response
/// body from `GET /<zbase32-pubkey>` against a public Pkarr relay).
/// `pubkey_zbase32` — the zbase32 form of the host's Ed25519 pubkey
/// the caller asked about. Returned back on the record for
/// convenience. `now_ts` — caller's current Unix timestamp (seconds).
/// Not used for verification here (see [`verify_record`]); exposed on
/// the signature so future shape checks can be folded in.
///
/// Returns a JS object matching [`core::HostRecord`].
#[wasm_bindgen]
pub fn decode_host_record(
    packet_bytes: &[u8],
    pubkey_zbase32: &str,
    _now_ts: u64,
) -> Result<JsValue, JsError> {
    let out = core::decode_host_record(packet_bytes, pubkey_zbase32, _now_ts)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    to_js(&out)
}

/// Verify the inner Ed25519 signature + 2-hour freshness window on a
/// pkarr packet's `_openhost` record.
///
/// Returns `true` when the record is structurally valid, its `ts` is
/// within the freshness window around `now_ts`, and the signature
/// over the canonical bytes verifies against `pubkey_zbase32`.
/// Returns `false` when decode succeeds but verification fails — JS
/// can treat `false` as "retry another relay" without special error
/// handling. Structural/parse errors surface as `JsError`.
#[wasm_bindgen]
pub fn verify_record(
    packet_bytes: &[u8],
    pubkey_zbase32: &str,
    now_ts: u64,
) -> Result<bool, JsError> {
    core::verify_record(packet_bytes, pubkey_zbase32, now_ts)
        .map_err(|e| JsError::new(&format!("{e}")))
}

/// Look up the sealed offer record (if any) inside a daemon's pkarr
/// packet. Returns `Ok(None)` when the packet carries no offer TXT
/// for this daemon — the routine "no new offer yet" case for dialer
/// poll loops.
#[wasm_bindgen]
pub fn decode_offer(packet_bytes: &[u8], daemon_pk_zbase32: &str) -> Result<JsValue, JsError> {
    let out = core::decode_offer(packet_bytes, daemon_pk_zbase32)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    to_js(&out)
}

/// Reassemble + return the fragmented answer record addressed to
/// `client_pk_zbase32` from inside a daemon's pkarr packet.
///
/// See `spec/01-wire-format.md §3.3` for the fragment envelope. This
/// function does NOT unseal — it returns the raw sealed ciphertext
/// (concatenated across fragments) so the caller can run sealed-box
/// open with the client's X25519 private key, which the WASM
/// extension is not trusted to see. Returns `Ok(None)` when no
/// fragment set for this client is present.
#[wasm_bindgen]
pub fn decode_answer_fragments(
    packet_bytes: &[u8],
    daemon_salt: &[u8],
    client_pk_zbase32: &str,
) -> Result<JsValue, JsError> {
    let out = core::decode_answer_fragments(packet_bytes, daemon_salt, client_pk_zbase32)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    to_js(&out)
}
