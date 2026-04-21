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
//! - [`parse_host_record`] — structurally decode the main `_openhost`
//!   record from packet bytes. **Does not verify the signature** —
//!   used when JS wants to render a preview ("we found a pkarr record
//!   for this pubkey, here's what it claims") before paying the
//!   crypto-verify cost.
//! - [`decode_and_verify`] — combined decode + Ed25519-verify +
//!   2-hour-freshness pass. This is the recommended export for any
//!   JS caller that's going to trust the returned record. Folds
//!   `parse_host_record` + `SignedRecord::verify` into a single
//!   parse so the browser doesn't deserialize the packet twice.
//! - [`decode_offer`] — pull a sealed offer record out of a daemon's
//!   packet (used by the dialer's offer-poll loop).
//! - [`decode_answer_fragments`] — reassemble + return the fragmented
//!   `_answer-<client-hash>-<idx>` records published by a daemon for
//!   this client (PR #15's fragment codec). Returns raw sealed bytes;
//!   the WASM shim is not trusted to see the client's X25519 key.

pub mod core;

use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Install a panic hook that writes every Rust panic as a
/// `console.error` in the host JS context. Without this, a panicking
/// `#[wasm_bindgen]` export surfaces to JS as the generic
/// `RuntimeError: unreachable` with no message, defeating
/// diagnostics. Idempotent — hookless harm if called many times.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

fn to_js<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsError> {
    serde_wasm_bindgen::to_value(value)
        .map_err(|e| JsError::new(&format!("JS serialization failed: {e}")))
}

fn to_js_err<E: std::fmt::Display>(e: &E) -> JsError {
    JsError::new(&e.to_string())
}

/// Structurally decode a pkarr packet into its `_openhost` main
/// record.
///
/// `packet_bytes` — raw bytes returned by a relay (the HTTP response
/// body from `GET /<zbase32-pubkey>` against a public Pkarr relay).
/// `pubkey_zbase32` — the zbase32 form of the host's Ed25519 pubkey
/// the caller asked about. Returned back on the record for
/// convenience.
///
/// **Does not verify the signature or freshness.** Use
/// [`decode_and_verify`] whenever the returned record will be trusted
/// to pick a connection endpoint. Returns a JS object matching
/// [`core::HostRecord`].
#[wasm_bindgen]
pub fn parse_host_record(packet_bytes: &[u8], pubkey_zbase32: &str) -> Result<JsValue, JsError> {
    let out = core::parse_host_record(packet_bytes, pubkey_zbase32).map_err(|e| to_js_err(&e))?;
    to_js(&out)
}

/// Decode + verify a pkarr packet in one pass.
///
/// Runs the same decode as [`parse_host_record`], then the Ed25519
/// signature check + 2-hour freshness window. Returns the decoded
/// record on success. On failure, the returned `JsError` message
/// distinguishes structural-parse failures (malformed TXT, base64
/// error) from verification failures ("record verify failed: ...") so
/// JS can branch on the message prefix today; a structured error
/// union is planned for PR #28.3.
///
/// `now_ts` is the caller's current Unix timestamp (seconds). Use
/// `Math.floor(Date.now() / 1000)` on the JS side; the shim enforces
/// the spec's 2-hour window around this value.
#[wasm_bindgen]
pub fn decode_and_verify(
    packet_bytes: &[u8],
    pubkey_zbase32: &str,
    now_ts: u64,
) -> Result<JsValue, JsError> {
    let out =
        core::decode_and_verify(packet_bytes, pubkey_zbase32, now_ts).map_err(|e| to_js_err(&e))?;
    to_js(&out)
}

/// Look up the sealed offer record (if any) inside a daemon's pkarr
/// packet. Returns `Ok(null)` when the packet carries no offer TXT
/// for this daemon — the routine "no new offer yet" case for dialer
/// poll loops.
#[wasm_bindgen]
pub fn decode_offer(packet_bytes: &[u8], daemon_pk_zbase32: &str) -> Result<JsValue, JsError> {
    let out = core::decode_offer(packet_bytes, daemon_pk_zbase32).map_err(|e| to_js_err(&e))?;
    to_js(&out)
}

/// Reassemble + return the fragmented answer record addressed to
/// `client_pk_zbase32` from inside a daemon's pkarr packet.
///
/// See `spec/01-wire-format.md §3.3` for the fragment envelope. This
/// function does NOT unseal — it returns the raw sealed ciphertext
/// (concatenated across fragments) so the caller can run sealed-box
/// open with the client's X25519 private key, which the WASM
/// extension is not trusted to see. Returns `Ok(null)` when no
/// fragment set for this client is present.
#[wasm_bindgen]
pub fn decode_answer_fragments(
    packet_bytes: &[u8],
    daemon_salt: &[u8],
    client_pk_zbase32: &str,
    daemon_pk_zbase32: &str,
) -> Result<JsValue, JsError> {
    let out = core::decode_answer_fragments(
        packet_bytes,
        daemon_salt,
        client_pk_zbase32,
        daemon_pk_zbase32,
    )
    .map_err(|e| to_js_err(&e))?;
    to_js(&out)
}

// ============================================================================
// Phase 4: browser-dialer primitives (PR #28.3)
// ============================================================================

/// Seal a client offer plaintext to the daemon's X25519 pubkey.
/// Returns the raw sealed bytes; JS base64url-encodes them for the
/// Pkarr relay PUT.
///
/// Internally extracts the compact v3 offer blob from the raw SDP
/// `RTCPeerConnection.createOffer()` produced — JS never sees the
/// blob structure. The v3 blob reduces a Chrome-generated ~1100-byte
/// SDP to a ~130-byte body so the sealed packet fits under BEP44's
/// 1000-byte cap.
///
/// `binding_mode_u8` MUST be `0x02` (CertFp) for browser calls.
#[wasm_bindgen]
pub fn seal_offer(
    daemon_pk_zbase32: &str,
    client_pk_zbase32: &str,
    offer_sdp: &str,
    binding_mode_u8: u8,
) -> Result<Vec<u8>, JsError> {
    core::seal_offer(
        daemon_pk_zbase32,
        client_pk_zbase32,
        offer_sdp,
        binding_mode_u8,
    )
    .map_err(|e| to_js_err(&e))
}

/// Given a raw offer SDP, return the canonical reconstructed SDP the
/// daemon will build from the extracted v3 blob. Use this on the JS
/// side to compute an `offer_sdp_hash` that matches what the daemon
/// will hash on its end — the answer's binding hash is over the
/// reconstructed form, not the browser's raw SDP.
#[wasm_bindgen]
pub fn canonicalize_offer_sdp(offer_sdp: &str, binding_mode_u8: u8) -> Result<String, JsError> {
    core::canonicalize_offer_sdp(offer_sdp, binding_mode_u8).map_err(|e| to_js_err(&e))
}

/// Open an answer ciphertext with the client's 32-byte secret key and
/// return a reconstructed SDP ready for
/// `RTCPeerConnection.setRemoteDescription`. Handles both v1 and v2
/// answer shapes transparently — see [`core::open_answer`] for the
/// format description.
///
/// `host_dtls_fp_hex` is the lowercase-hex 64-char encoding of the
/// host's SHA-256 DTLS certificate fingerprint, derived from the
/// already-resolved pkarr `_openhost` record on the JS side
/// (`record.dtls_fingerprint_hex`). Ignored for legacy v1 answers;
/// required for v2.
#[wasm_bindgen]
pub fn open_answer(
    client_sk_bytes: &[u8],
    sealed_base64url: &str,
    host_dtls_fp_hex: &str,
) -> Result<JsValue, JsError> {
    let out = core::open_answer(client_sk_bytes, sealed_base64url, host_dtls_fp_hex)
        .map_err(|e| to_js_err(&e))?;
    to_js(&out)
}

/// Compute 32 AUTH bytes for a browser dial's CertFp channel binding.
/// Feeds [`sign_auth_client`] + [`verify_auth_host`].
#[wasm_bindgen]
pub fn compute_cert_fp_binding(
    cert_der: &[u8],
    host_pk_zbase32: &str,
    client_pk_zbase32: &str,
    nonce_bytes: &[u8],
) -> Result<Vec<u8>, JsError> {
    core::compute_cert_fp_binding(cert_der, host_pk_zbase32, client_pk_zbase32, nonce_bytes)
        .map(|arr| arr.to_vec())
        .map_err(|e| to_js_err(&e))
}

/// Produce the AUTH_CLIENT payload (96 bytes: 32B client_pk ||
/// 64B Ed25519 sig over `auth_bytes`).
#[wasm_bindgen]
pub fn sign_auth_client(client_sk_bytes: &[u8], auth_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    core::sign_auth_client(client_sk_bytes, auth_bytes).map_err(|e| to_js_err(&e))
}

/// Verify the daemon's AUTH_HOST 64-byte signature against
/// `auth_bytes` under `host_pk`. Returns a `bool`.
#[wasm_bindgen]
pub fn verify_auth_host(
    host_pk_zbase32: &str,
    auth_bytes: &[u8],
    signature_64b: &[u8],
) -> Result<bool, JsError> {
    core::verify_auth_host(host_pk_zbase32, auth_bytes, signature_64b).map_err(|e| to_js_err(&e))
}

/// Encode one wire frame for the data channel.
#[wasm_bindgen]
pub fn encode_frame(frame_type_u8: u8, payload: Vec<u8>) -> Result<Vec<u8>, JsError> {
    core::encode_frame(frame_type_u8, payload).map_err(|e| to_js_err(&e))
}

/// Try to decode one frame from the front of `buf`. Returns JS `null`
/// on incomplete buffer; a `DecodedFrame` object otherwise.
#[wasm_bindgen]
pub fn decode_frame(buf: &[u8]) -> Result<JsValue, JsError> {
    let out = core::decode_frame(buf).map_err(|e| to_js_err(&e))?;
    to_js(&out)
}

/// Derive the client's zbase32 Ed25519 pubkey from its 32-byte seed.
#[wasm_bindgen]
pub fn client_pubkey_from_seed(seed_bytes: &[u8]) -> Result<String, JsError> {
    core::client_pubkey_from_seed(seed_bytes).map_err(|e| to_js_err(&e))
}

/// Assemble a serialized Pkarr `SignedPacket` carrying the client's
/// offer TXT, ready for `PUT https://<relay>/<client-pk-zbase32>`.
#[wasm_bindgen]
pub fn build_offer_packet(
    client_sk_bytes: &[u8],
    daemon_pk_zbase32: &str,
    sealed_offer: &[u8],
    now_ts: u64,
) -> Result<Vec<u8>, JsError> {
    core::build_offer_packet(client_sk_bytes, daemon_pk_zbase32, sealed_offer, now_ts)
        .map_err(|e| to_js_err(&e))
}
