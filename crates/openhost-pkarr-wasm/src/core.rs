//! Plain-Rust core tier of the wasm shim.
//!
//! Every function here takes byte slices / strings + returns plain
//! Rust DTOs, so it can be unit-tested on the host target without
//! dragging in a wasm-bindgen runtime. The `#[wasm_bindgen]` layer in
//! [`crate`] root wraps each of these with a `JsValue` translation
//! step.

use openhost_core::identity::PublicKey;
use openhost_core::pkarr_record::{SignedRecord, SALT_LEN};
use pkarr::SignedPacket;
use serde::Serialize;
use thiserror::Error;

/// Errors produced by the core tier. The `#[wasm_bindgen]` layer
/// stringifies these into `JsError`; a structured JS-side error
/// union is deferred to PR #28.3 (where the dialer state machine
/// needs to branch on specific error kinds).
#[derive(Debug, Error)]
pub enum Error {
    /// The zbase32 input did not decode to a 32-byte Ed25519 pubkey.
    #[error("invalid zbase32 pubkey: {0}")]
    InvalidPubkey(String),
    /// `daemon_salt` was not exactly [`SALT_LEN`] bytes.
    #[error("salt must be exactly {SALT_LEN} bytes")]
    SaltLength,
    /// `pkarr::SignedPacket::deserialize` rejected the raw relay
    /// bytes. This is also where the outer BEP44 signature check
    /// fires (pkarr verifies on deserialize).
    #[error("pkarr deserialize failed: {0}")]
    Packet(String),
    /// The openhost-pkarr resolver-layer decode failed (no
    /// `_openhost` TXT record, base64 decode error, etc.).
    #[error("decode failed: {0}")]
    Pkarr(#[from] openhost_pkarr::PkarrError),
}

/// Result alias over [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// JS-friendly view of a decoded `SignedRecord`. All byte arrays land
/// in JS as lowercase hex strings — Uint8Array conversion is a
/// two-line `Uint8Array.from(s.match(/../g).map(b => parseInt(b, 16)))`
/// on the caller side.
#[derive(Debug, Serialize)]
pub struct HostRecord {
    /// The zbase32 pubkey the caller asked about (echoed back so JS
    /// can key subsequent operations off a single object).
    pub pubkey_zbase32: String,
    /// Protocol version byte. Must equal `PROTOCOL_VERSION = 2` today.
    pub version: u8,
    /// Unix timestamp (seconds) at which the host published.
    pub ts: u64,
    /// SHA-256 fingerprint of the daemon's DTLS certificate, hex.
    pub dtls_fingerprint_hex: String,
    /// UTF-8 roles field (e.g. `"server"`).
    pub roles: String,
    /// Per-host random HMAC salt, hex.
    pub salt_hex: String,
    /// UTF-8 discovery hints.
    pub disc: String,
    /// 64-byte Ed25519 signature, hex. Use [`crate::verify_record`] to
    /// actually validate it.
    pub signature_hex: String,
}

/// JS-friendly offer record — base64url because that matches the
/// on-wire DNS TXT value (operators cross-referencing with a `dig`
/// tool see base64url there).
#[derive(Debug, Serialize)]
pub struct Offer {
    /// Sealed ciphertext, base64url-nopad (matches on-wire form).
    pub sealed_base64url: String,
}

/// JS-friendly answer record.
#[derive(Debug, Serialize)]
pub struct Answer {
    /// HMAC label identifying the client this answer is addressed to,
    /// hex-encoded.
    pub client_hash_hex: String,
    /// Reassembled sealed ciphertext (post-fragment-reassembly),
    /// base64url-nopad.
    pub sealed_base64url: String,
    /// Daemon-local creation timestamp. Not wire-visible; used for
    /// replay-ordering diagnostics.
    pub created_at: u64,
}

fn parse_pubkey(s: &str) -> Result<PublicKey> {
    PublicKey::from_zbase32(s).map_err(|e| Error::InvalidPubkey(e.to_string()))
}

fn parse_salt(bytes: &[u8]) -> Result<[u8; SALT_LEN]> {
    <[u8; SALT_LEN]>::try_from(bytes).map_err(|_| Error::SaltLength)
}

fn parse_packet(bytes: &[u8]) -> Result<SignedPacket> {
    SignedPacket::deserialize(bytes).map_err(|e| Error::Packet(e.to_string()))
}

fn base64_url_nopad(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn host_record_dto(pubkey_zbase32: &str, signed: &SignedRecord) -> HostRecord {
    let r = &signed.record;
    HostRecord {
        pubkey_zbase32: pubkey_zbase32.to_string(),
        version: r.version,
        ts: r.ts,
        dtls_fingerprint_hex: hex::encode(r.dtls_fp),
        roles: r.roles.clone(),
        salt_hex: hex::encode(r.salt),
        disc: r.disc.clone(),
        signature_hex: hex::encode(signed.signature.to_bytes()),
    }
}

/// Decode a pkarr packet into its `_openhost` main record. See the
/// wasm-bindgen wrapper at crate root for API documentation.
pub fn decode_host_record(
    packet_bytes: &[u8],
    pubkey_zbase32: &str,
    _now_ts: u64,
) -> Result<HostRecord> {
    // Validate the pubkey up-front — a garbage pubkey here is the
    // easiest bug to diagnose, so surface it before spending cycles
    // on packet deserialization.
    parse_pubkey(pubkey_zbase32)?;
    let packet = parse_packet(packet_bytes)?;
    let signed = openhost_pkarr::decode(&packet)?;
    Ok(host_record_dto(pubkey_zbase32, &signed))
}

/// Verify the inner Ed25519 signature + 2-hour freshness window. See
/// the wasm-bindgen wrapper at crate root for API documentation.
pub fn verify_record(packet_bytes: &[u8], pubkey_zbase32: &str, now_ts: u64) -> Result<bool> {
    let pubkey = parse_pubkey(pubkey_zbase32)?;
    let packet = parse_packet(packet_bytes)?;
    let signed = openhost_pkarr::decode(&packet)?;
    Ok(signed.verify(&pubkey, now_ts).is_ok())
}

/// Look up the sealed offer record (if any) inside a daemon's pkarr
/// packet. See the wasm-bindgen wrapper at crate root for API
/// documentation.
pub fn decode_offer(packet_bytes: &[u8], daemon_pk_zbase32: &str) -> Result<Option<Offer>> {
    let daemon_pk = parse_pubkey(daemon_pk_zbase32)?;
    let packet = parse_packet(packet_bytes)?;
    let offer = openhost_pkarr::decode_offer_from_packet(&packet, &daemon_pk)?;
    Ok(offer.map(|o| Offer {
        sealed_base64url: base64_url_nopad(&o.sealed),
    }))
}

/// Reassemble + return the fragmented answer record addressed to
/// `client_pk_zbase32`. See the wasm-bindgen wrapper at crate root
/// for API documentation.
pub fn decode_answer_fragments(
    packet_bytes: &[u8],
    daemon_salt: &[u8],
    client_pk_zbase32: &str,
) -> Result<Option<Answer>> {
    let salt = parse_salt(daemon_salt)?;
    let client_pk = parse_pubkey(client_pk_zbase32)?;
    let packet = parse_packet(packet_bytes)?;
    let entry = openhost_pkarr::decode_answer_fragments_from_packet(&packet, &salt, &client_pk)?;
    Ok(entry.map(|e| Answer {
        client_hash_hex: hex::encode(e.client_hash),
        sealed_base64url: base64_url_nopad(&e.sealed),
        created_at: e.created_at,
    }))
}
