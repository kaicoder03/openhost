//! Plain-Rust core tier of the wasm shim.
//!
//! Every function here takes byte slices / strings + returns plain
//! Rust DTOs, so it can be unit-tested on the host target without
//! dragging in a wasm-bindgen runtime. The `#[wasm_bindgen]` layer in
//! [`crate`] root wraps each of these with a `JsValue` translation
//! step.

use openhost_core::channel_binding_wire::{
    AUTH_CLIENT_PAYLOAD_LEN, AUTH_NONCE_LEN, EXPORTER_SECRET_LEN,
};
/// Ed25519 signature byte length. Not exported by `channel_binding_wire`
/// today; pinned here because the browser AUTH_CLIENT + AUTH_HOST
/// payloads both carry one of these.
const SIGNATURE_LEN: usize = 64;
use openhost_core::crypto::auth_bytes_bound;
use openhost_core::identity::{PublicKey, SigningKey, PUBLIC_KEY_LEN, SIGNING_KEY_LEN};
use openhost_core::pkarr_record::{SignedRecord, SALT_LEN};
use openhost_core::wire::{Frame, FrameType};
use openhost_pkarr::offer::OfferRecord;
use openhost_pkarr::{AnswerEntry, BindingMode, OfferPlaintext, SignedPacket};
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
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
    /// `decode_and_verify` ran but the inner Ed25519 signature was
    /// invalid, the record was outside its freshness window, or a
    /// structural invariant failed.
    #[error("record verify failed: {0}")]
    VerifyFailed(String),
    /// Input byte slice was the wrong length for a fixed-size array
    /// parameter (client SK, nonce, etc.).
    #[error("expected {expected} bytes for {field}, got {got}")]
    WrongLength {
        /// Short name identifying the parameter.
        field: &'static str,
        /// Byte count required.
        expected: usize,
        /// Byte count provided.
        got: usize,
    },
    /// Sealed-box open failed (wrong private key or tampered
    /// ciphertext).
    #[error("sealed-box open failed: {0}")]
    SealedBoxOpen(String),
    /// Base64url-nopad decode failed on the caller's sealed input.
    #[error("base64url decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The wire framing codec rejected the caller's bytes.
    #[error("frame codec: {0}")]
    Frame(String),
    /// Hex decoding of a fixed-size input (e.g. the host's DTLS
    /// fingerprint) failed.
    #[error("hex decode failed: {0}")]
    Hex(String),
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
    /// v3 sidecar (PR #42.2): daemon's embedded-TURN relay IPv4
    /// address, if it advertises one. `None` for v2 records.
    pub turn_ip: Option<String>,
    /// v3 sidecar (PR #42.2): daemon's embedded-TURN relay UDP
    /// port, if it advertises one. Paired with `turn_ip`.
    pub turn_port: Option<u16>,
    /// 64-byte Ed25519 signature, hex. Already validated against
    /// `pubkey_zbase32` when this value came from
    /// [`decode_and_verify`]; advisory only when it came from
    /// [`parse_host_record`].
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

fn parse_packet(bytes: &[u8], signer_pk: &PublicKey) -> Result<SignedPacket> {
    // Pkarr relay HTTP responses carry `signature(64) || seq(8) || v`.
    // `SignedPacket::deserialize` expects the on-disk cache layout
    // `last_seen(8) || pubkey(32) || signature(64) || seq(8) || v`, so
    // we prepend a zero `last_seen` and the signer's pubkey here.
    // Matches `SignedPacket::from_relay_payload` internally, which we
    // can't call directly without re-boxing through `Bytes`.
    let mut framed = Vec::with_capacity(8 + 32 + bytes.len());
    framed.extend_from_slice(&[0u8; 8]);
    framed.extend_from_slice(&signer_pk.to_bytes());
    framed.extend_from_slice(bytes);
    SignedPacket::deserialize(&framed).map_err(|e| Error::Packet(e.to_string()))
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
        turn_ip: r.turn_endpoint.map(|ep| ep.ip.to_string()),
        turn_port: r.turn_endpoint.map(|ep| ep.port),
        signature_hex: hex::encode(signed.signature.to_bytes()),
    }
}

/// Structurally parse a pkarr packet into its `_openhost` main
/// record. Does **not** verify the inner Ed25519 signature or the
/// freshness window — callers that need either should call
/// [`decode_and_verify`] instead. See the wasm-bindgen wrapper at
/// crate root for API documentation.
pub fn parse_host_record(packet_bytes: &[u8], pubkey_zbase32: &str) -> Result<HostRecord> {
    let pubkey = parse_pubkey(pubkey_zbase32)?;
    let packet = parse_packet(packet_bytes, &pubkey)?;
    let signed = openhost_pkarr::decode(&packet)?;
    Ok(host_record_dto(pubkey_zbase32, &signed))
}

/// Parse a pkarr packet AND verify the inner Ed25519 signature plus
/// 2-hour freshness window against `now_ts`. Folds `parse_host_record`
/// plus `SignedRecord::verify` into a single pass so the browser
/// doesn't pay the `SignedPacket::deserialize` cost twice.
///
/// Returns `Err(VerifyFailed)` when decode succeeds but verification
/// fails — JS can handle that path as "substrate lied to us; try
/// another relay" distinctly from a structural parse failure.
pub fn decode_and_verify(
    packet_bytes: &[u8],
    pubkey_zbase32: &str,
    now_ts: u64,
) -> Result<HostRecord> {
    let pubkey = parse_pubkey(pubkey_zbase32)?;
    let packet = parse_packet(packet_bytes, &pubkey)?;
    let signed = openhost_pkarr::decode(&packet)?;
    signed
        .verify(&pubkey, now_ts)
        .map_err(|e| Error::VerifyFailed(e.to_string()))?;
    Ok(host_record_dto(pubkey_zbase32, &signed))
}

/// Look up the sealed offer record (if any) inside a daemon's pkarr
/// packet. See the wasm-bindgen wrapper at crate root for API
/// documentation.
pub fn decode_offer(packet_bytes: &[u8], daemon_pk_zbase32: &str) -> Result<Option<Offer>> {
    let daemon_pk = parse_pubkey(daemon_pk_zbase32)?;
    let packet = parse_packet(packet_bytes, &daemon_pk)?;
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
    daemon_pk_zbase32: &str,
) -> Result<Option<Answer>> {
    let salt = parse_salt(daemon_salt)?;
    let client_pk = parse_pubkey(client_pk_zbase32)?;
    let daemon_pk = parse_pubkey(daemon_pk_zbase32)?;
    let packet = parse_packet(packet_bytes, &daemon_pk)?;
    let entry = openhost_pkarr::decode_answer_fragments_from_packet(&packet, &salt, &client_pk)?;
    Ok(entry.map(|e| Answer {
        client_hash_hex: hex::encode(e.client_hash),
        sealed_base64url: base64_url_nopad(&e.sealed),
        created_at: e.created_at,
    }))
}

// ============================================================================
// Phase 4: browser-dialer primitives (PR #28.3)
// ============================================================================
//
// The browser extension's JS orchestrator owns the RTCPeerConnection.
// Everything below is the crypto + wire-codec surface the orchestrator
// calls via wasm-bindgen during a dial:
//
//   1. `seal_offer`           — seal the client's offer SDP to the host.
//   2. (publish via relay)    — JS PUTs the sealed bytes to a Pkarr relay.
//   3. (poll + decode_answer) — JS calls `decode_answer_fragments` +
//                               `open_answer` to recover the answer SDP.
//   4. (apply answer)         — JS drives setRemoteDescription.
//   5. `compute_cert_fp_binding` + `sign_auth_client` — build the
//      AUTH_CLIENT payload once DTLS is up.
//   6. `verify_auth_host`     — validate the daemon's AUTH_HOST reply.
//   7. `encode_frame` / `decode_frame` — HTTP-over-DataChannel I/O.

/// Decrypted answer plaintext returned to JS. Matches the wire form
/// from `spec/01-wire-format.md §3.3`.
#[derive(Debug, Serialize)]
pub struct OpenedAnswer {
    /// The responding daemon's Ed25519 pubkey, zbase32. Cross-check
    /// against the Pkarr signer before trusting the answer.
    pub daemon_pk_zbase32: String,
    /// SHA-256 of the UTF-8 offer SDP this answer is bound to, hex.
    pub offer_sdp_hash_hex: String,
    /// The daemon's SDP answer text.
    pub answer_sdp: String,
}

/// Decoded wire frame returned to JS.
#[derive(Debug, Serialize)]
pub struct DecodedFrame {
    /// Raw frame-type byte (see `spec/01-wire-format.md §4`).
    pub frame_type: u8,
    /// Frame payload.
    pub payload: Vec<u8>,
    /// Total bytes consumed from the buffer for this frame (header +
    /// payload). Callers shift their read buffer forward by this count.
    pub consumed: usize,
}

fn parse_binding_mode(b: u8) -> Result<BindingMode> {
    BindingMode::try_from_u8(b).map_err(Error::Pkarr)
}

fn parse_array<const N: usize>(bytes: &[u8], field: &'static str) -> Result<[u8; N]> {
    <[u8; N]>::try_from(bytes).map_err(|_| Error::WrongLength {
        field,
        expected: N,
        got: bytes.len(),
    })
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Seal an [`OpenhostPlaintext`-equivalent] client offer to the daemon.
/// JS hands the returned `Vec<u8>` to a Pkarr relay PUT as the sealed
/// offer record TXT value (after base64url-nopad encoding, which lives
/// on the JS side to keep the WASM boundary byte-level).
///
/// `binding_mode_u8` MUST be `0x02 CertFp` for browser calls; `0x01
/// Exporter` is permitted for host-target tests but never emitted by a
/// production browser build.
pub fn seal_offer(
    daemon_pk_zbase32: &str,
    client_pk_zbase32: &str,
    offer_sdp: &str,
    binding_mode_u8: u8,
) -> Result<Vec<u8>> {
    let daemon_pk = parse_pubkey(daemon_pk_zbase32)?;
    let client_pk = parse_pubkey(client_pk_zbase32)?;
    let binding_mode = parse_binding_mode(binding_mode_u8)?;
    // Extract the compact v3 blob from the raw SDP on the WASM side
    // so JS never has to see the blob structure — it just hands us
    // the SDP that `RTCPeerConnection.createOffer()` produced.
    let client_dtls_fp =
        openhost_pkarr::extract_sha256_fingerprint_from_sdp(offer_sdp).map_err(Error::Pkarr)?;
    let offer_blob = openhost_pkarr::sdp_to_offer_blob(offer_sdp, &client_dtls_fp, binding_mode)
        .map_err(Error::Pkarr)?;
    let plaintext = OfferPlaintext::new_v3(client_pk, offer_blob);
    let mut rng = OsRng;
    let record = OfferRecord::seal(&mut rng, &daemon_pk, &plaintext)?;
    Ok(record.sealed)
}

/// Compute the canonical offer SDP (as reconstructed on the daemon
/// side) for a given raw SDP — exposed so JS can hash this exact
/// string for answer-binding, matching what the daemon will hash
/// from the received blob.
pub fn canonicalize_offer_sdp(offer_sdp: &str, binding_mode_u8: u8) -> Result<String> {
    let binding_mode = parse_binding_mode(binding_mode_u8)?;
    let client_dtls_fp =
        openhost_pkarr::extract_sha256_fingerprint_from_sdp(offer_sdp).map_err(Error::Pkarr)?;
    let offer_blob = openhost_pkarr::sdp_to_offer_blob(offer_sdp, &client_dtls_fp, binding_mode)
        .map_err(Error::Pkarr)?;
    Ok(openhost_pkarr::offer_blob_to_sdp(&offer_blob))
}

/// Open an answer record with the client's 32-byte Ed25519 secret key
/// and return a complete SDP string ready for
/// `RTCPeerConnection.setRemoteDescription`. Transparently handles
/// both v1 (full SDP embedded) and v2 (compact blob) answer shapes:
///
/// - v2 blob → reconstructs a minimal SDP locally using
///   [`openhost_pkarr::answer_blob_to_sdp`] with `host_dtls_fp_hex` as
///   the fingerprint (browser callers already have this from the
///   resolved pkarr `_openhost` record).
/// - v1 SDP → passes through unchanged; `host_dtls_fp_hex` is ignored.
///
/// `host_dtls_fp_hex` MUST be the lowercase-hex encoding of the host's
/// 32-byte SHA-256 DTLS certificate fingerprint, without separators
/// (e.g. `"aabb..."`, 64 chars). The `:`-separated colon-hex form the
/// pkarr record uses can be stripped on the JS side with
/// `.replace(/:/g, "").toLowerCase()`.
pub fn open_answer(
    client_sk_bytes: &[u8],
    sealed_base64url: &str,
    host_dtls_fp_hex: &str,
) -> Result<OpenedAnswer> {
    let sk_arr: [u8; SIGNING_KEY_LEN] = parse_array(client_sk_bytes, "client_sk")?;
    let client_sk = SigningKey::from_bytes(&sk_arr);
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let sealed = URL_SAFE_NO_PAD.decode(sealed_base64url.as_bytes())?;
    // AnswerEntry only needs `sealed` for open(); client_hash +
    // created_at are ignored, so we synthesize placeholders.
    let entry = AnswerEntry {
        client_hash: [0u8; openhost_pkarr::CLIENT_HASH_LEN],
        sealed,
        created_at: 0,
    };
    let plain = entry
        .open(&client_sk)
        .map_err(|e| Error::SealedBoxOpen(e.to_string()))?;
    let answer_sdp = match plain.answer {
        openhost_pkarr::AnswerPayload::V2Blob(blob) => {
            let fp = parse_dtls_fp_hex(host_dtls_fp_hex)?;
            openhost_pkarr::answer_blob_to_sdp(&blob, &fp)
        }
        openhost_pkarr::AnswerPayload::V1Sdp(s) => s,
    };
    Ok(OpenedAnswer {
        daemon_pk_zbase32: plain.daemon_pk.to_zbase32(),
        offer_sdp_hash_hex: hex::encode(plain.offer_sdp_hash),
        answer_sdp,
    })
}

/// Parse a lowercase-hex-encoded DTLS fingerprint (64 chars) into its
/// 32-byte array. Tolerates upper-case as well. Reject everything else
/// so a mis-formatted string can't silently seed a bad fingerprint.
fn parse_dtls_fp_hex(s: &str) -> Result<[u8; openhost_pkarr::DTLS_FP_LEN]> {
    let raw = hex::decode(s).map_err(|e| Error::Hex(e.to_string()))?;
    parse_array::<{ openhost_pkarr::DTLS_FP_LEN }>(&raw, "host_dtls_fp")
}

/// Compute the 32-byte AUTH bytes for a browser (CertFp) dial.
///
/// The input `cert_der` is the DER-encoded DTLS certificate the browser
/// reads from `RTCDtlsTransport.getRemoteCertificates()[0]`. The output
/// feeds the AUTH_CLIENT signature (via [`sign_auth_client`]) and the
/// AUTH_HOST verify (via [`verify_auth_host`]), matching the daemon's
/// Phase 2 `derive_binding_secret(CertFp)` path byte-for-byte.
pub fn compute_cert_fp_binding(
    cert_der: &[u8],
    host_pk_zbase32: &str,
    client_pk_zbase32: &str,
    nonce_bytes: &[u8],
) -> Result<[u8; 32]> {
    let host_pk = parse_pubkey(host_pk_zbase32)?;
    let client_pk = parse_pubkey(client_pk_zbase32)?;
    let nonce: [u8; AUTH_NONCE_LEN] = parse_array(nonce_bytes, "nonce")?;
    if cert_der.is_empty() {
        return Err(Error::VerifyFailed(
            "remote DTLS certificate DER is empty".to_string(),
        ));
    }
    let secret = sha256_32(cert_der);
    debug_assert_eq!(secret.len(), EXPORTER_SECRET_LEN);
    let auth = auth_bytes_bound(&secret, &host_pk.to_bytes(), &client_pk.to_bytes(), &nonce)
        .map_err(|e| Error::VerifyFailed(e.to_string()))?;
    Ok(auth)
}

/// Produce the 96-byte AUTH_CLIENT payload (32B client_pk ||
/// 64B Ed25519 signature over `auth_bytes`).
pub fn sign_auth_client(client_sk_bytes: &[u8], auth_bytes: &[u8]) -> Result<Vec<u8>> {
    let sk_arr: [u8; SIGNING_KEY_LEN] = parse_array(client_sk_bytes, "client_sk")?;
    let client_sk = SigningKey::from_bytes(&sk_arr);
    // auth_bytes is always 32 bytes (AUTH_BYTES_LEN). Enforce up-front
    // so mis-sized inputs surface as WrongLength instead of a cryptic
    // downstream verify failure.
    let _: [u8; 32] = parse_array(auth_bytes, "auth_bytes")?;
    let sig = client_sk.sign(auth_bytes);
    let mut out = Vec::with_capacity(AUTH_CLIENT_PAYLOAD_LEN);
    out.extend_from_slice(&client_sk.public_key().to_bytes());
    out.extend_from_slice(&sig.to_bytes());
    Ok(out)
}

/// Verify the 64-byte AUTH_HOST signature against `auth_bytes` under
/// `host_pk`. Returns `Ok(true)` on good signature, `Ok(false)` on
/// bad. Malformed lengths surface as [`Error::WrongLength`].
pub fn verify_auth_host(
    host_pk_zbase32: &str,
    auth_bytes: &[u8],
    signature_64b: &[u8],
) -> Result<bool> {
    let host_pk = parse_pubkey(host_pk_zbase32)?;
    let _: [u8; 32] = parse_array(auth_bytes, "auth_bytes")?;
    let sig_arr: [u8; SIGNATURE_LEN] = parse_array(signature_64b, "signature")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    Ok(host_pk.as_dalek().verify_strict(auth_bytes, &sig).is_ok())
}

/// Encode a wire frame to bytes ready to ship over the data channel.
/// The frame-type byte matches `spec/01-wire-format.md §4`.
pub fn encode_frame(frame_type_u8: u8, payload: Vec<u8>) -> Result<Vec<u8>> {
    let frame_type = FrameType::from_u8(frame_type_u8)
        .map_err(|e| Error::Frame(format!("unknown frame type 0x{frame_type_u8:02x}: {e}")))?;
    let frame = Frame::new(frame_type, payload).map_err(|e| Error::Frame(e.to_string()))?;
    Ok(frame.encode_to_vec())
}

/// Try to decode one frame from the front of `buf`. Returns `None`
/// (as an untyped option → JS `null`) if `buf` is incomplete; a
/// [`DecodedFrame`] otherwise with `consumed` bytes from the front.
pub fn decode_frame(buf: &[u8]) -> Result<Option<DecodedFrame>> {
    match Frame::try_decode(buf) {
        Ok(None) => Ok(None),
        Ok(Some((frame, consumed))) => Ok(Some(DecodedFrame {
            frame_type: frame.frame_type.as_u8(),
            payload: frame.payload,
            consumed,
        })),
        Err(e) => Err(Error::Frame(e.to_string())),
    }
}

// Silence the "unused" warnings for constants we only reach through
// conditional paths (eg. PUBLIC_KEY_LEN is only consumed inside
// parse_array via the N generic).
#[allow(dead_code)]
const _: usize = PUBLIC_KEY_LEN;

/// Derive the client's zbase32 Ed25519 pubkey from its 32-byte seed.
/// The browser extension stores the seed in IndexedDB; JS needs the
/// pubkey string to address offer records + parse hostRecord
/// self-check fields without re-implementing Ed25519 scalarmult.
pub fn client_pubkey_from_seed(seed_bytes: &[u8]) -> Result<String> {
    let seed: [u8; SIGNING_KEY_LEN] = parse_array(seed_bytes, "client_seed")?;
    Ok(SigningKey::from_bytes(&seed).public_key().to_zbase32())
}

/// Assemble a Pkarr `SignedPacket` carrying one `_offer-<host-hash>`
/// TXT entry, signed by the client's identity key. Returns the raw
/// wire bytes ready for an HTTP PUT to a Pkarr relay
/// (`PUT https://<relay>/<client-pk-zbase32>`).
///
/// Mirrors `openhost_client::Dialer::publish_offer` byte-for-byte
/// (see `crates/openhost-client/src/dialer.rs:338-372`) minus the
/// monotonic-seq bump — callers pass `now_ts` explicitly so a JS
/// dialer can bump past its own last publish on retry.
pub fn build_offer_packet(
    client_sk_bytes: &[u8],
    daemon_pk_zbase32: &str,
    sealed_offer: &[u8],
    now_ts: u64,
) -> Result<Vec<u8>> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use pkarr::dns::rdata::TXT;
    use pkarr::dns::Name;
    use pkarr::{Keypair, SignedPacket, Timestamp};

    let seed: [u8; SIGNING_KEY_LEN] = parse_array(client_sk_bytes, "client_sk")?;
    let daemon_pk = parse_pubkey(daemon_pk_zbase32)?;

    let txt_value = URL_SAFE_NO_PAD.encode(sealed_offer);
    let label = openhost_pkarr::host_hash_label(&daemon_pk);
    let name = format!("{}{label}", openhost_pkarr::OFFER_TXT_PREFIX);

    let keypair = Keypair::from_secret_key(&seed);
    let ts_micros = now_ts
        .checked_mul(1_000_000)
        .ok_or_else(|| Error::VerifyFailed("ts overflow".to_string()))?;

    let packet = SignedPacket::builder()
        .txt(
            Name::new_unchecked(&name),
            TXT::try_from(txt_value.as_str())
                .map_err(|e| Error::VerifyFailed(format!("txt build: {e}")))?,
            openhost_pkarr::OFFER_TXT_TTL,
        )
        .timestamp(Timestamp::from(ts_micros))
        .sign(&keypair)
        .map_err(|e| Error::VerifyFailed(format!("sign: {e}")))?;

    // Relay HTTP PUT expects `sig(64) || seq(8) || v` — the
    // `to_relay_payload` shape. `packet.serialize()` prepends
    // `last_seen(8) || pubkey(32)` for on-disk cache use, which
    // relays reject with HTTP 400. Fixed in the compact-offer-blob
    // PR; the pre-rollout browser dial path never reached this
    // step so the bug was latent.
    Ok(packet.to_relay_payload().to_vec())
}
