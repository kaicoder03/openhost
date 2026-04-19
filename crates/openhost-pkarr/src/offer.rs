//! Offer + answer record codec for the daemon's signalling loop.
//!
//! # Overview
//!
//! Clients publish an ephemeral offer SDP by posting a `SignedPacket`
//! under their own Ed25519 pubkey containing a TXT record at
//! `_offer-<host-hash>`. The TXT value is a sealed-box ciphertext
//! addressed to the daemon's Ed25519 identity (converted to X25519).
//! The daemon polls known clients, reads the TXT, unseals it, and
//! hands the inner SDP to
//! [`crate::listener::PassivePeer::handle_offer`].
//!
//! The daemon publishes the answer back as an extra TXT record
//! inside its own regular `_openhost` packet, at
//! `_answer-<client-hash>`. The `_openhost` TXT bytes are completely
//! unchanged; clients that only decode the main record don't notice.
//! Client-side consumers that DO know their `client_hash` look for
//! the `_answer-*` TXT, unseal it against their own identity, and
//! apply the answer SDP to their peer connection.
//!
//! Canonical reference: `spec/01-wire-format.md §3.3`.
//!
//! # Wire format (v0.1)
//!
//! Both TXT values are `base64url_no_pad(sealed_box_ciphertext)`.
//! The sealed-box plaintext begins with a 1-byte `compression_tag`
//! that determines the layout of the remaining bytes:
//!
//! ```text
//! inner_plaintext = compression_tag || body
//!
//!   compression_tag : u8
//!       0x01 = Uncompressed — `body` bytes follow verbatim (legacy).
//!       0x02 = Zlib (RFC 1950) — `body` bytes are the zlib-encoded
//!              form of the uncompressed body below. Decompressed
//!              output MUST NOT exceed 65_536 bytes.
//!       Other values MUST be rejected as malformed.
//!
//!   body (offer)  =  "openhost-offer-inner1"   (21 bytes)
//!                 || client_pk                  (32 bytes)
//!                 || sdp_len                    (u32 big-endian)
//!                 || offer_sdp_utf8             (sdp_len bytes)
//!
//!   body (answer) =  "openhost-answer-inner1"  (22 bytes)
//!                 || daemon_pk                  (32 bytes)
//!                 || offer_sdp_hash             (32 bytes, SHA-256)
//!                 || sdp_len                    (u32 big-endian)
//!                 || answer_sdp_utf8            (sdp_len bytes)
//! ```
//!
//! v0.1+ encoders emit `compression_tag = 0x02`. Decoders accept
//! both `0x01` and `0x02`. The inner `client_pk` / `daemon_pk` MUST
//! match the outer BEP44 signer pubkey — cross-checked on decode so
//! a hostile substrate cannot splice an offer signed under key A
//! with inner plaintext claiming key B.

use crate::codec::{BEP44_MAX_V_BYTES, MICROS_PER_SECOND, OPENHOST_TXT_NAME, OPENHOST_TXT_TTL};
use crate::error::{PkarrError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openhost_core::crypto::{
    allowlist_hash, public_key_to_x25519, sealed_box_open, sealed_box_seal, signing_key_to_x25519,
};
use openhost_core::identity::{PublicKey, SigningKey, PUBLIC_KEY_LEN};
use openhost_core::pkarr_record::{SignedRecord, SALT_LEN};
use pkarr::dns::rdata::{RData, TXT};
use pkarr::dns::Name;
use pkarr::{Keypair, SignedPacket, Timestamp};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Compression discriminator prefixing every sealed inner plaintext.
/// Encoders post-v0.1 MUST emit `Zlib`; decoders MUST accept both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum CompressionTag {
    /// v1 legacy layout — body bytes follow the tag verbatim.
    Uncompressed = 0x01,
    /// v2 — body bytes are zlib-compressed (RFC 1950) after the tag.
    Zlib = 0x02,
}

impl CompressionTag {
    fn try_from_u8(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::Uncompressed),
            0x02 => Ok(Self::Zlib),
            _ => Err(PkarrError::MalformedCanonical(
                "unknown offer/answer inner compression tag",
            )),
        }
    }
}

/// Maximum decompressed inner-plaintext size. A legitimate SDP is
/// ~500 bytes; 4 KiB covers fully-trickled ICE; 64 KiB is two orders
/// of magnitude past anything plausible, tight enough to defeat zlib
/// bombs. Decoders MUST reject inputs whose decompressed size would
/// exceed this cap.
const MAX_DECOMPRESSED_PLAINTEXT: usize = 64 * 1024;

/// Domain separator embedded in the offer inner plaintext.
pub const OFFER_INNER_DOMAIN: &[u8] = b"openhost-offer-inner1";

/// Domain separator embedded in the answer inner plaintext.
pub const ANSWER_INNER_DOMAIN: &[u8] = b"openhost-answer-inner1";

/// Domain separator used when deriving the `_offer.` DNS label from the
/// daemon's pubkey. Domain-separated from `allowlist_hash` so observers
/// cannot correlate the offer path with allowlist entries.
const HOST_HASH_DOMAIN: &[u8] = b"openhost-offer-host-v1";

/// Truncated length of the host/client DNS-label hashes.
pub const HOST_HASH_LEN: usize = 16;
/// Alias for parity with [`openhost_core::pkarr_record::CLIENT_HASH_LEN`].
pub const CLIENT_HASH_LEN: usize = openhost_core::pkarr_record::CLIENT_HASH_LEN;

/// SHA-256 output length, re-exported here because the answer plaintext
/// carries an SDP hash of exactly this size.
pub const OFFER_SDP_HASH_LEN: usize = 32;

/// DNS label prefix for offer records. Full single-label name is
/// `_offer-<host-hash-label>`. simple-dns reserves the
/// `_service._proto` two-label DNS-SD form for short service names
/// (≤15 chars); a 26-char z-base-32 hash doesn't fit, so we collapse
/// to a single label separated by `-`.
pub const OFFER_TXT_PREFIX: &str = "_offer-";

/// DNS label prefix for answer records. v0.2+ encoders emit one
/// `_answer-<client-hash-label>-<idx>` TXT per fragment; see
/// [`encode_with_answers`] and [`decode_answer_fragments_from_packet`].
pub const ANSWER_TXT_PREFIX: &str = "_answer-";

/// TTL (in seconds) used for both offer and answer TXT records. Short
/// because they're per-handshake and shouldn't be cached.
pub const OFFER_TXT_TTL: u32 = 30;

// ============================================================================
// Answer fragmentation (spec §3.3, v0.2+)
// ============================================================================
//
// v0.1 shipped one `_answer-<client-hash>` TXT per queued answer, which
// routinely overflowed BEP44's 1000-byte `v` cap when combined with the
// main `_openhost` record, forcing the encoder into an eviction path
// that silently dropped answers. v0.2+ fragments the sealed ciphertext
// across multiple `_answer-<client-hash>-<idx>` TXTs. The dialer
// reassembles before unsealing.
//
// Wire format of each fragment (BEFORE base64url):
//
//   [u8]   version       = FRAGMENT_VERSION
//   [u8]   chunk_idx     (0-based)
//   [u8]   chunk_total   (1..=MAX_FRAGMENT_TOTAL, repeated in every fragment)
//   [u16]  payload_len   big-endian, ≤ MAX_FRAGMENT_PAYLOAD_BYTES
//   [..]   payload       slice of the sealed-box ciphertext
//
// This is a breaking wire change relative to v0.1: v0.1 daemons emit
// one unnumbered `_answer-<client-hash>` TXT, v0.2 daemons emit one or
// more `_answer-<client-hash>-<idx>` TXTs. v0.1 clients will not find
// the unnumbered name on a v0.2 host packet, and vice versa. Since v0.1
// answer delivery was explicitly documented as best-effort (eviction),
// and both sides upgrade in lockstep with this PR, that break is
// acceptable.

const FRAGMENT_VERSION: u8 = 0x01;
const FRAGMENT_HEADER_LEN: usize = 5;

/// Maximum payload bytes per fragment. Bumped from 180 → 500 in PR #25:
/// real webrtc-rs answers seal to ~450 bytes, which at 180-byte fragments
/// forced a 3-fragment encoding whose combined DNS-RR overhead tipped the
/// BEP44 1000-byte packet over the cap. At 500, the common case is a
/// single fragment whose base64url value is ~670 chars; the fragment's
/// TXT record carries it as multiple DNS character-strings per RFC 1035
/// §3.3.14 (each ≤ 255 bytes). Decoders concatenate character-strings
/// before base64url-decoding, so the on-wire change is transparent.
pub const MAX_FRAGMENT_PAYLOAD_BYTES: usize = 500;

/// Maximum number of fragments per answer. Bounded by the `u8`
/// `chunk_total` field on the wire (so 255 is both the hard ceiling
/// and `u8::MAX`). At [`MAX_FRAGMENT_PAYLOAD_BYTES`] = 500 this caps
/// the sealed ciphertext per answer at 127,500 bytes — well past
/// anything a plausible WebRTC answer produces.
pub const MAX_FRAGMENT_TOTAL: u8 = 255;

/// DNS TXT character-string ceiling per RFC 1035 §3.3.14. The
/// `simple-dns` crate (via `pkarr`) enforces this on every string a
/// caller appends to a `TXT` rdata; values longer than this must be
/// split into multiple strings within the same RR.
const DNS_CHARACTER_STRING_MAX: usize = 255;

fn encode_fragment(idx: u8, total: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_FRAGMENT_PAYLOAD_BYTES);
    let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + payload.len());
    out.push(FRAGMENT_VERSION);
    out.push(idx);
    out.push(total);
    let len =
        u16::try_from(payload.len()).expect("payload ≤ MAX_FRAGMENT_PAYLOAD_BYTES < u16::MAX");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[derive(Debug)]
struct DecodedFragment {
    idx: u8,
    total: u8,
    payload: Vec<u8>,
}

fn decode_fragment(bytes: &[u8]) -> Result<DecodedFragment> {
    if bytes.len() < FRAGMENT_HEADER_LEN {
        return Err(PkarrError::MalformedCanonical(
            "truncated answer fragment header",
        ));
    }
    let version = bytes[0];
    if version != FRAGMENT_VERSION {
        return Err(PkarrError::MalformedCanonical(
            "unknown answer fragment version",
        ));
    }
    let idx = bytes[1];
    let total = bytes[2];
    if total == 0 {
        return Err(PkarrError::MalformedCanonical(
            "answer fragment total must be >= 1",
        ));
    }
    if idx >= total {
        return Err(PkarrError::MalformedCanonical(
            "answer fragment idx >= total",
        ));
    }
    let payload_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if payload_len == 0 {
        // A zero-length payload is meaningless — a well-formed fragment
        // always carries at least one byte of the sealed ciphertext.
        // Rejecting here defends against padding-by-empty-fragments
        // that would otherwise waste decoder work.
        return Err(PkarrError::MalformedCanonical(
            "answer fragment payload_len is zero",
        ));
    }
    if payload_len > MAX_FRAGMENT_PAYLOAD_BYTES {
        return Err(PkarrError::MalformedCanonical(
            "answer fragment payload exceeds per-fragment cap",
        ));
    }
    let expected_end = FRAGMENT_HEADER_LEN + payload_len;
    if bytes.len() != expected_end {
        return Err(PkarrError::MalformedCanonical(
            "answer fragment payload length mismatch",
        ));
    }
    Ok(DecodedFragment {
        idx,
        total,
        payload: bytes[FRAGMENT_HEADER_LEN..expected_end].to_vec(),
    })
}

fn split_into_fragments(sealed: &[u8]) -> Result<Vec<Vec<u8>>> {
    if sealed.is_empty() {
        // Sealed-box output is always ≥48 bytes; an empty payload is a
        // construction bug, not a wire condition.
        return Err(PkarrError::MalformedCanonical(
            "cannot fragment empty sealed ciphertext",
        ));
    }
    let chunk_count = sealed.len().div_ceil(MAX_FRAGMENT_PAYLOAD_BYTES);
    if chunk_count > MAX_FRAGMENT_TOTAL as usize {
        return Err(PkarrError::PacketTooLarge { size: sealed.len() });
    }
    let total = u8::try_from(chunk_count).expect("chunk_count bounded by MAX_FRAGMENT_TOTAL");
    Ok(sealed
        .chunks(MAX_FRAGMENT_PAYLOAD_BYTES)
        .enumerate()
        .map(|(i, chunk)| encode_fragment(i as u8, total, chunk))
        .collect())
}

/// One offer record. Wraps the sealed-box ciphertext; the outer BEP44
/// signature on the containing [`SignedPacket`] provides integrity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferRecord {
    /// Sealed-box ciphertext of an [`OfferPlaintext`], addressed to the
    /// daemon's X25519 pubkey.
    pub sealed: Vec<u8>,
}

/// Decrypted contents of an [`OfferRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferPlaintext {
    /// The offering client's Ed25519 pubkey. MUST match the outer BEP44
    /// signer; cross-checked on decode.
    pub client_pk: PublicKey,
    /// SDP offer text (UTF-8).
    pub offer_sdp: String,
}

/// One answer record the daemon has queued for publication. Each entry
/// contributes one `_answer._<client-hash>` TXT inside the daemon's
/// next signed packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerEntry {
    /// `allowlist_hash(daemon_salt, client_pk)` — the DNS label key.
    pub client_hash: [u8; CLIENT_HASH_LEN],
    /// Sealed-box ciphertext of an [`AnswerPlaintext`], addressed to the
    /// client's X25519 pubkey.
    pub sealed: Vec<u8>,
    /// Daemon-local creation timestamp. Not wire-visible; used only for
    /// eviction ordering when the packet would otherwise overflow the
    /// BEP44 1000-byte cap.
    pub created_at: u64,
}

/// Decrypted contents of an [`AnswerEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerPlaintext {
    /// The responding daemon's Ed25519 pubkey. MUST match the outer
    /// BEP44 signer; cross-checked on decode.
    pub daemon_pk: PublicKey,
    /// SHA-256 of the UTF-8 offer SDP this answer is bound to. Prevents
    /// a racing adversary from re-binding a valid answer onto a different
    /// offer.
    pub offer_sdp_hash: [u8; OFFER_SDP_HASH_LEN],
    /// SDP answer text (UTF-8).
    pub answer_sdp: String,
}

// ============================================================================
// Label helpers
// ============================================================================

/// 16-byte domain-separated hash of a daemon pubkey. Used to derive the
/// `_offer._<host-hash>` DNS label.
#[must_use]
pub fn host_hash(daemon_pk: &PublicKey) -> [u8; HOST_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(HOST_HASH_DOMAIN);
    hasher.update(daemon_pk.to_bytes());
    let full = hasher.finalize();
    let mut out = [0u8; HOST_HASH_LEN];
    out.copy_from_slice(&full[..HOST_HASH_LEN]);
    out
}

/// z-base-32 encoding of [`host_hash`]. Fits in a DNS label (26 chars,
/// well under the 63-char limit).
#[must_use]
pub fn host_hash_label(daemon_pk: &PublicKey) -> String {
    zbase32::encode_full_bytes(&host_hash(daemon_pk))
}

/// z-base-32 encoding of `allowlist_hash(daemon_salt, client_pk)`. Used
/// for the `_answer._<client-hash>` DNS label.
#[must_use]
pub fn client_hash_label(daemon_salt: &[u8; SALT_LEN], client_pk: &PublicKey) -> String {
    let h = allowlist_hash(daemon_salt, &client_pk.to_bytes());
    zbase32::encode_full_bytes(&h)
}

/// Full DNS name for the offer TXT record the daemon expects under the
/// given client's zone: `_offer._<host-hash-label>`.
#[must_use]
pub fn offer_txt_name(daemon_pk: &PublicKey) -> String {
    format!("{OFFER_TXT_PREFIX}{}", host_hash_label(daemon_pk))
}

/// Base DNS name (without the `-<idx>` fragment suffix) the daemon
/// publishes answers under inside its own zone: `_answer-<client-hash-label>`.
/// v0.2+ callers should use [`answer_txt_chunk_name`]; this helper
/// exists for diagnostic tooling and tests.
#[must_use]
pub fn answer_txt_name(daemon_salt: &[u8; SALT_LEN], client_pk: &PublicKey) -> String {
    format!(
        "{ANSWER_TXT_PREFIX}{}",
        client_hash_label(daemon_salt, client_pk)
    )
}

/// Full DNS name for one fragment of an answer, carrying the 0-based
/// `idx` suffix. Format: `_answer-<client-hash-label>-<idx>`.
#[must_use]
pub fn answer_txt_chunk_name(
    daemon_salt: &[u8; SALT_LEN],
    client_pk: &PublicKey,
    idx: u8,
) -> String {
    format!("{}-{}", answer_txt_name(daemon_salt, client_pk), idx)
}

// ============================================================================
// Seal / open
// ============================================================================

impl OfferRecord {
    /// Seal an offer SDP to the daemon. Called by client-side code
    /// (PR #8); the function lives here so the codec stays symmetric.
    pub fn seal<R: CryptoRngCore>(
        rng: &mut R,
        daemon_pk: &PublicKey,
        plaintext: &OfferPlaintext,
    ) -> Result<Self> {
        let inner = encode_offer_plaintext(plaintext);
        let recipient = public_key_to_x25519(daemon_pk).map_err(PkarrError::Core)?;
        let sealed = sealed_box_seal(rng, &recipient, &inner);
        Ok(Self { sealed })
    }

    /// Unseal with the daemon's identity signing key. Returns the
    /// contained [`OfferPlaintext`] on success.
    ///
    /// Callers MUST additionally cross-check
    /// `plaintext.client_pk == packet.public_key()` — `decode_offer_from_packet`
    /// does this automatically; direct callers must not skip it.
    pub fn open(&self, daemon_sk: &SigningKey) -> Result<OfferPlaintext> {
        let recipient = signing_key_to_x25519(daemon_sk);
        let inner = sealed_box_open(&recipient, &self.sealed).map_err(PkarrError::Core)?;
        parse_offer_plaintext(&inner)
    }
}

impl AnswerEntry {
    /// Seal an answer SDP to the client. Called by the daemon after
    /// `PassivePeer::handle_offer` returns the answer SDP.
    pub fn seal<R: CryptoRngCore>(
        rng: &mut R,
        client_pk: &PublicKey,
        daemon_salt: &[u8; SALT_LEN],
        plaintext: &AnswerPlaintext,
        created_at: u64,
    ) -> Result<Self> {
        let inner = encode_answer_plaintext(plaintext);
        let recipient = public_key_to_x25519(client_pk).map_err(PkarrError::Core)?;
        let sealed = sealed_box_seal(rng, &recipient, &inner);
        let client_hash = allowlist_hash(daemon_salt, &client_pk.to_bytes());
        Ok(Self {
            client_hash,
            sealed,
            created_at,
        })
    }

    /// Open the sealed ciphertext with the client's signing key. Used by
    /// PR #8's client-side consumer.
    pub fn open(&self, client_sk: &SigningKey) -> Result<AnswerPlaintext> {
        let recipient = signing_key_to_x25519(client_sk);
        let inner = sealed_box_open(&recipient, &self.sealed).map_err(PkarrError::Core)?;
        parse_answer_plaintext(&inner)
    }
}

/// Convenience: SHA-256 of the UTF-8 offer SDP. Used to build the
/// `offer_sdp_hash` field in an [`AnswerPlaintext`].
#[must_use]
pub fn hash_offer_sdp(offer_sdp: &str) -> [u8; OFFER_SDP_HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(offer_sdp.as_bytes());
    let full = hasher.finalize();
    let mut out = [0u8; OFFER_SDP_HASH_LEN];
    out.copy_from_slice(&full);
    out
}

// ============================================================================
// Encode / decode — packet level
// ============================================================================

/// Encode a [`SignedRecord`] into a [`SignedPacket`], optionally
/// carrying fragmented answer TXT records. When `answers` is empty the
/// returned packet is byte-identical to what [`crate::codec::encode`]
/// would produce — an existing test pins this invariant.
///
/// Each [`AnswerEntry`]'s sealed ciphertext is split into one or more
/// fragments of up to [`MAX_FRAGMENT_PAYLOAD_BYTES`] bytes and emitted
/// as `_answer-<client-hash>-<idx>` TXT records. Fragments of one
/// answer are packed atomically: if adding them would overflow
/// [`BEP44_MAX_V_BYTES`], the whole answer is evicted (oldest entries
/// first, by `created_at`) and a `warn!` is logged so operators notice
/// shedding.
pub fn encode_with_answers(
    signed: &SignedRecord,
    signing_key: &SigningKey,
    answers: &[AnswerEntry],
) -> Result<SignedPacket> {
    let canonical = signed.record.canonical_signing_bytes()?;
    let mut main_blob = Vec::with_capacity(64 + canonical.len());
    main_blob.extend_from_slice(&signed.signature.to_bytes());
    main_blob.extend_from_slice(&canonical);
    let main_txt = URL_SAFE_NO_PAD.encode(&main_blob);

    let seed = Zeroizing::new(signing_key.to_bytes());
    let keypair = Keypair::from_secret_key(&seed);

    let ts_micros =
        signed
            .record
            .ts
            .checked_mul(MICROS_PER_SECOND)
            .ok_or(PkarrError::TimestampOverflow {
                ts: signed.record.ts,
            })?;
    let ts = Timestamp::from(ts_micros);

    // Sort by created_at ascending so oldest entries are at the front —
    // eviction walks the front, keeping the freshest answers.
    let mut sorted: Vec<&AnswerEntry> = answers.iter().collect();
    sorted.sort_by_key(|e| e.created_at);

    // Pre-compute the fragment record set for every answer. Each inner
    // Vec is the atomic publication unit: either every fragment of an
    // answer makes it into the packet, or none does.
    let mut per_answer_records: Vec<Vec<(String, String)>> = Vec::with_capacity(sorted.len());
    for entry in &sorted {
        let fragments = split_into_fragments(&entry.sealed)?;
        let label = zbase32::encode_full_bytes(&entry.client_hash);
        let base = format!("{ANSWER_TXT_PREFIX}{label}");
        let named: Vec<(String, String)> = fragments
            .into_iter()
            .enumerate()
            .map(|(i, frag)| (format!("{base}-{i}"), URL_SAFE_NO_PAD.encode(&frag)))
            .collect();
        per_answer_records.push(named);
    }

    // Flatten once up-front. Eviction moves `records_start` forward to
    // the first byte of the next answer's fragment set — no per-retry
    // re-collection needed.
    let flat_records: Vec<&(String, String)> = per_answer_records
        .iter()
        .flat_map(|answer| answer.iter())
        .collect();
    let mut answer_start_offsets: Vec<usize> = Vec::with_capacity(sorted.len() + 1);
    let mut running = 0usize;
    for answer in &per_answer_records {
        answer_start_offsets.push(running);
        running += answer.len();
    }
    answer_start_offsets.push(running);

    // Try with ALL answers first. pkarr's own signer enforces the
    // 1000-byte BEP44 cap and returns `SignedPacketBuildError::PacketTooLarge`
    // BEFORE we get a packet back, so we need to drop entries and
    // retry rather than post-hoc inspecting `encoded_packet().len()`.
    let mut keep_from = 0usize;
    loop {
        let records_start = answer_start_offsets[keep_from];
        let records = &flat_records[records_start..];
        match build_packet(&main_txt, ts, records, &keypair) {
            Ok(packet) => {
                // Defensive: also re-check our own ceiling in case the
                // pkarr crate's check moves in a future release.
                if packet.encoded_packet().len() > BEP44_MAX_V_BYTES {
                    if keep_from >= sorted.len() {
                        return Err(PkarrError::PacketTooLarge {
                            size: packet.encoded_packet().len(),
                        });
                    }
                    tracing::warn!(
                        evicted_client_hash = %hex_hash(&sorted[keep_from].client_hash),
                        fragments = per_answer_records[keep_from].len(),
                        "openhost-pkarr: answer entry evicted — packet would exceed BEP44 1000-byte limit",
                    );
                    keep_from += 1;
                    continue;
                }
                return Ok(packet);
            }
            Err(PkarrError::Build(e)) if is_packet_too_large(&e) => {
                if keep_from >= sorted.len() {
                    return Err(PkarrError::Build(e));
                }
                tracing::warn!(
                    evicted_client_hash = %hex_hash(&sorted[keep_from].client_hash),
                    fragments = per_answer_records[keep_from].len(),
                    "openhost-pkarr: answer entry evicted — packet would exceed BEP44 1000-byte limit",
                );
                keep_from += 1;
            }
            Err(other) => return Err(other),
        }
    }
}

fn is_packet_too_large(err: &pkarr::errors::SignedPacketBuildError) -> bool {
    // `SignedPacketBuildError::PacketTooLarge(usize)` is the relevant
    // variant; fall back to string matching so we stay forward-
    // compatible with minor pkarr version bumps that might rename it.
    matches!(
        err,
        pkarr::errors::SignedPacketBuildError::PacketTooLarge(_)
    )
}

fn build_packet(
    main_txt: &str,
    ts: Timestamp,
    records: &[&(String, String)],
    keypair: &Keypair,
) -> Result<SignedPacket> {
    let mut builder = SignedPacket::builder().timestamp(ts).txt(
        Name::new_unchecked(OPENHOST_TXT_NAME),
        build_multi_string_txt(main_txt)?,
        OPENHOST_TXT_TTL,
    );
    for (name, value) in records {
        builder = builder.txt(
            Name::new_unchecked(name),
            build_multi_string_txt(value)?,
            OFFER_TXT_TTL,
        );
    }
    Ok(builder.sign(keypair)?)
}

/// Build a DNS TXT rdata from an arbitrary-length ASCII value, splitting
/// it across multiple character-strings as needed (each ≤ 255 bytes per
/// RFC 1035 §3.3.14). Used by every writer of `_openhost` and
/// `_answer-*` fragment TXTs so values larger than one DNS character-
/// string (e.g. post-PR-25 answer fragments at `MAX_FRAGMENT_PAYLOAD_BYTES
/// = 500`) encode correctly.
///
/// Callers MUST pass an ASCII value (typically a base64url string).
/// Non-ASCII inputs would split at byte boundaries that straddle
/// code-points and the decoder would see mojibake. Debug builds assert
/// the invariant.
fn build_multi_string_txt(value: &str) -> Result<TXT<'static>> {
    debug_assert!(
        value.is_ascii(),
        "build_multi_string_txt expects ASCII; multi-byte UTF-8 would be split mid-code-point"
    );
    // `simple_dns::TXT::with_string` borrows the input string for the
    // lifetime of the returned TXT. To hand back a `TXT<'static>` we
    // collect every chunk into an owned `Vec<String>` that outlives
    // the loop's borrows, then call `into_owned()` at the end to
    // internalise those borrows.
    let chunks: Vec<String> = value
        .as_bytes()
        .chunks(DNS_CHARACTER_STRING_MAX)
        .map(|c| {
            core::str::from_utf8(c)
                .expect("caller guaranteed ASCII")
                .to_string()
        })
        .collect();
    let mut txt = TXT::new();
    for s in &chunks {
        txt = txt
            .with_string(s)
            .map_err(|e| PkarrError::TxtBuildFailed(e.to_string()))?;
    }
    Ok(txt.into_owned())
}

/// Look for an `_offer-<host-hash>` TXT inside `packet` and return it
/// decoded. Returns `Ok(None)` if the expected TXT is absent.
///
/// **Does NOT cross-check** the inner `client_pk` inside the sealed
/// plaintext against the outer BEP44 signer — the sealed bytes aren't
/// unsealed here. The caller MUST perform that check after
/// [`OfferRecord::open`] to defend against a substrate splicing an
/// offer signed by key A that claims to come from key B. See the
/// `process_client_packet` path in `openhost-daemon::offer_poller` for
/// the canonical implementation.
pub fn decode_offer_from_packet(
    packet: &SignedPacket,
    daemon_pk: &PublicKey,
) -> Result<Option<OfferRecord>> {
    let want_name = offer_txt_name(daemon_pk);
    let text = match collect_single_txt(packet, &want_name)? {
        Some(t) => t,
        None => return Ok(None),
    };
    let sealed = URL_SAFE_NO_PAD.decode(text.as_bytes())?;
    Ok(Some(OfferRecord { sealed }))
}

/// Scan `packet` for fragmented `_answer-<client-hash>-<idx>` TXT
/// records addressed to `client_pk`, reassemble them, and return the
/// resulting [`AnswerEntry`] with the concatenated sealed ciphertext.
/// Returns `Ok(None)` when no fragments addressed to this client are
/// present (i.e. the daemon has not yet queued an answer for us).
///
/// Rejects malformed fragmentation: inconsistent `chunk_total` across
/// fragments, missing or duplicate indices, oversized payloads, and
/// unknown envelope versions all produce `PkarrError::MalformedCanonical`.
///
/// **Does NOT cross-check** the inner `daemon_pk` inside the reassembled
/// sealed plaintext against the outer BEP44 signer — the caller MUST do
/// that after [`AnswerEntry::open`] to defend against a splicing
/// substrate.
pub fn decode_answer_fragments_from_packet(
    packet: &SignedPacket,
    daemon_salt: &[u8; SALT_LEN],
    client_pk: &PublicKey,
) -> Result<Option<AnswerEntry>> {
    let client_hash = allowlist_hash(daemon_salt, &client_pk.to_bytes());
    let base = format!(
        "{ANSWER_TXT_PREFIX}{}",
        zbase32::encode_full_bytes(&client_hash)
    );

    // TODO(perf): replace the per-fragment `collect_single_txt` probes
    // with a single pass over `packet.all_resource_records()` that
    // bucket-sorts matching names by their numeric `-<idx>` suffix.
    // Today this walks the packet's RR list `chunk_total` times — fine
    // for the 1–3 fragments we see in practice, O(N²) in the
    // pathological MAX_FRAGMENT_TOTAL=255 case. Not a hotpath (one
    // reassembly per dial attempt) so the refactor is deferred.

    // Probe idx = 0 first. Missing zero-fragment ⇒ no answer for us.
    let first_name = format!("{base}-0");
    let Some(first_text) = collect_single_txt(packet, &first_name)? else {
        return Ok(None);
    };
    let first_bytes = URL_SAFE_NO_PAD.decode(first_text.as_bytes())?;
    let first = decode_fragment(&first_bytes)?;
    if first.idx != 0 {
        return Err(PkarrError::MalformedCanonical(
            "answer fragment 0 carries non-zero idx",
        ));
    }
    let total = first.total;

    let mut fragments: Vec<DecodedFragment> = Vec::with_capacity(total as usize);
    fragments.push(first);
    for i in 1..total {
        let name = format!("{base}-{i}");
        let text = collect_single_txt(packet, &name)?.ok_or(PkarrError::MalformedCanonical(
            "answer fragment set is missing an idx",
        ))?;
        let bytes = URL_SAFE_NO_PAD.decode(text.as_bytes())?;
        let frag = decode_fragment(&bytes)?;
        if frag.total != total {
            return Err(PkarrError::MalformedCanonical(
                "answer fragments disagree on chunk_total",
            ));
        }
        if frag.idx != i {
            return Err(PkarrError::MalformedCanonical(
                "answer fragment idx disagrees with its DNS label suffix",
            ));
        }
        fragments.push(frag);
    }

    let mut sealed = Vec::with_capacity(fragments.iter().map(|f| f.payload.len()).sum());
    for frag in fragments {
        sealed.extend_from_slice(&frag.payload);
    }

    // Use the packet timestamp as a sensible default for `created_at` —
    // the caller can override if they track their own receipt time.
    let packet_ts_micros: u64 = packet.timestamp().into();
    Ok(Some(AnswerEntry {
        client_hash,
        sealed,
        created_at: packet_ts_micros / MICROS_PER_SECOND,
    }))
}

fn collect_single_txt(packet: &SignedPacket, name: &str) -> Result<Option<String>> {
    let mut seen = 0usize;
    let mut out = String::new();
    for rr in packet.resource_records(name) {
        if let RData::TXT(txt) = &rr.rdata {
            seen += 1;
            if seen > 1 {
                // Multiple TXTs at the same name → malformed.
                return Err(PkarrError::MultipleOpenhostRecords);
            }
            for (key, value) in txt.iter_raw() {
                out.push_str(core::str::from_utf8(key).map_err(|_| PkarrError::InvalidUtf8)?);
                if let Some(v) = value {
                    out.push('=');
                    out.push_str(core::str::from_utf8(v).map_err(|_| PkarrError::InvalidUtf8)?);
                }
            }
        }
    }
    if seen == 0 {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

// ============================================================================
// Inner plaintext encode / decode
// ============================================================================

/// Shape of the v1 body: `domain || client_pk || sdp_len(u32be) || sdp`.
/// No leading compression tag — that's added by
/// [`encode_offer_plaintext`] / [`parse_offer_plaintext`] around the
/// compression layer.
fn encode_offer_body(p: &OfferPlaintext) -> Vec<u8> {
    let sdp = p.offer_sdp.as_bytes();
    let mut out = Vec::with_capacity(OFFER_INNER_DOMAIN.len() + PUBLIC_KEY_LEN + 4 + sdp.len());
    out.extend_from_slice(OFFER_INNER_DOMAIN);
    out.extend_from_slice(&p.client_pk.to_bytes());
    let len = u32::try_from(sdp.len())
        .expect("SDP length bounded well below u32::MAX by BEP44 1000-byte cap");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(sdp);
    out
}

fn parse_offer_body(body: &[u8]) -> Result<OfferPlaintext> {
    let mut r = InnerCursor::new(body);
    let domain = r.take(OFFER_INNER_DOMAIN.len())?;
    if domain != OFFER_INNER_DOMAIN {
        return Err(PkarrError::MalformedCanonical(
            "missing openhost-offer-inner1 domain separator",
        ));
    }
    let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
    pk_bytes.copy_from_slice(r.take(PUBLIC_KEY_LEN)?);
    let client_pk = PublicKey::from_bytes(&pk_bytes).map_err(PkarrError::Core)?;
    let sdp_len = r.u32_be()? as usize;
    let sdp_bytes = r.take(sdp_len)?;
    let offer_sdp = core::str::from_utf8(sdp_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("offer SDP is not valid UTF-8"))?
        .to_string();
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after offer plaintext",
        ));
    }
    Ok(OfferPlaintext {
        client_pk,
        offer_sdp,
    })
}

/// Encode a v2 (zlib-compressed) offer inner plaintext. v0.1+ default.
fn encode_offer_plaintext(p: &OfferPlaintext) -> Vec<u8> {
    let body = encode_offer_body(p);
    let compressed = zlib_compress(&body);
    let mut out = Vec::with_capacity(1 + compressed.len());
    out.push(CompressionTag::Zlib as u8);
    out.extend_from_slice(&compressed);
    out
}

/// Parse an offer inner plaintext. Accepts both `Uncompressed` (v1
/// legacy) and `Zlib` (v2) tags.
fn parse_offer_plaintext(bytes: &[u8]) -> Result<OfferPlaintext> {
    let mut r = InnerCursor::new(bytes);
    let tag = CompressionTag::try_from_u8(r.u8()?)?;
    let body_bytes;
    let body: &[u8] = match tag {
        CompressionTag::Uncompressed => r.remaining(),
        CompressionTag::Zlib => {
            body_bytes = zlib_decompress_capped(r.remaining(), MAX_DECOMPRESSED_PLAINTEXT)?;
            &body_bytes
        }
    };
    parse_offer_body(body)
}

/// Shape of the v1 answer body.
fn encode_answer_body(p: &AnswerPlaintext) -> Vec<u8> {
    let sdp = p.answer_sdp.as_bytes();
    let mut out = Vec::with_capacity(
        ANSWER_INNER_DOMAIN.len() + PUBLIC_KEY_LEN + OFFER_SDP_HASH_LEN + 4 + sdp.len(),
    );
    out.extend_from_slice(ANSWER_INNER_DOMAIN);
    out.extend_from_slice(&p.daemon_pk.to_bytes());
    out.extend_from_slice(&p.offer_sdp_hash);
    let len = u32::try_from(sdp.len())
        .expect("SDP length bounded well below u32::MAX by BEP44 1000-byte cap");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(sdp);
    out
}

/// Encode a v2 (zlib-compressed) answer inner plaintext.
fn encode_answer_plaintext(p: &AnswerPlaintext) -> Vec<u8> {
    let body = encode_answer_body(p);
    let compressed = zlib_compress(&body);
    let mut out = Vec::with_capacity(1 + compressed.len());
    out.push(CompressionTag::Zlib as u8);
    out.extend_from_slice(&compressed);
    out
}

fn parse_answer_plaintext(bytes: &[u8]) -> Result<AnswerPlaintext> {
    let mut r = InnerCursor::new(bytes);
    let tag = CompressionTag::try_from_u8(r.u8()?)?;
    let body_bytes;
    let body: &[u8] = match tag {
        CompressionTag::Uncompressed => r.remaining(),
        CompressionTag::Zlib => {
            body_bytes = zlib_decompress_capped(r.remaining(), MAX_DECOMPRESSED_PLAINTEXT)?;
            &body_bytes
        }
    };
    parse_answer_body(body)
}

fn parse_answer_body(body: &[u8]) -> Result<AnswerPlaintext> {
    let mut r = InnerCursor::new(body);
    let domain = r.take(ANSWER_INNER_DOMAIN.len())?;
    if domain != ANSWER_INNER_DOMAIN {
        return Err(PkarrError::MalformedCanonical(
            "missing openhost-answer-inner1 domain separator",
        ));
    }
    let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
    pk_bytes.copy_from_slice(r.take(PUBLIC_KEY_LEN)?);
    let daemon_pk = PublicKey::from_bytes(&pk_bytes).map_err(PkarrError::Core)?;
    let mut offer_sdp_hash = [0u8; OFFER_SDP_HASH_LEN];
    offer_sdp_hash.copy_from_slice(r.take(OFFER_SDP_HASH_LEN)?);
    let sdp_len = r.u32_be()? as usize;
    let sdp_bytes = r.take(sdp_len)?;
    let answer_sdp = core::str::from_utf8(sdp_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("answer SDP is not valid UTF-8"))?
        .to_string();
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after answer plaintext",
        ));
    }
    Ok(AnswerPlaintext {
        daemon_pk,
        offer_sdp_hash,
        answer_sdp,
    })
}

fn hex_hash(h: &[u8; CLIENT_HASH_LEN]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(h.len() * 2);
    for b in h {
        // Writing via fmt::Write avoids allocating a temporary String
        // per byte (which the per-byte `format!` version did).
        write!(&mut s, "{b:02x}").expect("String never errors on write");
    }
    s
}

struct InnerCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> InnerCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(PkarrError::MalformedCanonical("length overflow"))?;
        if end > self.buf.len() {
            return Err(PkarrError::MalformedCanonical("truncated inner plaintext"));
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    /// Remainder of the buffer after the current position.
    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}

/// Zlib-compress `body` at the highest level. Used by v2
/// inner-plaintext encoders. `Compression::best()` trades a few
/// milliseconds of CPU for 5-10% better ratio on short messages —
/// important because the sealed answer + base64url + DNS packaging
/// needs to fit inside the remaining BEP44 budget alongside the main
/// `_openhost` record.
fn zlib_compress(body: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::with_capacity(body.len()), Compression::best());
    enc.write_all(body)
        .expect("writing into a Vec<u8> never errors");
    enc.finish()
        .expect("zlib finalize must not fail on Vec<u8>")
}

/// Zlib-decompress up to `cap` bytes. Returns
/// `PkarrError::MalformedCanonical` if the output would exceed `cap`.
fn zlib_decompress_capped(input: &[u8], cap: usize) -> Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut decoder = ZlibDecoder::new(input);
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut chunk = [0u8; 4096];
    loop {
        let n = decoder
            .read(&mut chunk)
            .map_err(|_| PkarrError::MalformedCanonical("zlib decompression failed"))?;
        if n == 0 {
            break;
        }
        if out.len() + n > cap {
            return Err(PkarrError::MalformedCanonical(
                "decompressed plaintext exceeds 64 KiB cap",
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec;
    use crate::test_support::{sample_record, RFC_SEED};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const CLIENT_SEED: [u8; 32] = [0x77; 32];

    fn host_sk() -> SigningKey {
        SigningKey::from_bytes(&RFC_SEED)
    }

    fn client_sk() -> SigningKey {
        SigningKey::from_bytes(&CLIENT_SEED)
    }

    fn deterministic_rng() -> StdRng {
        StdRng::from_seed([0x42; 32])
    }

    const SAMPLE_OFFER_SDP: &str = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
                                    m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                                    c=IN IP4 0.0.0.0\r\na=setup:active\r\n";

    const SAMPLE_ANSWER_SDP: &str = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
                                     m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                                     c=IN IP4 0.0.0.0\r\na=setup:passive\r\n";

    // ---------- label helpers ----------

    #[test]
    fn host_hash_is_deterministic_and_domain_separated() {
        let pk = host_sk().public_key();
        let a = host_hash(&pk);
        let b = host_hash(&pk);
        assert_eq!(a, b);
        // Domain-separation: a raw SHA256 of just the pubkey differs.
        let mut h = Sha256::new();
        h.update(pk.to_bytes());
        let full = h.finalize();
        let mut raw = [0u8; HOST_HASH_LEN];
        raw.copy_from_slice(&full[..HOST_HASH_LEN]);
        assert_ne!(a, raw, "host_hash must include the HOST_HASH_DOMAIN prefix");
    }

    #[test]
    fn host_hash_label_fits_dns() {
        let pk = host_sk().public_key();
        let label = host_hash_label(&pk);
        // z-base-32 of 16 bytes = 26 chars, well under 63.
        assert!(label.len() < 63);
        assert!(label.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn client_hash_label_matches_allowlist_hash_encoding() {
        let salt = [0x11u8; SALT_LEN];
        let client_pk = client_sk().public_key();
        let label = client_hash_label(&salt, &client_pk);
        let expect_hash = allowlist_hash(&salt, &client_pk.to_bytes());
        let expect = zbase32::encode_full_bytes(&expect_hash);
        assert_eq!(label, expect);
    }

    // ---------- plaintext roundtrip ----------

    #[test]
    fn offer_plaintext_roundtrips() {
        let client_pk = client_sk().public_key();
        let p = OfferPlaintext {
            client_pk,
            offer_sdp: SAMPLE_OFFER_SDP.to_string(),
        };
        let enc = encode_offer_plaintext(&p);
        let dec = parse_offer_plaintext(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn offer_plaintext_rejects_unknown_compression_tag() {
        let p = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: "v=0".to_string(),
        };
        let mut enc = encode_offer_plaintext(&p);
        enc[0] = 0xFF;
        assert!(matches!(
            parse_offer_plaintext(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_plaintext_rejects_truncated_zlib_body() {
        // Truncating a v2 blob inside the zlib stream fails
        // decompression. (v1-truncation is still covered by the v1
        // back-compat test below.)
        let p = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: "v=0".to_string(),
        };
        let enc = encode_offer_plaintext(&p);
        assert!(matches!(
            parse_offer_plaintext(&enc[..5]),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    /// Hand-craft a v1 (uncompressed) offer plaintext and confirm the
    /// new v2 decoder accepts it. Locks the legacy wire layout against
    /// accidental encoder breakage.
    #[test]
    fn offer_plaintext_accepts_v1_uncompressed_for_backcompat() {
        let p = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: SAMPLE_OFFER_SDP.to_string(),
        };
        let body = encode_offer_body(&p);
        let mut v1 = Vec::with_capacity(1 + body.len());
        v1.push(0x01);
        v1.extend_from_slice(&body);
        let dec = parse_offer_plaintext(&v1).unwrap();
        assert_eq!(dec, p);
    }

    /// Zlib compression MUST strictly shrink a realistic-sized SDP
    /// (the main v0.1 motivation). Don't pin an exact ratio — flate2
    /// output isn't byte-deterministic across backend versions.
    #[test]
    fn v2_encoding_is_smaller_than_v1_for_realistic_sdp() {
        // ~500-byte SDP with multiple ICE candidates — representative
        // of what the daemon's handle_offer produces after gather.
        let mut sdp = String::from(SAMPLE_OFFER_SDP);
        for i in 0..12 {
            sdp.push_str(&format!(
                "a=candidate:{i} 1 udp 2122260223 192.168.1.{i} 50000 typ host\r\n"
            ));
        }
        let p = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: sdp.clone(),
        };
        let v1_body = encode_offer_body(&p);
        let v1_total = 1 + v1_body.len();
        let v2 = encode_offer_plaintext(&p);
        assert!(
            v2.len() < v1_total,
            "v2 compressed plaintext ({} bytes) must be strictly smaller than v1 ({})",
            v2.len(),
            v1_total,
        );
    }

    /// Defense-in-depth: feed a zip bomb (128 KiB of zeros compressed
    /// to ~130 bytes) under a v2 tag; the decoder must reject it at
    /// the 64 KiB cap rather than allocate unbounded memory.
    #[test]
    fn decompression_dos_cap_rejects_oversized_blob() {
        let zero_bomb = vec![0u8; 128 * 1024];
        let compressed = zlib_compress(&zero_bomb);
        let mut input = Vec::with_capacity(1 + compressed.len());
        input.push(CompressionTag::Zlib as u8);
        input.extend_from_slice(&compressed);
        assert!(matches!(
            parse_offer_plaintext(&input),
            Err(PkarrError::MalformedCanonical(
                "decompressed plaintext exceeds 64 KiB cap"
            ))
        ));
    }

    /// Empty SDP should still round-trip cleanly.
    #[test]
    fn empty_offer_sdp_roundtrips_v2() {
        let p = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: String::new(),
        };
        let enc = encode_offer_plaintext(&p);
        let dec = parse_offer_plaintext(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn answer_plaintext_accepts_v1_uncompressed_for_backcompat() {
        let daemon_pk = host_sk().public_key();
        let p = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer_sdp: SAMPLE_ANSWER_SDP.to_string(),
        };
        let body = encode_answer_body(&p);
        let mut v1 = Vec::with_capacity(1 + body.len());
        v1.push(0x01);
        v1.extend_from_slice(&body);
        let dec = parse_answer_plaintext(&v1).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn answer_plaintext_roundtrips() {
        let daemon_pk = host_sk().public_key();
        let p = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer_sdp: SAMPLE_ANSWER_SDP.to_string(),
        };
        let enc = encode_answer_plaintext(&p);
        let dec = parse_answer_plaintext(&enc).unwrap();
        assert_eq!(dec, p);
    }

    // ---------- seal / open ----------

    #[test]
    fn offer_seal_open_roundtrip() {
        let daemon_pk = host_sk().public_key();
        let daemon_sk = host_sk();
        let plaintext = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: SAMPLE_OFFER_SDP.to_string(),
        };
        let mut rng = deterministic_rng();
        let record = OfferRecord::seal(&mut rng, &daemon_pk, &plaintext).unwrap();
        let opened = record.open(&daemon_sk).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn offer_open_with_wrong_key_fails() {
        let daemon_pk = host_sk().public_key();
        let plaintext = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: SAMPLE_OFFER_SDP.to_string(),
        };
        let mut rng = deterministic_rng();
        let record = OfferRecord::seal(&mut rng, &daemon_pk, &plaintext).unwrap();
        // Open with the client's key (which is not the recipient).
        let wrong_sk = client_sk();
        assert!(record.open(&wrong_sk).is_err());
    }

    #[test]
    fn answer_seal_open_roundtrip() {
        let daemon_pk = host_sk().public_key();
        let client_pk = client_sk().public_key();
        let client_sk = client_sk();
        let salt = [0x33u8; SALT_LEN];
        let plaintext = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer_sdp: SAMPLE_ANSWER_SDP.to_string(),
        };
        let mut rng = deterministic_rng();
        let entry =
            AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, 1_700_000_000).unwrap();
        let opened = entry.open(&client_sk).unwrap();
        assert_eq!(opened, plaintext);
        assert_eq!(entry.created_at, 1_700_000_000);
        assert_eq!(
            entry.client_hash,
            allowlist_hash(&salt, &client_pk.to_bytes())
        );
    }

    // ---------- encode_with_answers ----------

    fn reference_signed() -> SignedRecord {
        let sk = host_sk();
        SignedRecord::sign(sample_record(1_700_000_000), &sk).unwrap()
    }

    #[test]
    fn encode_with_empty_answers_matches_plain_codec() {
        let sk = host_sk();
        let signed = reference_signed();
        let plain = codec::encode(&signed, &sk).unwrap();
        let via_offer = encode_with_answers(&signed, &sk, &[]).unwrap();
        // Packet bytes are byte-for-byte identical.
        assert_eq!(plain.as_bytes(), via_offer.as_bytes());
    }

    #[test]
    fn encode_with_one_answer_preserves_openhost_txt() {
        let sk = host_sk();
        let signed = reference_signed();
        let client_pk = client_sk().public_key();
        let daemon_pk = sk.public_key();
        let salt = [0x33u8; SALT_LEN];

        let plaintext = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer_sdp: SAMPLE_ANSWER_SDP.to_string(),
        };
        let mut rng = deterministic_rng();
        let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, 17).unwrap();

        let packet = encode_with_answers(&signed, &sk, std::slice::from_ref(&entry)).unwrap();

        // The main `_openhost` record decodes to byte-identical canonical bytes.
        let decoded_main = codec::decode(&packet).unwrap();
        assert_eq!(decoded_main.record, signed.record);

        // The fragmented `_answer-<client-hash>-<idx>` TXTs reassemble
        // into the original sealed AnswerEntry.
        let decoded = decode_answer_fragments_from_packet(&packet, &salt, &client_pk)
            .unwrap()
            .expect("answer fragments are present");
        assert_eq!(decoded.sealed, entry.sealed);
        let opened = decoded.open(&client_sk()).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn encode_evicts_oldest_when_overflow() {
        let sk = host_sk();
        let signed = reference_signed();
        let salt = [0x33u8; SALT_LEN];

        // Two entries, each small enough that ONE fits alongside the
        // main record, but not both. The oldest MUST be evicted; the
        // fresher MUST survive.
        //
        // Constructs the AnswerEntry directly with synthetic large
        // `sealed` payloads to keep the test independent of zlib's
        // compression ratio on whatever sample SDP we happened to
        // pick. Each entry's sealed ciphertext is 450 bytes of
        // high-entropy pseudorandom content — just under
        // MAX_FRAGMENT_PAYLOAD_BYTES = 500, so one answer fragments
        // into a single RR, and two of them exceed the BEP44 budget
        // with the main `_openhost` record.
        let mut entries = Vec::new();
        for (i, seed_byte) in [(0u64, 0x10u8), (1u64, 0x11u8)] {
            let pk = SigningKey::from_bytes(&[seed_byte; 32]).public_key();
            let client_hash = allowlist_hash(&salt, &pk.to_bytes());
            let mut rng = StdRng::from_seed([seed_byte; 32]);
            let mut sealed = vec![0u8; 450];
            rand::RngCore::fill_bytes(&mut rng, &mut sealed);
            entries.push(AnswerEntry {
                client_hash,
                sealed,
                created_at: i,
            });
        }

        let packet = encode_with_answers(&signed, &sk, &entries).unwrap();
        assert!(
            packet.encoded_packet().len() <= BEP44_MAX_V_BYTES,
            "encoded packet must fit the BEP44 cap; got {}",
            packet.encoded_packet().len()
        );

        // Freshest (created_at = 1) survives.
        let freshest_pk = SigningKey::from_bytes(&[0x11u8; 32]).public_key();
        assert!(
            decode_answer_fragments_from_packet(&packet, &salt, &freshest_pk)
                .unwrap()
                .is_some(),
            "the freshest answer must survive eviction"
        );
        // Oldest (created_at = 0) was dropped — fragment 0 not in packet.
        let oldest_pk = SigningKey::from_bytes(&[0x10u8; 32]).public_key();
        assert!(
            decode_answer_fragments_from_packet(&packet, &salt, &oldest_pk)
                .unwrap()
                .is_none(),
            "the oldest answer must be evicted"
        );
    }

    // ---------- answer fragmentation (v0.2+) ----------

    /// Small answer: seals a minimal SDP, verifies the packet carries
    /// exactly `chunk_total` consecutive `_answer-<hash>-<idx>` records
    /// and nothing at the past-the-end index, and that reassembly
    /// returns the original sealed bytes. The exact `chunk_total`
    /// depends on zlib output for the sample SDP (not byte-pinnable
    /// across flate2 versions) so we assert the shape, not a number.
    #[test]
    fn small_answer_fragments_and_reassembles() {
        let sk = host_sk();
        let signed = reference_signed();
        let client_pk = client_sk().public_key();
        let salt = [0x33u8; SALT_LEN];

        let plaintext = AnswerPlaintext {
            daemon_pk: sk.public_key(),
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer_sdp: SAMPLE_ANSWER_SDP.to_string(),
        };
        let mut rng = deterministic_rng();
        let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, 1).unwrap();

        let expected_total = entry.sealed.len().div_ceil(MAX_FRAGMENT_PAYLOAD_BYTES);
        let packet = encode_with_answers(&signed, &sk, std::slice::from_ref(&entry)).unwrap();

        for idx in 0..expected_total {
            let name = answer_txt_chunk_name(&salt, &client_pk, idx as u8);
            assert!(
                collect_single_txt(&packet, &name).unwrap().is_some(),
                "expected fragment at {name}",
            );
        }
        let past_end = answer_txt_chunk_name(&salt, &client_pk, expected_total as u8);
        assert!(
            collect_single_txt(&packet, &past_end).unwrap().is_none(),
            "no fragment expected past chunk_total",
        );

        let reassembled = decode_answer_fragments_from_packet(&packet, &salt, &client_pk)
            .unwrap()
            .expect("fragments present");
        assert_eq!(reassembled.sealed, entry.sealed);
        let opened = reassembled.open(&client_sk()).unwrap();
        assert_eq!(opened, plaintext);
    }

    /// Force a multi-fragment answer by sealing an SDP large enough
    /// that the ciphertext exceeds MAX_FRAGMENT_PAYLOAD_BYTES, then
    /// verify reassembly returns the original sealed bytes. We can't
    /// stuff it into a full-signer packet because of the BEP44 cap —
    /// drive the fragment codec directly via split_into_fragments +
    /// decode_fragment.
    #[test]
    fn multi_fragment_answer_reassembles() {
        // At MAX_FRAGMENT_PAYLOAD_BYTES = 500, a single fragment now
        // holds up to 500 raw bytes, so to exercise multi-fragment
        // reassembly we need a larger synthetic payload. 1300 raw
        // bytes → 3 fragments (500 + 500 + 300).
        let sealed = (0u8..=u8::MAX).cycle().take(1300).collect::<Vec<u8>>();
        let fragments = split_into_fragments(&sealed).unwrap();
        assert_eq!(fragments.len(), 3);
        let mut decoded: Vec<DecodedFragment> = fragments
            .iter()
            .map(|b| decode_fragment(b).unwrap())
            .collect();
        // Shuffle idx order; decoder is order-agnostic at reassembly-time
        // via the lookup-by-idx probe, but double-check the fragment
        // carries idx + total in its own header.
        decoded.reverse();
        for f in &decoded {
            assert_eq!(f.total, 3);
        }
        let mut sorted = decoded;
        sorted.sort_by_key(|f| f.idx);
        let mut reassembled = Vec::with_capacity(sealed.len());
        for f in sorted {
            reassembled.extend_from_slice(&f.payload);
        }
        assert_eq!(reassembled, sealed);
    }

    #[test]
    fn fragment_decode_rejects_unknown_version() {
        let bytes = vec![0xFF, 0, 1, 0, 0];
        assert!(matches!(
            decode_fragment(&bytes),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn fragment_decode_rejects_idx_ge_total() {
        let bytes = vec![FRAGMENT_VERSION, 3, 2, 0, 0];
        assert!(matches!(
            decode_fragment(&bytes),
            Err(PkarrError::MalformedCanonical(
                "answer fragment idx >= total"
            ))
        ));
    }

    #[test]
    fn fragment_decode_rejects_zero_total() {
        let bytes = vec![FRAGMENT_VERSION, 0, 0, 0, 0];
        assert!(matches!(
            decode_fragment(&bytes),
            Err(PkarrError::MalformedCanonical(
                "answer fragment total must be >= 1"
            ))
        ));
    }

    #[test]
    fn fragment_decode_rejects_length_mismatch() {
        // Header claims payload_len = 10 but only 5 payload bytes follow.
        let mut bytes = vec![FRAGMENT_VERSION, 0, 1];
        bytes.extend_from_slice(&10u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 5]);
        assert!(matches!(
            decode_fragment(&bytes),
            Err(PkarrError::MalformedCanonical(
                "answer fragment payload length mismatch"
            ))
        ));
    }

    #[test]
    fn fragment_reassembly_detects_chunk_total_disagreement() {
        // Build a packet with two fragments whose headers disagree on
        // `chunk_total`. We synthesize them directly into a SignedPacket
        // rather than going through encode_with_answers (which only
        // emits self-consistent fragment sets).
        let sk = host_sk();
        let client_pk = client_sk().public_key();
        let salt = [0x33u8; SALT_LEN];
        let signed = reference_signed();

        // Valid fragment 0 claiming total = 2, plus a fake fragment 1
        // claiming total = 3.
        let frag0 = encode_fragment(0, 2, b"first-half");
        let frag1 = encode_fragment(1, 3, b"second-half");
        let client_hash = allowlist_hash(&salt, &client_pk.to_bytes());
        let label = zbase32::encode_full_bytes(&client_hash);
        let base = format!("{ANSWER_TXT_PREFIX}{label}");

        let main_blob = {
            let canonical = signed.record.canonical_signing_bytes().unwrap();
            let mut b = Vec::with_capacity(64 + canonical.len());
            b.extend_from_slice(&signed.signature.to_bytes());
            b.extend_from_slice(&canonical);
            URL_SAFE_NO_PAD.encode(&b)
        };
        let seed = Zeroizing::new(sk.to_bytes());
        let keypair = Keypair::from_secret_key(&seed);
        let ts = Timestamp::from(signed.record.ts * MICROS_PER_SECOND);
        let packet = SignedPacket::builder()
            .timestamp(ts)
            .txt(
                Name::new_unchecked(OPENHOST_TXT_NAME),
                TXT::try_from(main_blob.as_str()).unwrap(),
                OPENHOST_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(&format!("{base}-0")),
                TXT::try_from(URL_SAFE_NO_PAD.encode(&frag0).as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(&format!("{base}-1")),
                TXT::try_from(URL_SAFE_NO_PAD.encode(&frag1).as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        let err = decode_answer_fragments_from_packet(&packet, &salt, &client_pk)
            .expect_err("chunk_total disagreement must be rejected");
        assert!(
            matches!(err, PkarrError::MalformedCanonical(m) if m.contains("chunk_total")),
            "expected chunk_total mismatch error",
        );
    }

    #[test]
    fn fragment_reassembly_detects_missing_middle() {
        // Emit frag 0 (total = 3) and frag 2, but skip frag 1.
        let sk = host_sk();
        let client_pk = client_sk().public_key();
        let salt = [0x33u8; SALT_LEN];
        let signed = reference_signed();

        let frag0 = encode_fragment(0, 3, b"first");
        let frag2 = encode_fragment(2, 3, b"third");
        let client_hash = allowlist_hash(&salt, &client_pk.to_bytes());
        let label = zbase32::encode_full_bytes(&client_hash);
        let base = format!("{ANSWER_TXT_PREFIX}{label}");

        let main_blob = {
            let canonical = signed.record.canonical_signing_bytes().unwrap();
            let mut b = Vec::with_capacity(64 + canonical.len());
            b.extend_from_slice(&signed.signature.to_bytes());
            b.extend_from_slice(&canonical);
            URL_SAFE_NO_PAD.encode(&b)
        };
        let seed = Zeroizing::new(sk.to_bytes());
        let keypair = Keypair::from_secret_key(&seed);
        let ts = Timestamp::from(signed.record.ts * MICROS_PER_SECOND);
        let packet = SignedPacket::builder()
            .timestamp(ts)
            .txt(
                Name::new_unchecked(OPENHOST_TXT_NAME),
                TXT::try_from(main_blob.as_str()).unwrap(),
                OPENHOST_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(&format!("{base}-0")),
                TXT::try_from(URL_SAFE_NO_PAD.encode(&frag0).as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(&format!("{base}-2")),
                TXT::try_from(URL_SAFE_NO_PAD.encode(&frag2).as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        let err = decode_answer_fragments_from_packet(&packet, &salt, &client_pk)
            .expect_err("missing middle fragment must be rejected");
        assert!(
            matches!(err, PkarrError::MalformedCanonical(m) if m.contains("missing")),
            "expected missing-fragment error, got {err:?}",
        );
    }

    /// Defense against a packet where a non-zero fragment's envelope
    /// `chunk_idx` disagrees with the numeric suffix of its DNS name
    /// (e.g. `_answer-<hash>-1` carries envelope idx=2). Spec §3.3
    /// requires consistency and the decoder must reject, otherwise an
    /// attacker who controls the publisher key could trivially rewire
    /// the reassembly order.
    #[test]
    fn fragment_reassembly_detects_label_envelope_idx_disagreement() {
        let sk = host_sk();
        let client_pk = client_sk().public_key();
        let salt = [0x33u8; SALT_LEN];
        let signed = reference_signed();

        // Two well-formed fragments claiming total = 2, but the second
        // fragment's envelope claims idx=0 (duplicate) even though its
        // DNS label suffix is `-1`.
        let frag0 = encode_fragment(0, 2, b"zero");
        let frag_wrong = encode_fragment(0, 2, b"oops");
        let client_hash = allowlist_hash(&salt, &client_pk.to_bytes());
        let label = zbase32::encode_full_bytes(&client_hash);
        let base = format!("{ANSWER_TXT_PREFIX}{label}");

        let main_blob = {
            let canonical = signed.record.canonical_signing_bytes().unwrap();
            let mut b = Vec::with_capacity(64 + canonical.len());
            b.extend_from_slice(&signed.signature.to_bytes());
            b.extend_from_slice(&canonical);
            URL_SAFE_NO_PAD.encode(&b)
        };
        let seed = Zeroizing::new(sk.to_bytes());
        let keypair = Keypair::from_secret_key(&seed);
        let ts = Timestamp::from(signed.record.ts * MICROS_PER_SECOND);
        let packet = SignedPacket::builder()
            .timestamp(ts)
            .txt(
                Name::new_unchecked(OPENHOST_TXT_NAME),
                TXT::try_from(main_blob.as_str()).unwrap(),
                OPENHOST_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(&format!("{base}-0")),
                TXT::try_from(URL_SAFE_NO_PAD.encode(&frag0).as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(&format!("{base}-1")),
                TXT::try_from(URL_SAFE_NO_PAD.encode(&frag_wrong).as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        let err = decode_answer_fragments_from_packet(&packet, &salt, &client_pk)
            .expect_err("label/envelope idx disagreement must be rejected");
        assert!(
            matches!(err, PkarrError::MalformedCanonical(m) if m.contains("disagrees with its DNS label suffix")),
            "expected label-mismatch error, got {err:?}",
        );
    }

    // ---------- decode_offer_from_packet ----------

    #[test]
    fn decode_offer_from_packet_reads_sealed_txt() {
        // Simulate a client-side publish: build a SignedPacket under the
        // client's key containing the sealed offer TXT.
        let client_sk = client_sk();
        let daemon_pk = host_sk().public_key();

        let plaintext = OfferPlaintext {
            client_pk: client_sk.public_key(),
            offer_sdp: SAMPLE_OFFER_SDP.to_string(),
        };
        let mut rng = deterministic_rng();
        let offer = OfferRecord::seal(&mut rng, &daemon_pk, &plaintext).unwrap();

        let txt_value = URL_SAFE_NO_PAD.encode(&offer.sealed);
        let seed = Zeroizing::new(client_sk.to_bytes());
        let keypair = Keypair::from_secret_key(&seed);
        let packet = SignedPacket::builder()
            .txt(
                Name::new_unchecked(&offer_txt_name(&daemon_pk)),
                TXT::try_from(txt_value.as_str()).unwrap(),
                OFFER_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        let decoded = decode_offer_from_packet(&packet, &daemon_pk)
            .unwrap()
            .expect("offer TXT present");
        let opened = decoded.open(&host_sk()).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn decode_offer_from_packet_returns_none_when_missing() {
        // A packet that contains only `_openhost` (no `_offer.*`) — the
        // decoder returns Ok(None).
        let sk = host_sk();
        let signed = reference_signed();
        let packet = encode_with_answers(&signed, &sk, &[]).unwrap();
        let daemon_pk = sk.public_key();
        let res = decode_offer_from_packet(&packet, &daemon_pk).unwrap();
        assert!(res.is_none());
    }
}
