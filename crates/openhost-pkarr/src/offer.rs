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

/// Domain separator for the v1 offer inner plaintext body. Still
/// accepted on decode for backwards compatibility; v1 bodies carry no
/// explicit `binding_mode` byte and default to
/// [`BindingMode::Exporter`]. New encoders emit v2 via
/// [`OFFER_INNER_DOMAIN_V2`].
pub const OFFER_INNER_DOMAIN_V1: &[u8] = b"openhost-offer-inner1";

/// Alias for [`OFFER_INNER_DOMAIN_V1`]. Retained for downstream
/// diagnostic tooling that referenced the pre-PR-28.3 constant name.
pub const OFFER_INNER_DOMAIN: &[u8] = OFFER_INNER_DOMAIN_V1;

/// Domain separator for the v2 offer inner plaintext body (PR #28.3+).
/// v2 appends a 1-byte `binding_mode` field after the SDP so browsers
/// can advertise cert-fingerprint binding (see [`BindingMode`]).
pub const OFFER_INNER_DOMAIN_V2: &[u8] = b"openhost-offer-inner2";

/// Domain separator for the v3 offer inner plaintext body
/// (compact-offer-blob PR). v3 replaces the full SDP with a binary
/// [`OfferBlob`] so Chrome-generated SDPs (~1100 bytes raw) fit
/// alongside the DNS and pkarr overhead in BEP44's 1000-byte packet
/// cap. Symmetric to `openhost-answer-inner2` on the answer side.
pub const OFFER_INNER_DOMAIN_V3: &[u8] = b"openhost-offer-inner3";

/// Domain separator for the v1 answer inner plaintext body. Still
/// accepted on decode (legacy daemons publishing full SDPs); new
/// encoders emit v2 via [`ANSWER_INNER_DOMAIN_V2`].
pub const ANSWER_INNER_DOMAIN_V1: &[u8] = b"openhost-answer-inner1";

/// Alias for [`ANSWER_INNER_DOMAIN_V1`]. Retained for downstream
/// diagnostic tooling that referenced the pre-PR-32 constant name.
pub const ANSWER_INNER_DOMAIN: &[u8] = ANSWER_INNER_DOMAIN_V1;

/// Domain separator for the v2 answer inner plaintext body (PR #32+).
/// v2 replaces the full SDP with a compact binary [`AnswerBlob`] so the
/// sealed + fragmented packet fits inside BEP44's 1000-byte `v` cap
/// alongside the main `_openhost` record. Clients reconstruct a
/// minimal-but-valid SDP at consumption time using the host's DTLS
/// fingerprint (already pinned under the outer BEP44 signature via the
/// main record).
pub const ANSWER_INNER_DOMAIN_V2: &[u8] = b"openhost-answer-inner2";

/// Channel-binding mode advertised by the client in an offer plaintext.
///
/// - [`Exporter`][BindingMode::Exporter]: RFC 5705 DTLS exporter bytes
///   feed the channel-binding HMAC (the original CLI-to-CLI path).
///   Spec reference: `spec/04-security.md §7.6` "exporter binding."
/// - [`CertFp`][BindingMode::CertFp]: SHA-256 of the host's DTLS
///   certificate DER substitutes for the exporter bytes. Required for
///   browser clients — `RTCDtlsTransport` does not expose the RFC 5705
///   exporter today. The cert fingerprint is pinned via Pkarr so an
///   attacker who forges a matching fingerprint has already broken the
///   host's Ed25519 identity key; the security delta vs. Exporter is
///   therefore near-zero for openhost's threat model. See
///   `spec/04-security.md §7.6` "cert-fingerprint binding."
///
/// Wire format: 1 byte. `0x01` = Exporter, `0x02` = CertFp, other
/// values rejected on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BindingMode {
    /// RFC 5705 DTLS exporter binding (CLI default).
    Exporter = 0x01,
    /// SHA-256-of-cert-DER binding (browser-mandatory).
    CertFp = 0x02,
}

impl BindingMode {
    /// Encode the mode as the single byte that lands on the wire.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse a wire byte into a `BindingMode`. Unknown bytes are a
    /// hard decode error — the shim must refuse to speak an unknown
    /// binding protocol.
    pub fn try_from_u8(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Self::Exporter),
            0x02 => Ok(Self::CertFp),
            _ => Err(PkarrError::MalformedCanonical(
                "unknown offer binding_mode byte",
            )),
        }
    }
}

/// DTLS `a=setup:` role carried inside a compact offer / answer blob.
///
/// Valid values per blob type:
///
/// - **Answer blob** ([`AnswerBlob`]): only `Active` or `Passive`.
///   The daemon always picks a concrete role; `Actpass` in an answer
///   SDP is a spec violation and the encoder rejects it.
/// - **Offer blob** ([`OfferBlob`]): `Active` (CLI convention) or
///   `Actpass` (browser convention — Chrome emits `a=setup:actpass`
///   on every offer so the answerer picks). `Passive` in an offer
///   flips the DTLS roles against spec and is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SetupRole {
    /// `a=setup:active` — the side that initiates the DTLS handshake.
    Active = 0,
    /// `a=setup:passive` — the side that waits for DTLS ClientHello.
    Passive = 1,
    /// `a=setup:actpass` — either role is acceptable; answerer picks.
    /// Valid in offers only.
    Actpass = 2,
}

impl SetupRole {
    /// SDP-textual form (`"active"`, `"passive"`, or `"actpass"`) used
    /// when reconstructing the minimal SDP on the consumer side.
    #[must_use]
    pub fn as_sdp_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Passive => "passive",
            Self::Actpass => "actpass",
        }
    }
}

/// ICE candidate type. Mirrors the lowercase strings that appear in
/// SDP `a=candidate:` lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CandidateType {
    /// Local interface address.
    Host = 0,
    /// Server-reflexive (learned via STUN).
    Srflx = 1,
    /// Peer-reflexive (learned via an inbound connectivity check).
    Prflx = 2,
    /// Relayed (TURN).
    Relay = 3,
}

impl CandidateType {
    /// SDP `typ` string used when reconstructing `a=candidate:` lines.
    #[must_use]
    pub fn as_sdp_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Srflx => "srflx",
            Self::Prflx => "prflx",
            Self::Relay => "relay",
        }
    }

    fn from_u8(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Self::Host),
            1 => Ok(Self::Srflx),
            2 => Ok(Self::Prflx),
            3 => Ok(Self::Relay),
            _ => Err(PkarrError::MalformedCanonical(
                "unknown answer-blob candidate type",
            )),
        }
    }
}

/// One ICE candidate carried inside an [`AnswerBlob`]. The blob omits
/// foundation, priority, component, and transport: at consumption time
/// the client synthesises a stable placeholder foundation (`1`),
/// priority (`1`), component (`1`), and transport (`udp`), since the
/// openhost handshake only ever uses UDP and a single RTP component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobCandidate {
    /// Candidate type (host/srflx/prflx/relay).
    pub typ: CandidateType,
    /// IPv4 or IPv6 address. v2 encoders MUST emit only IPv4 (mirrors
    /// the PR #31 candidate-hygiene filter); IPv6 is reserved for a
    /// future encoder bump when multi-fragment headroom is explicit.
    pub ip: std::net::IpAddr,
    /// UDP port.
    pub port: u16,
}

/// Compact binary representation of a WebRTC answer. Replaces the full
/// SDP in v2 answer records. The client reconstructs a minimal valid
/// SDP from these fields plus the host's DTLS fingerprint.
///
/// Wire layout (inside the v2 answer body, after the 22-byte domain,
/// 32-byte `daemon_pk`, 32-byte `offer_sdp_hash`, and a `u16` blob
/// length prefix):
///
/// ```text
/// version      : u8 (0x01)
/// flags        : u8  (bit 0 = setup_role: 0=active, 1=passive; rest MUST be 0)
/// ufrag_len    : u8  (4..=32 per RFC 8445 §5.3)
/// ufrag        : <ufrag_len> ASCII bytes
/// pwd_len      : u8  (22..=32 per RFC 8445 §5.3)
/// pwd          : <pwd_len> ASCII bytes
/// cand_count   : u8  (0..=MAX_BLOB_CANDIDATES)
/// candidates[] : cand_count entries of:
///                  typ    : u8   (CandidateType)
///                  family : u8   (4 | 6)
///                  addr   : 4 or 16 bytes
///                  port   : u16 big-endian
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerBlob {
    /// ICE ufrag — MUST be 4..=32 ASCII bytes (RFC 8445 §5.3).
    pub ice_ufrag: String,
    /// ICE pwd — MUST be 22..=32 ASCII bytes (RFC 8445 §5.3).
    pub ice_pwd: String,
    /// Setup role emitted by the daemon.
    pub setup: SetupRole,
    /// Post-gather-complete candidate list. Length bounded by
    /// [`MAX_BLOB_CANDIDATES`].
    pub candidates: Vec<BlobCandidate>,
}

/// Plaintext answer payload carried inside an [`AnswerPlaintext`].
/// v1 is decode-only (legacy daemons shipping a full SDP); all v2+
/// emitters MUST produce [`AnswerPayload::V2Blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnswerPayload {
    /// v1 answer body: the daemon's full SDP as a string. Post-PR-32
    /// emitters never produce this variant; it exists so clients can
    /// still consume answers from pre-PR-32 daemons during rollout.
    V1Sdp(String),
    /// v2 answer body: compact binary blob (see [`AnswerBlob`]).
    V2Blob(AnswerBlob),
}

/// Version byte at the front of the v2 answer blob body.
const ANSWER_BLOB_VERSION: u8 = 0x01;

/// Compact binary representation of a WebRTC offer. Replaces the full
/// SDP in v3 offer records. Symmetric to [`AnswerBlob`]: carries only
/// the fields the daemon cannot derive from its own state. The
/// daemon reconstructs a minimal valid SDP from these fields at
/// consumption time.
///
/// Wire layout (inside the v3 offer body, after the 21-byte domain,
/// 32-byte `client_pk`, and a `u16` blob length prefix):
///
/// ```text
/// version         : u8 (0x01)
/// flags           : u8
///                    bits 0-1: setup_role (0=Active, 1=Passive, 2=Actpass; 3 reserved)
///                    bit   2 : binding_mode (0=Exporter, 1=CertFp)
///                    bits 3-7: reserved, MUST be 0
/// ufrag_len       : u8 (MIN_ICE_UFRAG_LEN..=MAX_ICE_UFRAG_LEN)
/// ufrag           : <ufrag_len> ASCII bytes
/// pwd_len         : u8 (MIN_ICE_PWD_LEN..=MAX_ICE_PWD_LEN)
/// pwd             : <pwd_len> ASCII bytes
/// client_dtls_fp  : 32 bytes (SHA-256 of client DTLS cert DER)
/// cand_count      : u8 (0..=MAX_BLOB_CANDIDATES)
/// candidates[]    : cand_count entries of:
///                     typ    : u8   (CandidateType)
///                     family : u8   (4 | 6)
///                     addr   : 4 or 16 bytes
///                     port   : u16 big-endian
/// ```
///
/// Unlike the answer side, the client's DTLS fingerprint IS carried
/// in the blob. The answer side can pin its fingerprint via the
/// long-lived pkarr `_openhost` record signed under the outer BEP44
/// signature, but clients have no equivalent persistent record, so
/// the fingerprint piggybacks on the offer. Integrity is provided by
/// the sealed-box addressed to the daemon (any modification of the
/// ciphertext causes unseal to fail) plus the client's Ed25519
/// signature on the enclosing BEP44 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferBlob {
    /// ICE ufrag — MUST be 4..=32 ASCII bytes (RFC 8445 §5.3).
    pub ice_ufrag: String,
    /// ICE pwd — MUST be 22..=32 ASCII bytes (RFC 8445 §5.3).
    pub ice_pwd: String,
    /// DTLS `a=setup:` role the client advertises. CLI offers emit
    /// `Active`; browser offers emit `Actpass`. `Passive` is rejected
    /// on encode — it would flip the DTLS roles against spec §3.1.
    pub setup: SetupRole,
    /// Channel-binding mode the client will use post-DTLS. Browser
    /// offers always emit `CertFp`; CLI offers emit `Exporter` unless
    /// a future config flag opts into `CertFp`.
    pub binding_mode: BindingMode,
    /// SHA-256 of the client's DTLS certificate DER. Required so the
    /// daemon can verify the incoming DTLS handshake terminates at the
    /// same client whose Ed25519 key signed the BEP44 outer packet.
    pub client_dtls_fp: [u8; DTLS_FP_LEN],
    /// Post-gather-complete candidate list. Length bounded by
    /// [`MAX_BLOB_CANDIDATES`].
    pub candidates: Vec<BlobCandidate>,
}

/// Plaintext offer payload carried inside an [`OfferPlaintext`].
/// v1 and v2 full-SDP shapes stay decode-only; all v3+ emitters MUST
/// produce [`OfferPayload::V3Blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferPayload {
    /// Legacy v1 / v2 offer body: a full SDP string. Decode-only in
    /// post-compact-offer-blob daemons; retained so CLI clients
    /// dialing a pre-rollout host still round-trip.
    LegacySdp(String),
    /// v3 offer body: compact binary blob (see [`OfferBlob`]).
    V3Blob(OfferBlob),
}

/// Version byte at the front of the v3 offer blob body.
const OFFER_BLOB_VERSION: u8 = 0x01;

/// Ceiling on the offer blob byte length. A fully-packed blob with
/// 8 IPv4 candidates, 32-byte ufrag, 32-byte pwd, and 32-byte DTLS
/// fingerprint weighs ~170 bytes; 512 gives ~3× headroom while
/// bounding decoder work.
pub const MAX_OFFER_BLOB_LEN: usize = 512;

/// Ceiling on the blob byte length carried in the `u16` length prefix.
/// A fully-packed blob with 8 IPv4 candidates, a 32-byte ufrag, and a
/// 32-byte pwd weighs ~140 bytes; 512 gives ~3.5× headroom against
/// future encoder drift without allowing a malicious decoder DoS.
pub const MAX_ANSWER_BLOB_LEN: usize = 512;

/// Ceiling on the per-blob candidate count. Post-PR-31 filters reduce
/// a typical answer to 1 srflx + 0-3 host candidates; 8 still leaves
/// room for multi-interface hosts.
pub const MAX_BLOB_CANDIDATES: usize = 8;

/// Minimum ICE ufrag length per RFC 8445 §5.3.
pub const MIN_ICE_UFRAG_LEN: usize = 4;
/// Maximum ICE ufrag length per RFC 8445 §5.3.
pub const MAX_ICE_UFRAG_LEN: usize = 32;
/// Minimum ICE pwd length per RFC 8445 §5.3.
pub const MIN_ICE_PWD_LEN: usize = 22;
/// Maximum ICE pwd length per RFC 8445 §5.3.
pub const MAX_ICE_PWD_LEN: usize = 32;

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
    /// Carried offer, either the legacy v1/v2 full-SDP form
    /// (decode-only) or the v3 compact binary blob (the only form new
    /// emitters produce).
    pub offer: OfferPayload,
    /// Channel-binding mode the client will use on the resulting data
    /// channel. v1 offer bodies on the wire carry no binding_mode byte
    /// and decode with [`BindingMode::Exporter`]; v2 bodies carry it
    /// explicitly; v3 bodies carry it inside the blob's flags byte.
    pub binding_mode: BindingMode,
}

impl OfferPlaintext {
    /// Legacy-SDP constructor for tests and decode round-trips.
    /// Stores the SDP as [`OfferPayload::LegacySdp`] so the encode
    /// path will reject it (emitters must produce v3 blobs); use
    /// [`OfferPlaintext::new_v3`] to build an emittable plaintext.
    #[must_use]
    pub fn new(client_pk: PublicKey, offer_sdp: String) -> Self {
        Self {
            client_pk,
            offer: OfferPayload::LegacySdp(offer_sdp),
            binding_mode: BindingMode::Exporter,
        }
    }

    /// v3-blob constructor — the form every post-compact-offer
    /// emitter produces.
    #[must_use]
    pub fn new_v3(client_pk: PublicKey, blob: OfferBlob) -> Self {
        let binding_mode = blob.binding_mode;
        Self {
            client_pk,
            offer: OfferPayload::V3Blob(blob),
            binding_mode,
        }
    }
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
    /// Carried answer, either the v1 full-SDP form (decode-only) or
    /// the v2 compact binary blob (the only form new emitters produce).
    pub answer: AnswerPayload,
}

impl AnswerPlaintext {
    /// Convenience constructor matching the pre-PR-32 field set; the
    /// passed-in SDP string is stored as [`AnswerPayload::V1Sdp`]. Used
    /// by tests that still want to exercise the legacy decode path
    /// without hand-constructing an `AnswerPayload`.
    #[must_use]
    pub fn new_v1(
        daemon_pk: PublicKey,
        offer_sdp_hash: [u8; OFFER_SDP_HASH_LEN],
        answer_sdp: String,
    ) -> Self {
        Self {
            daemon_pk,
            offer_sdp_hash,
            answer: AnswerPayload::V1Sdp(answer_sdp),
        }
    }

    /// Convenience constructor for the v2 compact-blob answer — the
    /// form every post-PR-32 emitter produces.
    #[must_use]
    pub fn new_v2(
        daemon_pk: PublicKey,
        offer_sdp_hash: [u8; OFFER_SDP_HASH_LEN],
        blob: AnswerBlob,
    ) -> Self {
        Self {
            daemon_pk,
            offer_sdp_hash,
            answer: AnswerPayload::V2Blob(blob),
        }
    }
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
        let inner = encode_offer_plaintext(plaintext)?;
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
        let inner = encode_answer_plaintext(plaintext)?;
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

/// Encode an offer body. v3 (compact blob, `openhost-offer-inner3`)
/// is the only shape emitters produce; v1/v2 are decode-only and
/// [`encode_offer_body`] will panic in debug builds if handed a
/// [`OfferPayload::LegacySdp`] — use [`OfferPlaintext::new_v3`].
///
/// Wire layout for v3:
///
/// ```text
/// domain(OFFER_INNER_DOMAIN_V3) || client_pk(32B) ||
/// blob_len(u16 BE, ≤ MAX_OFFER_BLOB_LEN) || blob(blob_len bytes)
/// ```
fn encode_offer_body(p: &OfferPlaintext) -> Result<Vec<u8>> {
    let blob = match &p.offer {
        OfferPayload::V3Blob(b) => b,
        OfferPayload::LegacySdp(_) => {
            debug_assert!(
                false,
                "openhost-pkarr: emitters MUST produce v3 OfferBlob; LegacySdp is decode-only",
            );
            return Err(PkarrError::MalformedCanonical(
                "encoders MUST emit v3 offer blobs — OfferPayload::LegacySdp is decode-only",
            ));
        }
    };
    let blob_bytes = encode_offer_blob(blob)?;
    let mut out =
        Vec::with_capacity(OFFER_INNER_DOMAIN_V3.len() + PUBLIC_KEY_LEN + 2 + blob_bytes.len());
    out.extend_from_slice(OFFER_INNER_DOMAIN_V3);
    out.extend_from_slice(&p.client_pk.to_bytes());
    let len = u16::try_from(blob_bytes.len()).expect("blob_bytes ≤ MAX_OFFER_BLOB_LEN < u16::MAX");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&blob_bytes);
    Ok(out)
}

/// Serialise an [`OfferBlob`] to its on-wire byte form. Validates
/// RFC 8445 §5.3 ufrag/pwd length bounds, setup-role validity for
/// offers, and the per-blob candidate ceiling.
pub fn encode_offer_blob(b: &OfferBlob) -> Result<Vec<u8>> {
    let ufrag_bytes = b.ice_ufrag.as_bytes();
    if ufrag_bytes.len() < MIN_ICE_UFRAG_LEN || ufrag_bytes.len() > MAX_ICE_UFRAG_LEN {
        return Err(PkarrError::MalformedCanonical(
            "OfferBlob ice_ufrag length violates RFC 8445 §5.3 bounds",
        ));
    }
    if !b.ice_ufrag.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "OfferBlob ice_ufrag must be ASCII",
        ));
    }
    let pwd_bytes = b.ice_pwd.as_bytes();
    if pwd_bytes.len() < MIN_ICE_PWD_LEN || pwd_bytes.len() > MAX_ICE_PWD_LEN {
        return Err(PkarrError::MalformedCanonical(
            "OfferBlob ice_pwd length violates RFC 8445 §5.3 bounds",
        ));
    }
    if !b.ice_pwd.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "OfferBlob ice_pwd must be ASCII",
        ));
    }
    if b.candidates.len() > MAX_BLOB_CANDIDATES {
        return Err(PkarrError::MalformedCanonical(
            "OfferBlob candidates exceed MAX_BLOB_CANDIDATES",
        ));
    }

    // Setup-role bits 0-1 of the flags byte. `Passive` is a spec
    // violation for offers (it flips DTLS roles); the encoder refuses
    // to emit it so a bug upstream becomes a loud error rather than
    // silently broken negotiation.
    let setup_bits: u8 = match b.setup {
        SetupRole::Active => 0b00,
        SetupRole::Actpass => 0b10,
        SetupRole::Passive => return Err(PkarrError::MalformedCanonical(
            "OfferBlob setup_role must not be Passive (would flip DTLS roles against spec §3.1)",
        )),
    };
    let binding_bit: u8 = match b.binding_mode {
        BindingMode::Exporter => 0b000,
        BindingMode::CertFp => 0b100,
    };
    let flags = setup_bits | binding_bit;

    let mut out = Vec::with_capacity(80);
    out.push(OFFER_BLOB_VERSION);
    out.push(flags);
    out.push(ufrag_bytes.len() as u8);
    out.extend_from_slice(ufrag_bytes);
    out.push(pwd_bytes.len() as u8);
    out.extend_from_slice(pwd_bytes);
    out.extend_from_slice(&b.client_dtls_fp);
    out.push(b.candidates.len() as u8);
    for cand in &b.candidates {
        out.push(cand.typ as u8);
        match cand.ip {
            std::net::IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&cand.port.to_be_bytes());
    }
    if out.len() > MAX_OFFER_BLOB_LEN {
        return Err(PkarrError::MalformedCanonical(
            "encoded OfferBlob exceeds MAX_OFFER_BLOB_LEN",
        ));
    }
    Ok(out)
}

/// Parse an [`OfferBlob`] from its on-wire byte form. Strict inverse
/// of [`encode_offer_blob`]: unknown versions, reserved-flag-bits,
/// candidate types, address families, or length bounds all produce
/// [`PkarrError::MalformedCanonical`].
pub fn parse_offer_blob(bytes: &[u8]) -> Result<OfferBlob> {
    if bytes.len() > MAX_OFFER_BLOB_LEN {
        return Err(PkarrError::MalformedCanonical(
            "offer blob exceeds MAX_OFFER_BLOB_LEN",
        ));
    }
    let mut r = InnerCursor::new(bytes);
    let version = r.u8()?;
    if version != OFFER_BLOB_VERSION {
        return Err(PkarrError::MalformedCanonical("unknown offer-blob version"));
    }
    let flags = r.u8()?;
    // Bits 3-7 are reserved and MUST be 0; anything else is a hard
    // decode error so future encoder versions don't silently get
    // ignored.
    if flags & 0b1111_1000 != 0 {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob reserved flag bits must be zero",
        ));
    }
    let setup = match flags & 0b0000_0011 {
        0b00 => SetupRole::Active,
        0b01 => SetupRole::Passive,
        0b10 => SetupRole::Actpass,
        _ => {
            return Err(PkarrError::MalformedCanonical(
                "offer-blob reserved setup_role bit pattern",
            ))
        }
    };
    // Offer-blob invariant: setup MUST NOT be Passive (would flip DTLS
    // roles). The encoder rejects it; the decoder does too so a rogue
    // peer can't smuggle a malformed blob past us.
    if matches!(setup, SetupRole::Passive) {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob setup_role Passive is a spec violation",
        ));
    }
    let binding_mode = if flags & 0b0000_0100 == 0 {
        BindingMode::Exporter
    } else {
        BindingMode::CertFp
    };

    let ufrag_len = r.u8()? as usize;
    if !(MIN_ICE_UFRAG_LEN..=MAX_ICE_UFRAG_LEN).contains(&ufrag_len) {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob ice_ufrag length violates RFC 8445 §5.3 bounds",
        ));
    }
    let ufrag_bytes = r.take(ufrag_len)?;
    if !ufrag_bytes.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob ice_ufrag must be ASCII",
        ));
    }
    let ice_ufrag = core::str::from_utf8(ufrag_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("offer-blob ice_ufrag is not UTF-8"))?
        .to_string();

    let pwd_len = r.u8()? as usize;
    if !(MIN_ICE_PWD_LEN..=MAX_ICE_PWD_LEN).contains(&pwd_len) {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob ice_pwd length violates RFC 8445 §5.3 bounds",
        ));
    }
    let pwd_bytes = r.take(pwd_len)?;
    if !pwd_bytes.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob ice_pwd must be ASCII",
        ));
    }
    let ice_pwd = core::str::from_utf8(pwd_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("offer-blob ice_pwd is not UTF-8"))?
        .to_string();

    let mut client_dtls_fp = [0u8; DTLS_FP_LEN];
    client_dtls_fp.copy_from_slice(r.take(DTLS_FP_LEN)?);

    let cand_count = r.u8()? as usize;
    if cand_count > MAX_BLOB_CANDIDATES {
        return Err(PkarrError::MalformedCanonical(
            "offer-blob candidate count exceeds MAX_BLOB_CANDIDATES",
        ));
    }
    let mut candidates = Vec::with_capacity(cand_count);
    for _ in 0..cand_count {
        let typ = CandidateType::from_u8(r.u8()?)?;
        let family = r.u8()?;
        let ip = match family {
            4 => {
                let b = r.take(4)?;
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            6 => {
                let b = r.take(16)?;
                let mut arr = [0u8; 16];
                arr.copy_from_slice(b);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr))
            }
            _ => {
                return Err(PkarrError::MalformedCanonical(
                    "offer-blob candidate family must be 4 or 6",
                ));
            }
        };
        let port = r.u16_be()?;
        candidates.push(BlobCandidate { typ, ip, port });
    }
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after offer blob",
        ));
    }
    Ok(OfferBlob {
        ice_ufrag,
        ice_pwd,
        setup,
        binding_mode,
        client_dtls_fp,
        candidates,
    })
}

/// Parse an offer body. Dispatches on the 21-byte domain-separator
/// prefix: `openhost-offer-inner1` and `openhost-offer-inner2` yield
/// [`OfferPayload::LegacySdp`] (full SDP, decode-only);
/// `openhost-offer-inner3` yields [`OfferPayload::V3Blob`] with a
/// compact binary blob.
fn parse_offer_body(body: &[u8]) -> Result<OfferPlaintext> {
    if body.len() < OFFER_INNER_DOMAIN_V1.len() {
        return Err(PkarrError::MalformedCanonical(
            "offer plaintext shorter than domain separator",
        ));
    }
    let domain = &body[..OFFER_INNER_DOMAIN_V1.len()];
    if domain == OFFER_INNER_DOMAIN_V3 {
        return parse_offer_body_v3(body);
    }
    let is_v2 = domain == OFFER_INNER_DOMAIN_V2;
    let is_v1 = domain == OFFER_INNER_DOMAIN_V1;
    if !is_v1 && !is_v2 {
        return Err(PkarrError::MalformedCanonical(
            "unknown openhost-offer-inner domain separator",
        ));
    }

    let mut r = InnerCursor::new(body);
    let _domain = r.take(OFFER_INNER_DOMAIN_V1.len())?;
    let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
    pk_bytes.copy_from_slice(r.take(PUBLIC_KEY_LEN)?);
    let client_pk = PublicKey::from_bytes(&pk_bytes).map_err(PkarrError::Core)?;
    let sdp_len = r.u32_be()? as usize;
    let sdp_bytes = r.take(sdp_len)?;
    let offer_sdp = core::str::from_utf8(sdp_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("offer SDP is not valid UTF-8"))?
        .to_string();
    let binding_mode = if is_v2 {
        let b = r.u8()?;
        BindingMode::try_from_u8(b)?
    } else {
        BindingMode::Exporter
    };
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after offer plaintext",
        ));
    }
    Ok(OfferPlaintext {
        client_pk,
        offer: OfferPayload::LegacySdp(offer_sdp),
        binding_mode,
    })
}

fn parse_offer_body_v3(body: &[u8]) -> Result<OfferPlaintext> {
    let mut r = InnerCursor::new(body);
    let _domain = r.take(OFFER_INNER_DOMAIN_V3.len())?;
    let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
    pk_bytes.copy_from_slice(r.take(PUBLIC_KEY_LEN)?);
    let client_pk = PublicKey::from_bytes(&pk_bytes).map_err(PkarrError::Core)?;
    let blob_len = r.u16_be()? as usize;
    if blob_len > MAX_OFFER_BLOB_LEN {
        return Err(PkarrError::MalformedCanonical(
            "v3 offer blob_len exceeds MAX_OFFER_BLOB_LEN",
        ));
    }
    let blob_bytes = r.take(blob_len)?;
    let blob = parse_offer_blob(blob_bytes)?;
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after v3 offer plaintext",
        ));
    }
    let binding_mode = blob.binding_mode;
    Ok(OfferPlaintext {
        client_pk,
        offer: OfferPayload::V3Blob(blob),
        binding_mode,
    })
}

/// Encode a zlib-compressed offer inner plaintext. The body emitted
/// here is the v3 compact-blob form; v1/v2 are decode-only.
fn encode_offer_plaintext(p: &OfferPlaintext) -> Result<Vec<u8>> {
    let body = encode_offer_body(p)?;
    let compressed = zlib_compress(&body);
    let mut out = Vec::with_capacity(1 + compressed.len());
    out.push(CompressionTag::Zlib as u8);
    out.extend_from_slice(&compressed);
    Ok(out)
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

/// Encode an answer body. v2 (compact blob, `openhost-answer-inner2`)
/// is the only shape emitters produce; v1 is decode-only and
/// [`encode_answer_body`] will panic in debug builds if handed a
/// [`AnswerPayload::V1Sdp`] — use a v2 blob.
///
/// Wire layout for v2:
///
/// ```text
/// domain(ANSWER_INNER_DOMAIN_V2) || daemon_pk(32B) ||
/// offer_sdp_hash(32B) || blob_len(u16 BE, ≤ MAX_ANSWER_BLOB_LEN) || blob(blob_len bytes)
/// ```
fn encode_answer_body(p: &AnswerPlaintext) -> Result<Vec<u8>> {
    let blob = match &p.answer {
        AnswerPayload::V2Blob(b) => b,
        AnswerPayload::V1Sdp(_) => {
            debug_assert!(
                false,
                "openhost-pkarr: emitters MUST produce v2 AnswerBlob; V1Sdp is decode-only",
            );
            return Err(PkarrError::MalformedCanonical(
                "encoders MUST emit v2 answer blobs — AnswerPayload::V1Sdp is decode-only",
            ));
        }
    };
    let blob_bytes = encode_answer_blob(blob)?;
    let mut out = Vec::with_capacity(
        ANSWER_INNER_DOMAIN_V2.len() + PUBLIC_KEY_LEN + OFFER_SDP_HASH_LEN + 2 + blob_bytes.len(),
    );
    out.extend_from_slice(ANSWER_INNER_DOMAIN_V2);
    out.extend_from_slice(&p.daemon_pk.to_bytes());
    out.extend_from_slice(&p.offer_sdp_hash);
    let len = u16::try_from(blob_bytes.len()).expect("blob_bytes ≤ MAX_ANSWER_BLOB_LEN < u16::MAX");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&blob_bytes);
    Ok(out)
}

/// Serialise an [`AnswerBlob`] to its on-wire byte form. Validates
/// RFC 8445 §5.3 ufrag/pwd length bounds, the reserved-flag-bits
/// invariant, and the per-blob candidate ceiling.
pub fn encode_answer_blob(b: &AnswerBlob) -> Result<Vec<u8>> {
    let ufrag_bytes = b.ice_ufrag.as_bytes();
    if ufrag_bytes.len() < MIN_ICE_UFRAG_LEN || ufrag_bytes.len() > MAX_ICE_UFRAG_LEN {
        return Err(PkarrError::MalformedCanonical(
            "AnswerBlob ice_ufrag length violates RFC 8445 §5.3 bounds",
        ));
    }
    if !b.ice_ufrag.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "AnswerBlob ice_ufrag must be ASCII",
        ));
    }
    let pwd_bytes = b.ice_pwd.as_bytes();
    if pwd_bytes.len() < MIN_ICE_PWD_LEN || pwd_bytes.len() > MAX_ICE_PWD_LEN {
        return Err(PkarrError::MalformedCanonical(
            "AnswerBlob ice_pwd length violates RFC 8445 §5.3 bounds",
        ));
    }
    if !b.ice_pwd.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "AnswerBlob ice_pwd must be ASCII",
        ));
    }
    if b.candidates.len() > MAX_BLOB_CANDIDATES {
        return Err(PkarrError::MalformedCanonical(
            "AnswerBlob candidates exceed MAX_BLOB_CANDIDATES",
        ));
    }

    let mut out = Vec::with_capacity(32);
    out.push(ANSWER_BLOB_VERSION);
    // Flags byte: only bit 0 is allocated to setup_role (0=active, 1=passive);
    // remaining bits MUST be zero on the wire (enforced on decode).
    let flags: u8 =
        match b.setup {
            SetupRole::Active => 0b0000_0000,
            SetupRole::Passive => 0b0000_0001,
            SetupRole::Actpass => return Err(PkarrError::MalformedCanonical(
                "AnswerBlob setup_role must not be Actpass (answerer MUST pick a concrete role)",
            )),
        };
    out.push(flags);
    out.push(ufrag_bytes.len() as u8);
    out.extend_from_slice(ufrag_bytes);
    out.push(pwd_bytes.len() as u8);
    out.extend_from_slice(pwd_bytes);
    out.push(b.candidates.len() as u8);
    for cand in &b.candidates {
        out.push(cand.typ as u8);
        match cand.ip {
            std::net::IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&cand.port.to_be_bytes());
    }
    if out.len() > MAX_ANSWER_BLOB_LEN {
        return Err(PkarrError::MalformedCanonical(
            "encoded AnswerBlob exceeds MAX_ANSWER_BLOB_LEN",
        ));
    }
    Ok(out)
}

/// Parse an [`AnswerBlob`] from its on-wire byte form. Strict inverse
/// of [`encode_answer_blob`]: unknown versions, reserved-flag-bits,
/// candidate types, address families, or length bounds all produce
/// [`PkarrError::MalformedCanonical`].
pub fn parse_answer_blob(bytes: &[u8]) -> Result<AnswerBlob> {
    if bytes.len() > MAX_ANSWER_BLOB_LEN {
        return Err(PkarrError::MalformedCanonical(
            "answer blob exceeds MAX_ANSWER_BLOB_LEN",
        ));
    }
    let mut r = InnerCursor::new(bytes);
    let version = r.u8()?;
    if version != ANSWER_BLOB_VERSION {
        return Err(PkarrError::MalformedCanonical(
            "unknown answer-blob version",
        ));
    }
    let flags = r.u8()?;
    // Only bit 0 is defined; any other bit set is a hard decode error
    // so future encoder versions don't silently get ignored.
    if flags & 0b1111_1110 != 0 {
        return Err(PkarrError::MalformedCanonical(
            "answer-blob reserved flag bits must be zero",
        ));
    }
    let setup = if flags & 0b0000_0001 == 0 {
        SetupRole::Active
    } else {
        SetupRole::Passive
    };
    let ufrag_len = r.u8()? as usize;
    if !(MIN_ICE_UFRAG_LEN..=MAX_ICE_UFRAG_LEN).contains(&ufrag_len) {
        return Err(PkarrError::MalformedCanonical(
            "answer-blob ice_ufrag length violates RFC 8445 §5.3 bounds",
        ));
    }
    let ufrag_bytes = r.take(ufrag_len)?;
    if !ufrag_bytes.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "answer-blob ice_ufrag must be ASCII",
        ));
    }
    let ice_ufrag = core::str::from_utf8(ufrag_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("answer-blob ice_ufrag is not UTF-8"))?
        .to_string();
    let pwd_len = r.u8()? as usize;
    if !(MIN_ICE_PWD_LEN..=MAX_ICE_PWD_LEN).contains(&pwd_len) {
        return Err(PkarrError::MalformedCanonical(
            "answer-blob ice_pwd length violates RFC 8445 §5.3 bounds",
        ));
    }
    let pwd_bytes = r.take(pwd_len)?;
    if !pwd_bytes.is_ascii() {
        return Err(PkarrError::MalformedCanonical(
            "answer-blob ice_pwd must be ASCII",
        ));
    }
    let ice_pwd = core::str::from_utf8(pwd_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("answer-blob ice_pwd is not UTF-8"))?
        .to_string();
    let cand_count = r.u8()? as usize;
    if cand_count > MAX_BLOB_CANDIDATES {
        return Err(PkarrError::MalformedCanonical(
            "answer-blob candidate count exceeds MAX_BLOB_CANDIDATES",
        ));
    }
    let mut candidates = Vec::with_capacity(cand_count);
    for _ in 0..cand_count {
        let typ = CandidateType::from_u8(r.u8()?)?;
        let family = r.u8()?;
        let ip = match family {
            4 => {
                let b = r.take(4)?;
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            }
            6 => {
                let b = r.take(16)?;
                let mut arr = [0u8; 16];
                arr.copy_from_slice(b);
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr))
            }
            _ => {
                return Err(PkarrError::MalformedCanonical(
                    "answer-blob candidate family must be 4 or 6",
                ));
            }
        };
        let port = r.u16_be()?;
        candidates.push(BlobCandidate { typ, ip, port });
    }
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after answer blob",
        ));
    }
    Ok(AnswerBlob {
        ice_ufrag,
        ice_pwd,
        setup,
        candidates,
    })
}

/// Encode a zlib-compressed answer inner plaintext. The body emitted
/// here is the v2 compact-blob form; v1 is decode-only.
fn encode_answer_plaintext(p: &AnswerPlaintext) -> Result<Vec<u8>> {
    let body = encode_answer_body(p)?;
    let compressed = zlib_compress(&body);
    let mut out = Vec::with_capacity(1 + compressed.len());
    out.push(CompressionTag::Zlib as u8);
    out.extend_from_slice(&compressed);
    Ok(out)
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

/// Parse an answer body. Dispatches on the domain-separator prefix:
/// `openhost-answer-inner1` yields a v1 [`AnswerPayload::V1Sdp`] with
/// a full SDP string (legacy); `openhost-answer-inner2` yields a v2
/// [`AnswerPayload::V2Blob`] with a compact binary blob.
fn parse_answer_body(body: &[u8]) -> Result<AnswerPlaintext> {
    if body.len() < ANSWER_INNER_DOMAIN_V1.len() {
        return Err(PkarrError::MalformedCanonical(
            "answer plaintext shorter than domain separator",
        ));
    }
    let domain = &body[..ANSWER_INNER_DOMAIN_V1.len()];
    if domain == ANSWER_INNER_DOMAIN_V2 {
        parse_answer_body_v2(body)
    } else if domain == ANSWER_INNER_DOMAIN_V1 {
        parse_answer_body_v1(body)
    } else {
        Err(PkarrError::MalformedCanonical(
            "unknown openhost-answer-inner domain separator",
        ))
    }
}

fn parse_answer_body_v1(body: &[u8]) -> Result<AnswerPlaintext> {
    let mut r = InnerCursor::new(body);
    let _domain = r.take(ANSWER_INNER_DOMAIN_V1.len())?;
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
            "trailing bytes after v1 answer plaintext",
        ));
    }
    Ok(AnswerPlaintext {
        daemon_pk,
        offer_sdp_hash,
        answer: AnswerPayload::V1Sdp(answer_sdp),
    })
}

fn parse_answer_body_v2(body: &[u8]) -> Result<AnswerPlaintext> {
    let mut r = InnerCursor::new(body);
    let _domain = r.take(ANSWER_INNER_DOMAIN_V2.len())?;
    let mut pk_bytes = [0u8; PUBLIC_KEY_LEN];
    pk_bytes.copy_from_slice(r.take(PUBLIC_KEY_LEN)?);
    let daemon_pk = PublicKey::from_bytes(&pk_bytes).map_err(PkarrError::Core)?;
    let mut offer_sdp_hash = [0u8; OFFER_SDP_HASH_LEN];
    offer_sdp_hash.copy_from_slice(r.take(OFFER_SDP_HASH_LEN)?);
    let blob_len = r.u16_be()? as usize;
    if blob_len > MAX_ANSWER_BLOB_LEN {
        return Err(PkarrError::MalformedCanonical(
            "v2 answer blob_len exceeds MAX_ANSWER_BLOB_LEN",
        ));
    }
    let blob_bytes = r.take(blob_len)?;
    let blob = parse_answer_blob(blob_bytes)?;
    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after v2 answer plaintext",
        ));
    }
    Ok(AnswerPlaintext {
        daemon_pk,
        offer_sdp_hash,
        answer: AnswerPayload::V2Blob(blob),
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
    fn u16_be(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
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

/// DTLS fingerprint byte length — SHA-256 output.
pub const DTLS_FP_LEN: usize = 32;

/// Reconstruct a minimal but webrtc-rs + Chromium-compatible SDP
/// answer from a compact [`AnswerBlob`] + the host's already-verified
/// DTLS certificate fingerprint. Produced string matches what
/// legacy v1 answer records used to carry verbatim.
///
/// Implementation notes:
///
/// - `o=` origin session-id / version / `IN IP4 0.0.0.0` — safe
///   placeholders; neither webrtc-rs nor Chromium trust them for
///   anything load-bearing.
/// - `m=application 9 UDP/DTLS/SCTP webrtc-datachannel` with
///   `a=rtcp-mux` ⇒ one component, matches the daemon's generation.
/// - `a=sctp-port:5000` matches webrtc-rs's default (pion's too); if
///   the daemon ever drifts from 5000 the offer will still negotiate
///   because the offerer echoes what it received.
/// - `a=fingerprint:sha-256 <colon-hex>` is the load-bearing field —
///   it binds the DTLS handshake to the pkarr record's pinned
///   fingerprint, which is verified under the BEP44 signature before
///   the blob is ever opened.
/// - Each candidate synthesises a foundation of `1` and priority of
///   `1`: the offerer's pairing logic uses the
///   (local-candidate, remote-candidate) tuple for pair keys, so
///   placeholder values don't confuse it. `generation 0` is emitted
///   to match webrtc-rs's own answer output shape.
///
/// The output always ends with CRLF, matches the daemon-generated
/// SDP byte-for-byte in the fields the peers actually consume.
#[must_use]
pub fn answer_blob_to_sdp(blob: &AnswerBlob, dtls_fp: &[u8; DTLS_FP_LEN]) -> String {
    let fp_hex = colon_hex_upper(dtls_fp);
    let mut s = String::with_capacity(512);
    s.push_str("v=0\r\n");
    s.push_str("o=- 1 1 IN IP4 0.0.0.0\r\n");
    s.push_str("s=-\r\n");
    s.push_str("t=0 0\r\n");
    s.push_str("a=group:BUNDLE 0\r\n");
    s.push_str("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
    s.push_str("c=IN IP4 0.0.0.0\r\n");
    s.push_str("a=mid:0\r\n");
    s.push_str("a=rtcp-mux\r\n");
    s.push_str(&format!("a=ice-ufrag:{}\r\n", blob.ice_ufrag));
    s.push_str(&format!("a=ice-pwd:{}\r\n", blob.ice_pwd));
    s.push_str(&format!("a=fingerprint:sha-256 {fp_hex}\r\n"));
    s.push_str(&format!("a=setup:{}\r\n", blob.setup.as_sdp_str()));
    s.push_str("a=sctp-port:5000\r\n");
    for cand in &blob.candidates {
        s.push_str(&format!(
            "a=candidate:1 1 udp 1 {ip} {port} typ {typ} generation 0\r\n",
            ip = cand.ip,
            port = cand.port,
            typ = cand.typ.as_sdp_str(),
        ));
    }
    s.push_str("a=end-of-candidates\r\n");
    s
}

/// Extract an [`OfferBlob`] from a full SDP offer plus the client's
/// DTLS fingerprint. Mirrors `sdp_to_answer_blob` in the daemon's
/// listener crate, kept in this crate so both the CLI dialer and the
/// browser-extension WASM call into one codec. Candidate-hygiene
/// filters (IPv4 only, component-1 only, ≤[`MAX_BLOB_CANDIDATES`])
/// apply here so both call sites emit the same byte-identical blob.
///
/// `client_dtls_fp` is the SHA-256 of the client's DTLS certificate
/// DER. On webrtc-rs, obtain via
/// `RTCCertificate::get_fingerprints()`. On Chrome, pull it out of
/// the SDP itself (the `a=fingerprint:sha-256 <colon-hex>` line) —
/// see `extract_client_dtls_fp_from_sdp`.
///
/// Returns a structural error if the SDP is missing required
/// attributes or the fingerprint doesn't decode to 32 bytes.
pub fn sdp_to_offer_blob(
    sdp: &str,
    client_dtls_fp: &[u8; DTLS_FP_LEN],
    binding_mode: BindingMode,
) -> Result<OfferBlob> {
    let mut ice_ufrag: Option<String> = None;
    let mut ice_pwd: Option<String> = None;
    let mut setup: Option<SetupRole> = None;
    let mut candidates: Vec<BlobCandidate> = Vec::new();

    for raw_line in sdp.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("a=ice-ufrag:") {
            ice_ufrag = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=ice-pwd:") {
            ice_pwd = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("a=setup:") {
            setup = Some(match rest.trim() {
                "active" => SetupRole::Active,
                "actpass" => SetupRole::Actpass,
                // "passive" in an offer flips DTLS roles against
                // spec §3.1 — refuse. "holdconn" is similarly invalid.
                _ => {
                    return Err(PkarrError::MalformedCanonical(
                        "offer SDP a=setup must be active or actpass",
                    ))
                }
            });
        } else if let Some(rest) = line.strip_prefix("a=candidate:") {
            if let Some(cand) = parse_sdp_candidate_line(rest) {
                if candidates.len() < MAX_BLOB_CANDIDATES {
                    candidates.push(cand);
                }
                // else silently drop — hygiene-trim only emits MAX,
                // the daemon's reconstruction is happy with fewer.
            }
        }
    }

    Ok(OfferBlob {
        ice_ufrag: ice_ufrag.ok_or(PkarrError::MalformedCanonical(
            "offer SDP missing a=ice-ufrag",
        ))?,
        ice_pwd: ice_pwd.ok_or(PkarrError::MalformedCanonical(
            "offer SDP missing a=ice-pwd",
        ))?,
        setup: setup.ok_or(PkarrError::MalformedCanonical("offer SDP missing a=setup"))?,
        binding_mode,
        client_dtls_fp: *client_dtls_fp,
        candidates,
    })
}

/// Extract the SHA-256 `a=fingerprint` value from an SDP. Browser
/// callers need this to feed [`sdp_to_offer_blob`] — the browser
/// doesn't surface `RTCCertificate`'s raw DER so we pull the hash
/// from the SDP text itself, which the browser generates internally.
pub fn extract_sha256_fingerprint_from_sdp(sdp: &str) -> Result<[u8; DTLS_FP_LEN]> {
    for raw_line in sdp.lines() {
        let line = raw_line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("a=fingerprint:") {
            // Shape: "sha-256 AA:BB:CC:..." — we accept only sha-256.
            let mut parts = rest.trim().split_ascii_whitespace();
            match parts.next() {
                Some(alg) if alg.eq_ignore_ascii_case("sha-256") => {}
                _ => continue,
            }
            let hex_colon = parts.next().ok_or(PkarrError::MalformedCanonical(
                "a=fingerprint line missing hex component",
            ))?;
            return parse_colon_hex(hex_colon);
        }
    }
    Err(PkarrError::MalformedCanonical(
        "offer SDP missing a=fingerprint:sha-256 line",
    ))
}

fn parse_colon_hex(s: &str) -> Result<[u8; DTLS_FP_LEN]> {
    let mut out = [0u8; DTLS_FP_LEN];
    let mut idx = 0;
    for byte_str in s.split(':') {
        if idx >= DTLS_FP_LEN {
            return Err(PkarrError::MalformedCanonical(
                "DTLS fingerprint has more than 32 hex bytes",
            ));
        }
        if byte_str.len() != 2 {
            return Err(PkarrError::MalformedCanonical(
                "DTLS fingerprint byte must be exactly 2 hex chars",
            ));
        }
        out[idx] = u8::from_str_radix(byte_str, 16)
            .map_err(|_| PkarrError::MalformedCanonical("DTLS fingerprint byte not hex"))?;
        idx += 1;
    }
    if idx != DTLS_FP_LEN {
        return Err(PkarrError::MalformedCanonical(
            "DTLS fingerprint must be exactly 32 hex bytes",
        ));
    }
    Ok(out)
}

/// Parse the post-`a=candidate:` portion of one SDP candidate line
/// into a [`BlobCandidate`]. Returns `None` if the candidate fails
/// any hygiene filter (component ≠ 1, transport ≠ udp, IPv6,
/// unknown type) so the caller can skip it rather than blowing up
/// the whole blob. Private to this module — symmetric daemons have
/// their own copy in `listener.rs`.
fn parse_sdp_candidate_line(rest: &str) -> Option<BlobCandidate> {
    let mut toks = rest.split_whitespace();
    let _foundation = toks.next()?;
    let component = toks.next()?;
    if component != "1" {
        return None;
    }
    let transport = toks.next()?;
    if !transport.eq_ignore_ascii_case("udp") {
        return None;
    }
    let _priority = toks.next()?;
    let addr_s = toks.next()?;
    let port_s = toks.next()?;
    if toks.next() != Some("typ") {
        return None;
    }
    let typ_s = toks.next()?;
    let ip: std::net::IpAddr = addr_s.parse().ok()?;
    let port: u16 = port_s.parse().ok()?;
    // IPv4 only — matches the answer-side filter (PR #31 hygiene).
    let std::net::IpAddr::V4(_) = ip else {
        return None;
    };
    let typ = match typ_s {
        "host" => CandidateType::Host,
        "srflx" => CandidateType::Srflx,
        "prflx" => CandidateType::Prflx,
        "relay" => CandidateType::Relay,
        _ => return None,
    };
    Some(BlobCandidate { typ, ip, port })
}

/// Reconstruct a minimal SDP offer from an [`OfferBlob`]. Symmetric
/// to [`answer_blob_to_sdp`]: the daemon calls this after unsealing a
/// v3 offer to feed webrtc-rs a syntactically complete offer SDP for
/// `set_remote_description`. The client's DTLS fingerprint comes out
/// of the blob directly (it was carried there because clients have
/// no persistent pkarr record to pin it to).
#[must_use]
pub fn offer_blob_to_sdp(blob: &OfferBlob) -> String {
    let fp_hex = colon_hex_upper(&blob.client_dtls_fp);
    let mut s = String::with_capacity(512);
    s.push_str("v=0\r\n");
    s.push_str("o=- 1 1 IN IP4 0.0.0.0\r\n");
    s.push_str("s=-\r\n");
    s.push_str("t=0 0\r\n");
    s.push_str("a=group:BUNDLE 0\r\n");
    s.push_str("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n");
    s.push_str("c=IN IP4 0.0.0.0\r\n");
    s.push_str("a=mid:0\r\n");
    s.push_str("a=rtcp-mux\r\n");
    s.push_str(&format!("a=ice-ufrag:{}\r\n", blob.ice_ufrag));
    s.push_str(&format!("a=ice-pwd:{}\r\n", blob.ice_pwd));
    s.push_str(&format!("a=fingerprint:sha-256 {fp_hex}\r\n"));
    s.push_str(&format!("a=setup:{}\r\n", blob.setup.as_sdp_str()));
    s.push_str("a=sctp-port:5000\r\n");
    for cand in &blob.candidates {
        s.push_str(&format!(
            "a=candidate:1 1 udp 1 {ip} {port} typ {typ} generation 0\r\n",
            ip = cand.ip,
            port = cand.port,
            typ = cand.typ.as_sdp_str(),
        ));
    }
    s.push_str("a=end-of-candidates\r\n");
    s
}

/// Lowercase hex-encode each byte, separated by `:`, matching the
/// `a=fingerprint:sha-256 ...` formatting WebRTC uses. Upper-case is
/// conventional in SDP fingerprints; reconstructor matches that.
fn colon_hex_upper(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        write!(&mut out, "{b:02X}").expect("writing into String never fails");
    }
    out
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

    /// Build a representative v2 blob used as the sample payload in
    /// answer-plaintext tests. One srflx candidate, 4-char ufrag,
    /// 22-char pwd — matches the post-PR-31 daemon output shape.
    fn sample_blob() -> AnswerBlob {
        AnswerBlob {
            ice_ufrag: "abcd".to_string(),
            ice_pwd: "Supercalifragilistic!2".to_string(),
            setup: SetupRole::Passive,
            candidates: vec![BlobCandidate {
                typ: CandidateType::Srflx,
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
                port: 51_820,
            }],
        }
    }

    /// Representative v3 offer blob. Browser-style setup (`actpass`),
    /// CertFp binding, one srflx candidate. Keep in sync with
    /// [`sample_blob`] so tests that exercise both sides use the same
    /// wire shapes.
    fn sample_offer_blob() -> OfferBlob {
        OfferBlob {
            ice_ufrag: "abcd".to_string(),
            ice_pwd: "Supercalifragilistic!2".to_string(),
            setup: SetupRole::Actpass,
            binding_mode: BindingMode::CertFp,
            client_dtls_fp: [0xABu8; DTLS_FP_LEN],
            candidates: vec![BlobCandidate {
                typ: CandidateType::Srflx,
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7)),
                port: 45_678,
            }],
        }
    }

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
    fn offer_plaintext_roundtrips_v3() {
        let client_pk = client_sk().public_key();
        let p = OfferPlaintext::new_v3(client_pk, sample_offer_blob());
        let enc = encode_offer_plaintext(&p).unwrap();
        let dec = parse_offer_plaintext(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn offer_plaintext_rejects_unknown_compression_tag() {
        let client_pk = client_sk().public_key();
        let p = OfferPlaintext::new_v3(client_pk, sample_offer_blob());
        let mut enc = encode_offer_plaintext(&p).unwrap();
        enc[0] = 0xFF;
        assert!(matches!(
            parse_offer_plaintext(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_plaintext_rejects_truncated_zlib_body() {
        // Truncating a compressed offer inside the zlib stream fails
        // decompression.
        let client_pk = client_sk().public_key();
        let p = OfferPlaintext::new_v3(client_pk, sample_offer_blob());
        let enc = encode_offer_plaintext(&p).unwrap();
        assert!(matches!(
            parse_offer_plaintext(&enc[..5]),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    /// Hand-craft a legacy v1 *body* (the pre-PR-28.3 shape: v1 domain
    /// separator, no trailing `binding_mode` byte) wrapped in the
    /// Uncompressed compression tag, and confirm the v3-aware decoder
    /// accepts it as [`OfferPayload::LegacySdp`] with
    /// `binding_mode = Exporter` as the documented default. Locks the
    /// legacy wire layout against accidental decoder breakage.
    #[test]
    fn offer_plaintext_accepts_v1_uncompressed_body_for_backcompat() {
        let client_pk = client_sk().public_key();
        let sdp = SAMPLE_OFFER_SDP.as_bytes();
        let mut body =
            Vec::with_capacity(OFFER_INNER_DOMAIN_V1.len() + PUBLIC_KEY_LEN + 4 + sdp.len());
        body.extend_from_slice(OFFER_INNER_DOMAIN_V1);
        body.extend_from_slice(&client_pk.to_bytes());
        body.extend_from_slice(&u32::try_from(sdp.len()).unwrap().to_be_bytes());
        body.extend_from_slice(sdp);

        let mut wrapped = Vec::with_capacity(1 + body.len());
        wrapped.push(CompressionTag::Uncompressed as u8);
        wrapped.extend_from_slice(&body);

        let dec = parse_offer_plaintext(&wrapped).unwrap();
        assert_eq!(dec.client_pk, client_pk);
        match dec.offer {
            OfferPayload::LegacySdp(s) => assert_eq!(s, SAMPLE_OFFER_SDP),
            OfferPayload::V3Blob(_) => panic!("expected LegacySdp"),
        }
        assert_eq!(
            dec.binding_mode,
            BindingMode::Exporter,
            "v1 bodies must default to Exporter binding",
        );
    }

    /// v2 bodies (pre-compact-offer-blob, full SDP + trailing
    /// binding_mode byte) MUST still decode as [`OfferPayload::LegacySdp`]
    /// for the rollout window.
    #[test]
    fn offer_plaintext_accepts_v2_body_for_backcompat() {
        for mode in [BindingMode::Exporter, BindingMode::CertFp] {
            let client_pk = client_sk().public_key();
            let sdp = SAMPLE_OFFER_SDP.as_bytes();
            let mut body = Vec::with_capacity(
                OFFER_INNER_DOMAIN_V2.len() + PUBLIC_KEY_LEN + 4 + sdp.len() + 1,
            );
            body.extend_from_slice(OFFER_INNER_DOMAIN_V2);
            body.extend_from_slice(&client_pk.to_bytes());
            body.extend_from_slice(&u32::try_from(sdp.len()).unwrap().to_be_bytes());
            body.extend_from_slice(sdp);
            body.push(mode.as_u8());

            let mut wrapped = Vec::with_capacity(1 + body.len());
            wrapped.push(CompressionTag::Uncompressed as u8);
            wrapped.extend_from_slice(&body);

            let dec = parse_offer_plaintext(&wrapped).unwrap();
            match dec.offer {
                OfferPayload::LegacySdp(s) => assert_eq!(s, SAMPLE_OFFER_SDP),
                OfferPayload::V3Blob(_) => panic!("v2 body must decode as LegacySdp"),
            }
            assert_eq!(dec.binding_mode, mode);
        }
    }

    /// A v2 body with a garbage binding_mode byte must be rejected as
    /// malformed — we never silently downgrade to a default mode when
    /// the explicit byte is present but unknown.
    #[test]
    fn offer_plaintext_v2_rejects_unknown_binding_mode_byte() {
        let client_pk = client_sk().public_key();
        let sdp = SAMPLE_OFFER_SDP.as_bytes();
        let mut body =
            Vec::with_capacity(OFFER_INNER_DOMAIN_V2.len() + PUBLIC_KEY_LEN + 4 + sdp.len() + 1);
        body.extend_from_slice(OFFER_INNER_DOMAIN_V2);
        body.extend_from_slice(&client_pk.to_bytes());
        body.extend_from_slice(&u32::try_from(sdp.len()).unwrap().to_be_bytes());
        body.extend_from_slice(sdp);
        body.push(0xFF); // garbage binding_mode

        let mut wrapped = Vec::with_capacity(1 + body.len());
        wrapped.push(CompressionTag::Uncompressed as u8);
        wrapped.extend_from_slice(&body);

        assert!(matches!(
            parse_offer_plaintext(&wrapped),
            Err(PkarrError::MalformedCanonical(
                "unknown offer binding_mode byte"
            )),
        ));
    }

    // ---------- v3 offer-blob codec ----------

    #[test]
    fn offer_blob_roundtrips_all_fields() {
        let blob = OfferBlob {
            ice_ufrag: "abcd".to_string(),
            ice_pwd: "0123456789abcdefghij!@".to_string(),
            setup: SetupRole::Active,
            binding_mode: BindingMode::Exporter,
            client_dtls_fp: [0xABu8; DTLS_FP_LEN],
            candidates: vec![
                BlobCandidate {
                    typ: CandidateType::Host,
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                    port: 12_345,
                },
                BlobCandidate {
                    typ: CandidateType::Srflx,
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
                    port: 51_820,
                },
            ],
        };
        let enc = encode_offer_blob(&blob).unwrap();
        let dec = parse_offer_blob(&enc).unwrap();
        assert_eq!(dec, blob);
    }

    #[test]
    fn offer_blob_roundtrips_browser_shape() {
        // Browser default: actpass + CertFp.
        let blob = sample_offer_blob();
        let enc = encode_offer_blob(&blob).unwrap();
        let dec = parse_offer_blob(&enc).unwrap();
        assert_eq!(dec, blob);
    }

    #[test]
    fn offer_blob_rejects_passive_setup_role() {
        let mut blob = sample_offer_blob();
        blob.setup = SetupRole::Passive;
        assert!(matches!(
            encode_offer_blob(&blob),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_blob_rejects_unknown_version_byte() {
        let mut enc = encode_offer_blob(&sample_offer_blob()).unwrap();
        enc[0] = 0xFF;
        assert!(matches!(
            parse_offer_blob(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_blob_rejects_reserved_flag_bits() {
        let mut enc = encode_offer_blob(&sample_offer_blob()).unwrap();
        // Set a reserved bit (3-7).
        enc[1] |= 0b1000_0000;
        assert!(matches!(
            parse_offer_blob(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_blob_rejects_oversize_candidate_count() {
        let mut blob = sample_offer_blob();
        blob.candidates = (0..(MAX_BLOB_CANDIDATES + 1) as u8)
            .map(|i| BlobCandidate {
                typ: CandidateType::Host,
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i)),
                port: 1000 + i as u16,
            })
            .collect();
        assert!(matches!(
            encode_offer_blob(&blob),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_body_fits_inside_bep44_packet_budget() {
        // A v3 offer plaintext for a representative browser-style blob
        // MUST seal + base64url + DNS-wrap to well under the BEP44
        // 1000-byte cap. That's the entire point of this PR.
        let client_pk = client_sk().public_key();
        let p = OfferPlaintext::new_v3(client_pk, sample_offer_blob());
        let enc = encode_offer_plaintext(&p).unwrap();
        // Sealed ciphertext = plaintext + 48-byte libsodium overhead.
        // Base64url = 4/3. Plus DNS overhead (~40-60 bytes).
        let sealed_len = enc.len() + 48;
        let b64_len = sealed_len.div_ceil(3) * 4;
        let worst_case = b64_len + 128;
        assert!(
            worst_case < BEP44_MAX_V_BYTES,
            "v3 offer packet worst-case {} exceeds BEP44 cap {}",
            worst_case,
            BEP44_MAX_V_BYTES,
        );
    }

    #[test]
    fn offer_blob_to_sdp_is_syntactically_valid() {
        // Reconstructed SDP MUST contain the fields daemon-side
        // webrtc-rs will parse from a remote offer.
        let blob = sample_offer_blob();
        let sdp = offer_blob_to_sdp(&blob);
        assert!(sdp.contains("a=ice-ufrag:abcd"));
        assert!(sdp.contains("a=ice-pwd:Supercalifragilistic!2"));
        assert!(sdp.contains("a=setup:actpass"));
        assert!(sdp.contains("a=fingerprint:sha-256 "));
        assert!(sdp.contains("198.51.100.7 45678"));
        assert!(sdp.ends_with("a=end-of-candidates\r\n"));
    }

    #[test]
    fn binding_mode_try_from_rejects_unknown_bytes() {
        assert!(matches!(
            BindingMode::try_from_u8(0x00),
            Err(PkarrError::MalformedCanonical(_))
        ));
        assert!(matches!(
            BindingMode::try_from_u8(0xFF),
            Err(PkarrError::MalformedCanonical(_))
        ));
        assert_eq!(
            BindingMode::try_from_u8(0x01).unwrap(),
            BindingMode::Exporter
        );
        assert_eq!(BindingMode::try_from_u8(0x02).unwrap(), BindingMode::CertFp);
    }

    /// v3 plaintext for a browser-sized offer MUST stay well below the
    /// BEP44 packet-size ceiling even in the fully-packed worst case.
    /// This is the invariant that the whole PR was built to enforce —
    /// pre-v3 Chrome offers were hitting 1044-byte packets (above the
    /// 1000-byte cap).
    #[test]
    fn v3_offer_plaintext_stays_well_under_bep44_cap() {
        let mut blob = sample_offer_blob();
        // Fully pack the candidate list to exercise the worst case the
        // encoder will actually produce (MAX_BLOB_CANDIDATES hygiene
        // cap on the extraction side).
        blob.candidates = (0..MAX_BLOB_CANDIDATES as u8)
            .map(|i| BlobCandidate {
                typ: CandidateType::Host,
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, i)),
                port: 50_000 + i as u16,
            })
            .collect();
        let p = OfferPlaintext::new_v3(client_sk().public_key(), blob);
        let enc = encode_offer_plaintext(&p).unwrap();
        // Even with max candidates, the compressed plaintext fits in a
        // fraction of the BEP44 budget.
        assert!(
            enc.len() < 400,
            "fully-packed v3 offer plaintext was {} bytes; expected < 400",
            enc.len(),
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

    /// Zero-candidate v3 offer round-trips cleanly — matches the shape
    /// of an offer produced before any ICE gather completes.
    #[test]
    fn offer_plaintext_v3_zero_candidates_roundtrips() {
        let mut blob = sample_offer_blob();
        blob.candidates.clear();
        let p = OfferPlaintext::new_v3(client_sk().public_key(), blob);
        let enc = encode_offer_plaintext(&p).unwrap();
        let dec = parse_offer_plaintext(&enc).unwrap();
        assert_eq!(dec, p);
    }

    /// Hand-craft a v1 (legacy) answer plaintext (uncompressed + full
    /// SDP) and confirm `parse_answer_plaintext` still decodes it into
    /// an `AnswerPayload::V1Sdp`. New emitters never produce v1, but
    /// decoders accept it for the duration of the rollout.
    #[test]
    fn answer_plaintext_accepts_v1_uncompressed_for_backcompat() {
        let daemon_pk = host_sk().public_key();
        let answer_sdp = SAMPLE_ANSWER_SDP.to_string();
        let offer_sdp_hash = hash_offer_sdp(SAMPLE_OFFER_SDP);

        // Manually encode the v1 body shape.
        let sdp_bytes = answer_sdp.as_bytes();
        let mut v1_body = Vec::new();
        v1_body.extend_from_slice(ANSWER_INNER_DOMAIN_V1);
        v1_body.extend_from_slice(&daemon_pk.to_bytes());
        v1_body.extend_from_slice(&offer_sdp_hash);
        v1_body.extend_from_slice(&(sdp_bytes.len() as u32).to_be_bytes());
        v1_body.extend_from_slice(sdp_bytes);

        // Uncompressed tag + body.
        let mut v1 = Vec::with_capacity(1 + v1_body.len());
        v1.push(CompressionTag::Uncompressed as u8);
        v1.extend_from_slice(&v1_body);

        let dec = parse_answer_plaintext(&v1).unwrap();
        assert_eq!(dec.daemon_pk, daemon_pk);
        assert_eq!(dec.offer_sdp_hash, offer_sdp_hash);
        match dec.answer {
            AnswerPayload::V1Sdp(s) => assert_eq!(s, answer_sdp),
            AnswerPayload::V2Blob(_) => panic!("expected V1Sdp"),
        }
    }

    #[test]
    fn answer_plaintext_roundtrips() {
        let daemon_pk = host_sk().public_key();
        let p = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer: AnswerPayload::V2Blob(sample_blob()),
        };
        let enc = encode_answer_plaintext(&p).unwrap();
        let dec = parse_answer_plaintext(&enc).unwrap();
        assert_eq!(dec, p);
    }

    #[test]
    fn answer_blob_roundtrips_all_fields() {
        let blob = AnswerBlob {
            ice_ufrag: "abcd".to_string(),
            ice_pwd: "0123456789abcdefghij!@".to_string(),
            setup: SetupRole::Active,
            candidates: vec![
                BlobCandidate {
                    typ: CandidateType::Host,
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                    port: 12345,
                },
                BlobCandidate {
                    typ: CandidateType::Srflx,
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
                    port: 51_820,
                },
                BlobCandidate {
                    typ: CandidateType::Relay,
                    ip: std::net::IpAddr::V6(std::net::Ipv6Addr::from([
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                    ])),
                    port: 3478,
                },
            ],
        };
        let enc = encode_answer_blob(&blob).unwrap();
        let dec = parse_answer_blob(&enc).unwrap();
        assert_eq!(dec, blob);
    }

    #[test]
    fn answer_blob_parses_zero_candidates() {
        let blob = AnswerBlob {
            ice_ufrag: "abcd".to_string(),
            ice_pwd: "0123456789abcdefghij!@".to_string(),
            setup: SetupRole::Passive,
            candidates: vec![],
        };
        let enc = encode_answer_blob(&blob).unwrap();
        let dec = parse_answer_blob(&enc).unwrap();
        assert_eq!(dec, blob);
    }

    #[test]
    fn answer_blob_rejects_unknown_version() {
        let mut enc = encode_answer_blob(&sample_blob()).unwrap();
        enc[0] = 0xFF;
        assert!(matches!(
            parse_answer_blob(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn answer_blob_rejects_reserved_flag_bits() {
        let mut enc = encode_answer_blob(&sample_blob()).unwrap();
        enc[1] |= 0b1000_0000;
        assert!(matches!(
            parse_answer_blob(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn answer_blob_rejects_oversize_candidate_count() {
        let too_many = AnswerBlob {
            ice_ufrag: "abcd".to_string(),
            ice_pwd: "0123456789abcdefghij!@".to_string(),
            setup: SetupRole::Passive,
            candidates: (0..(MAX_BLOB_CANDIDATES + 1) as u8)
                .map(|i| BlobCandidate {
                    typ: CandidateType::Host,
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, i)),
                    port: 1000 + i as u16,
                })
                .collect(),
        };
        assert!(matches!(
            encode_answer_blob(&too_many),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn answer_blob_rejects_short_ufrag() {
        let bad = AnswerBlob {
            ice_ufrag: "ab".to_string(),
            ice_pwd: "0123456789abcdefghij!@".to_string(),
            setup: SetupRole::Passive,
            candidates: vec![],
        };
        assert!(matches!(
            encode_answer_blob(&bad),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn answer_body_fits_in_single_fragment_with_main_record() {
        // Seal a representative blob alongside the main record and
        // assert the resulting BEP44 packet fits the 1000-byte cap with
        // exactly one answer fragment — the whole point of the compact
        // blob design.
        let sk = host_sk();
        let signed = SignedRecord::sign(sample_record(1_700_000_000), &sk).unwrap();
        let client_pk = client_sk().public_key();
        let daemon_pk = sk.public_key();
        let salt = [0x33u8; SALT_LEN];

        let plaintext = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp(SAMPLE_OFFER_SDP),
            answer: AnswerPayload::V2Blob(sample_blob()),
        };
        let mut rng = deterministic_rng();
        let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, 1).unwrap();

        let expected_total = entry.sealed.len().div_ceil(MAX_FRAGMENT_PAYLOAD_BYTES);
        assert_eq!(
            expected_total, 1,
            "compact blob should fit in a single fragment"
        );

        let packet = encode_with_answers(&signed, &sk, std::slice::from_ref(&entry)).unwrap();
        assert!(
            packet.encoded_packet().len() <= BEP44_MAX_V_BYTES,
            "packet must fit BEP44 cap, got {}",
            packet.encoded_packet().len()
        );
    }

    #[test]
    fn legacy_v1_answer_still_decodes_via_parse_answer_body() {
        let daemon_pk = host_sk().public_key();
        let answer_sdp = SAMPLE_ANSWER_SDP.to_string();
        let sdp_bytes = answer_sdp.as_bytes();
        let offer_sdp_hash = hash_offer_sdp(SAMPLE_OFFER_SDP);

        let mut v1_body = Vec::new();
        v1_body.extend_from_slice(ANSWER_INNER_DOMAIN_V1);
        v1_body.extend_from_slice(&daemon_pk.to_bytes());
        v1_body.extend_from_slice(&offer_sdp_hash);
        v1_body.extend_from_slice(&(sdp_bytes.len() as u32).to_be_bytes());
        v1_body.extend_from_slice(sdp_bytes);

        let dec = parse_answer_body(&v1_body).unwrap();
        assert_eq!(dec.daemon_pk, daemon_pk);
        assert_eq!(dec.offer_sdp_hash, offer_sdp_hash);
        match dec.answer {
            AnswerPayload::V1Sdp(s) => assert_eq!(s, answer_sdp),
            AnswerPayload::V2Blob(_) => panic!("expected V1Sdp"),
        }
    }

    // ---------- seal / open ----------

    #[test]
    fn offer_seal_open_roundtrip() {
        let daemon_pk = host_sk().public_key();
        let daemon_sk = host_sk();
        let plaintext = OfferPlaintext::new_v3(client_sk().public_key(), sample_offer_blob());
        let mut rng = deterministic_rng();
        let record = OfferRecord::seal(&mut rng, &daemon_pk, &plaintext).unwrap();
        let opened = record.open(&daemon_sk).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn offer_open_with_wrong_key_fails() {
        let daemon_pk = host_sk().public_key();
        let plaintext = OfferPlaintext::new_v3(client_sk().public_key(), sample_offer_blob());
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
            answer: AnswerPayload::V2Blob(sample_blob()),
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
            answer: AnswerPayload::V2Blob(sample_blob()),
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
            answer: AnswerPayload::V2Blob(sample_blob()),
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

        let plaintext = OfferPlaintext::new_v3(client_sk.public_key(), sample_offer_blob());
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
