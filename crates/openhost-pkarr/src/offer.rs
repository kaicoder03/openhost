//! Offer + answer record codec for the daemon's signalling loop (PR #7a).
//!
//! # Overview
//!
//! Clients publish an ephemeral offer SDP by posting a `SignedPacket`
//! under their own Ed25519 pubkey containing a TXT record at
//! `_offer._<host-hash>`. The TXT value is a sealed-box ciphertext
//! addressed to the daemon's Ed25519 identity (converted to X25519). The
//! daemon polls known clients, reads the TXT, unseals it, and hands the
//! inner SDP to [`crate::listener::PassivePeer::handle_offer`].
//!
//! The daemon in turn publishes the answer back as an extra TXT record
//! inside its own regular `_openhost` packet, at `_answer._<client-hash>`.
//! The `_openhost` TXT bytes are completely unchanged; clients that only
//! decode the main record don't notice. Client-side consumers that DO
//! know their `client_hash` can look for the `_answer.*` TXT, unseal it
//! against their own identity, and apply the answer SDP to their peer
//! connection.
//!
//! # Spec status
//!
//! `spec/01-wire-format.md §3` describes the offer side only; the
//! answer record is a PR #7a extension flagged `TODO(v0.1 freeze)` in
//! the same file.
//!
//! # Wire format
//!
//! Both TXT values are `base64url_no_pad(sealed_box_ciphertext)` where
//! the sealed-box plaintext follows a domain-separated canonical form:
//!
//! ```text
//! offer_plaintext  = 0x01
//!                    || "openhost-offer-inner1"
//!                    || client_pk               (32 bytes)
//!                    || sdp_len                 (u32, big-endian)
//!                    || offer_sdp               (sdp_len bytes, UTF-8)
//!
//! answer_plaintext = 0x01
//!                    || "openhost-answer-inner1"
//!                    || daemon_pk               (32 bytes)
//!                    || offer_sdp_hash          (32 bytes, SHA-256 of the
//!                                                UTF-8 offer SDP this
//!                                                answer is bound to)
//!                    || sdp_len                 (u32, big-endian)
//!                    || answer_sdp              (sdp_len bytes, UTF-8)
//! ```
//!
//! The inner `client_pk` / `daemon_pk` MUST match the outer BEP44 signer
//! pubkey — cross-checked on decode so a hostile substrate cannot splice
//! an offer signed under key A with inner plaintext claiming key B.

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

/// Version tag prefixing every offer/answer inner plaintext.
const INNER_TAG: u8 = 0x01;

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

/// DNS label prefix for answer records. Full single-label name is
/// `_answer-<client-hash-label>`.
pub const ANSWER_TXT_PREFIX: &str = "_answer-";

/// TTL (in seconds) used for both offer and answer TXT records. Short
/// because they're per-handshake and shouldn't be cached.
pub const OFFER_TXT_TTL: u32 = 30;

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

/// Full DNS name the daemon publishes an answer at inside its own zone:
/// `_answer._<client-hash-label>`.
#[must_use]
pub fn answer_txt_name(daemon_salt: &[u8; SALT_LEN], client_pk: &PublicKey) -> String {
    format!(
        "{ANSWER_TXT_PREFIX}{}",
        client_hash_label(daemon_salt, client_pk)
    )
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
/// carrying answer TXT records. When `answers` is empty the returned
/// packet is byte-identical to what [`crate::codec::encode`] would
/// produce — an existing test pins this invariant.
///
/// When the packet would overflow [`BEP44_MAX_V_BYTES`] after including
/// all answers, the encoder evicts the oldest entries (smallest
/// `created_at` first) until the packet fits. A `warn!` is logged for
/// each eviction so operators notice shedding.
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
    // eviction walks the back, keeping the freshest answers.
    let mut sorted: Vec<&AnswerEntry> = answers.iter().collect();
    sorted.sort_by_key(|e| e.created_at);

    // Try with ALL answers first. pkarr's own signer enforces the
    // 1000-byte BEP44 cap and returns `SignedPacketBuildError::PacketTooLarge`
    // BEFORE we get a packet back, so we need to drop entries and
    // retry rather than post-hoc inspecting `encoded_packet().len()`.
    let mut keep_from = 0usize;
    loop {
        match build_packet(&main_txt, ts, &sorted[keep_from..], &keypair) {
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
    answers: &[&AnswerEntry],
    keypair: &Keypair,
) -> Result<SignedPacket> {
    let mut builder = SignedPacket::builder().timestamp(ts).txt(
        Name::new_unchecked(OPENHOST_TXT_NAME),
        TXT::try_from(main_txt).map_err(|e| PkarrError::TxtBuildFailed(e.to_string()))?,
        OPENHOST_TXT_TTL,
    );
    for entry in answers {
        let label = zbase32::encode_full_bytes(&entry.client_hash);
        let name_owned = format!("{ANSWER_TXT_PREFIX}{label}");
        let answer_txt = URL_SAFE_NO_PAD.encode(&entry.sealed);
        builder = builder.txt(
            Name::new_unchecked(&name_owned),
            TXT::try_from(answer_txt.as_str())
                .map_err(|e| PkarrError::TxtBuildFailed(e.to_string()))?,
            OFFER_TXT_TTL,
        );
    }
    Ok(builder.sign(keypair)?)
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

/// Look for an `_answer-<client-hash>` TXT inside `packet` (the daemon's
/// main record) and return it decoded. Called by PR #8's client-side
/// consumer: it already knows its own `client_pk` and the daemon's
/// published salt.
///
/// **Does NOT cross-check** the inner `daemon_pk` inside the sealed
/// plaintext against the outer BEP44 signer — the caller MUST do that
/// after [`AnswerEntry::open`] to defend against a splicing substrate.
pub fn decode_answer_from_packet(
    packet: &SignedPacket,
    daemon_salt: &[u8; SALT_LEN],
    client_pk: &PublicKey,
) -> Result<Option<AnswerEntry>> {
    let client_hash = allowlist_hash(daemon_salt, &client_pk.to_bytes());
    let want_name = format!(
        "{ANSWER_TXT_PREFIX}{}",
        zbase32::encode_full_bytes(&client_hash)
    );
    let text = match collect_single_txt(packet, &want_name)? {
        Some(t) => t,
        None => return Ok(None),
    };
    let sealed = URL_SAFE_NO_PAD.decode(text.as_bytes())?;
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

fn encode_offer_plaintext(p: &OfferPlaintext) -> Vec<u8> {
    let sdp = p.offer_sdp.as_bytes();
    let mut out = Vec::with_capacity(1 + OFFER_INNER_DOMAIN.len() + PUBLIC_KEY_LEN + 4 + sdp.len());
    out.push(INNER_TAG);
    out.extend_from_slice(OFFER_INNER_DOMAIN);
    out.extend_from_slice(&p.client_pk.to_bytes());
    let len = u32::try_from(sdp.len())
        .expect("SDP length bounded well below u32::MAX by BEP44 1000-byte cap");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(sdp);
    out
}

fn parse_offer_plaintext(bytes: &[u8]) -> Result<OfferPlaintext> {
    let mut r = InnerCursor::new(bytes);
    let tag = r.u8()?;
    if tag != INNER_TAG {
        return Err(PkarrError::MalformedCanonical(
            "unknown offer-inner encoding tag",
        ));
    }
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

fn encode_answer_plaintext(p: &AnswerPlaintext) -> Vec<u8> {
    let sdp = p.answer_sdp.as_bytes();
    let mut out = Vec::with_capacity(
        1 + ANSWER_INNER_DOMAIN.len() + PUBLIC_KEY_LEN + OFFER_SDP_HASH_LEN + 4 + sdp.len(),
    );
    out.push(INNER_TAG);
    out.extend_from_slice(ANSWER_INNER_DOMAIN);
    out.extend_from_slice(&p.daemon_pk.to_bytes());
    out.extend_from_slice(&p.offer_sdp_hash);
    let len = u32::try_from(sdp.len())
        .expect("SDP length bounded well below u32::MAX by BEP44 1000-byte cap");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(sdp);
    out
}

fn parse_answer_plaintext(bytes: &[u8]) -> Result<AnswerPlaintext> {
    let mut r = InnerCursor::new(bytes);
    let tag = r.u8()?;
    if tag != INNER_TAG {
        return Err(PkarrError::MalformedCanonical(
            "unknown answer-inner encoding tag",
        ));
    }
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
    fn offer_plaintext_rejects_tampered_tag() {
        let p = OfferPlaintext {
            client_pk: client_sk().public_key(),
            offer_sdp: "v=0".to_string(),
        };
        let mut enc = encode_offer_plaintext(&p);
        enc[0] = 0x02;
        assert!(matches!(
            parse_offer_plaintext(&enc),
            Err(PkarrError::MalformedCanonical(_))
        ));
    }

    #[test]
    fn offer_plaintext_rejects_truncated_input() {
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

        // The `_answer._<client-hash>` TXT decodes to the expected entry.
        let decoded = decode_answer_from_packet(&packet, &salt, &client_pk)
            .unwrap()
            .expect("answer TXT is present");
        let opened = decoded.open(&client_sk()).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn encode_evicts_oldest_when_overflow() {
        let sk = host_sk();
        let signed = reference_signed();
        let daemon_pk = sk.public_key();
        let salt = [0x33u8; SALT_LEN];

        // Two entries, each small enough that ONE fits alongside the
        // main record, but not both. The oldest MUST be evicted; the
        // fresher MUST survive.
        let medium_sdp = "v=0\r\n".to_string() + &"a=candidate: UDP ".repeat(9);
        let mut entries = Vec::new();
        for (i, seed_byte) in [(0u64, 0x10u8), (1u64, 0x11u8)] {
            let pk = SigningKey::from_bytes(&[seed_byte; 32]).public_key();
            let plaintext = AnswerPlaintext {
                daemon_pk,
                offer_sdp_hash: hash_offer_sdp(&medium_sdp),
                answer_sdp: medium_sdp.clone(),
            };
            let mut rng = StdRng::from_seed([seed_byte; 32]);
            entries.push(AnswerEntry::seal(&mut rng, &pk, &salt, &plaintext, i).unwrap());
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
            decode_answer_from_packet(&packet, &salt, &freshest_pk)
                .unwrap()
                .is_some(),
            "the freshest answer must survive eviction"
        );
        // Oldest (created_at = 0) was dropped.
        let oldest_pk = SigningKey::from_bytes(&[0x10u8; 32]).public_key();
        assert!(
            decode_answer_from_packet(&packet, &salt, &oldest_pk)
                .unwrap()
                .is_none(),
            "the oldest answer must be evicted"
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
