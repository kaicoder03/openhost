//! Translate between [`openhost_core::pkarr_record::SignedRecord`] and the
//! [`pkarr::SignedPacket`] DNS-packet form.
//!
//! Encoding: a single TXT resource record at name `_openhost` whose value is
//! `base64url(signature || canonical_signing_bytes)`, where `signature` is the
//! 64-byte Ed25519 signature from `SignedRecord::signature` and
//! `canonical_signing_bytes` is the deterministic byte string defined by
//! [`openhost_core::pkarr_record::OpenhostRecord::canonical_signing_bytes`].
//!
//! The outer BEP44 signature on the `SignedPacket` is produced by the same
//! Ed25519 identity key — no separate keys are used — via
//! [`pkarr::Keypair::from_secret_key`] over the 32-byte seed of the openhost
//! signing key.
//!
//! The canonical byte layout is frozen in M1 (see
//! `crates/openhost-core/src/pkarr_record/mod.rs`). The decoder in this file
//! parses it back into an `OpenhostRecord` without touching the `openhost-core`
//! public API.
//!
//! See `spec/01-wire-format.md §2` and `spec/test-vectors/pkarr_packet.json`.

use crate::error::{PkarrError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signature;
use openhost_core::identity::{PublicKey, SigningKey, PUBLIC_KEY_LEN};
use openhost_core::pkarr_record::{
    OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, MAX_DISC_LEN, PROTOCOL_VERSION, SALT_LEN,
};
use pkarr::dns::Name;
use pkarr::{Keypair, SignedPacket, Timestamp};
use zeroize::Zeroizing;

/// The TXT record name at which the encoded openhost blob is stored.
pub const OPENHOST_TXT_NAME: &str = "_openhost";

/// The TTL (in seconds) used for the `_openhost` TXT record.
///
/// 300 matches `pkarr::DEFAULT_MINIMUM_TTL`: clients refresh at least every five
/// minutes, well inside the 30-minute republish cadence required by
/// `spec/03-pkarr-records.md §1`.
pub const OPENHOST_TXT_TTL: u32 = 300;

/// The per-microsecond multiplier used to convert openhost seconds to pkarr
/// [`Timestamp`] values.
pub const MICROS_PER_SECOND: u64 = 1_000_000;

/// The 64-byte Ed25519 signature prefix at the front of the `_openhost` blob.
const SIGNATURE_LEN: usize = 64;

/// The BEP44 mutable-item payload limit (`v` field) enforced by the Mainline
/// DHT. The openhost-core canonical form is ~230 bytes for the reference vector;
/// the BEP44 limit is the tight constraint for records with many paired clients.
pub const BEP44_MAX_V_BYTES: usize = 1000;

/// Encode a [`SignedRecord`] into a [`pkarr::SignedPacket`].
///
/// The `SignedPacket`'s outer BEP44 signature is produced from `signing_key`'s
/// raw seed; the inner openhost signature inside the `_openhost` TXT record is
/// whatever was already present on `signed`. The caller is responsible for
/// ensuring they match (i.e. the same `SigningKey` was used to produce
/// `signed.signature`).
///
/// The pkarr packet's timestamp is set from `signed.record.ts * 1_000_000` so
/// BEP44 `seq` equals the record's Unix-seconds timestamp, as required by
/// `spec/03-pkarr-records.md §1`.
pub fn encode(signed: &SignedRecord, signing_key: &SigningKey) -> Result<SignedPacket> {
    let canonical = signed.record.canonical_signing_bytes()?;
    let mut blob = Vec::with_capacity(SIGNATURE_LEN + canonical.len());
    blob.extend_from_slice(&signed.signature.to_bytes());
    blob.extend_from_slice(&canonical);

    let encoded = URL_SAFE_NO_PAD.encode(&blob);

    let seed = Zeroizing::new(signing_key.to_bytes());
    let keypair = Keypair::from_secret_key(&seed);

    let name = Name::new_unchecked(OPENHOST_TXT_NAME);
    let txt = pkarr::dns::rdata::TXT::try_from(encoded.as_str())
        .map_err(|e| PkarrError::TxtBuildFailed(e.to_string()))?;

    let ts_micros =
        signed
            .record
            .ts
            .checked_mul(MICROS_PER_SECOND)
            .ok_or(PkarrError::TimestampOverflow {
                ts: signed.record.ts,
            })?;
    let ts = Timestamp::from(ts_micros);

    let packet = SignedPacket::builder()
        .txt(name, txt, OPENHOST_TXT_TTL)
        .timestamp(ts)
        .sign(&keypair)?;

    // The pkarr crate's own 1000-byte check lives behind `SignedPacket::new`,
    // but only over the encoded DNS packet. Re-assert it against
    // `encoded_packet()` so the error flows through our typed enum.
    if packet.encoded_packet().len() > BEP44_MAX_V_BYTES {
        return Err(PkarrError::PacketTooLarge {
            size: packet.encoded_packet().len(),
        });
    }

    Ok(packet)
}

/// Decode a [`pkarr::SignedPacket`] back into a [`SignedRecord`].
///
/// **Important: this function does NOT verify the inner Ed25519 signature.**
/// Verification of the outer BEP44 signature has already happened inside the
/// pkarr crate by the time a `SignedPacket` exists, but the inner openhost
/// signature is copied verbatim into the returned [`SignedRecord`]. Callers
/// (typically the resolver) **MUST** call [`SignedRecord::verify`] with a
/// `now_ts` before trusting any field of the returned record.
///
/// `decode` does run `record.validate(record.ts)` to reject records whose
/// schema invariants (empty `roles`, oversize `disc`, etc.) are violated;
/// the `ts` passed there is the record's own `ts`, so the 2-hour freshness
/// window is *not* enforced here. That still happens in `verify`.
///
/// Returns [`PkarrError::MissingOpenhostRecord`] if no `_openhost` TXT record
/// is present, [`PkarrError::MultipleOpenhostRecords`] if more than one is
/// present, and [`PkarrError::BlobTooShort`] if the decoded blob is shorter
/// than the 64-byte signature prefix.
pub fn decode(packet: &SignedPacket) -> Result<SignedRecord> {
    let text = collect_openhost_txt(packet)?;
    let blob = URL_SAFE_NO_PAD.decode(text.as_bytes())?;

    if blob.len() < SIGNATURE_LEN {
        return Err(PkarrError::BlobTooShort {
            got: blob.len(),
            min: SIGNATURE_LEN,
        });
    }

    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    sig_bytes.copy_from_slice(&blob[..SIGNATURE_LEN]);
    let signature = Signature::from_bytes(&sig_bytes);

    let record = parse_canonical_bytes(&blob[SIGNATURE_LEN..])?;
    record.validate(record.ts)?;

    Ok(SignedRecord { record, signature })
}

/// The 32-byte Ed25519 public key carried in the BEP44 header of `packet`,
/// converted to an [`openhost_core::identity::PublicKey`].
///
/// Useful to callers that want to cross-check the decoded record against the
/// packet's outer public key.
pub fn packet_public_key(packet: &SignedPacket) -> Result<PublicKey> {
    let bytes: [u8; PUBLIC_KEY_LEN] = *packet.public_key().as_bytes();
    PublicKey::from_bytes(&bytes).map_err(Into::into)
}

fn collect_openhost_txt(packet: &SignedPacket) -> Result<String> {
    let mut seen_txt = 0usize;
    let mut out = String::new();

    for rr in packet.resource_records(OPENHOST_TXT_NAME) {
        if let pkarr::dns::rdata::RData::TXT(txt) = &rr.rdata {
            seen_txt += 1;
            if seen_txt > 1 {
                // More than one TXT RR at `_openhost`. The spec mandates
                // exactly one; concatenating would yield a base64url blob
                // that almost certainly wouldn't decode, but fail loudly so
                // a misconfigured publisher is easy to diagnose.
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

    if seen_txt == 0 {
        return Err(PkarrError::MissingOpenhostRecord);
    }

    Ok(out)
}

/// Inverse of [`OpenhostRecord::canonical_signing_bytes`].
///
/// Keeps strict parity with the layout documented at
/// `crates/openhost-core/src/pkarr_record/mod.rs:122-138`. Changes to that
/// layout require a coordinated update here.
fn parse_canonical_bytes(bytes: &[u8]) -> Result<OpenhostRecord> {
    let mut r = Cursor::new(bytes);

    let tag = r.u8()?;
    if tag != 0x01 {
        return Err(PkarrError::MalformedCanonical("unknown encoding tag"));
    }

    let domain = r.take(9)?;
    if domain != b"openhost1" {
        return Err(PkarrError::MalformedCanonical(
            "missing openhost1 domain separator",
        ));
    }

    let version = r.u8()?;
    if version != PROTOCOL_VERSION {
        return Err(PkarrError::MalformedCanonical(
            "unsupported protocol version",
        ));
    }

    let ts = r.u64_be()?;

    let mut dtls_fp = [0u8; DTLS_FINGERPRINT_LEN];
    dtls_fp.copy_from_slice(r.take(DTLS_FINGERPRINT_LEN)?);

    let roles_len = r.u8()? as usize;
    let roles_bytes = r.take(roles_len)?;
    let roles = core::str::from_utf8(roles_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("roles is not valid UTF-8"))?
        .to_string();

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(r.take(SALT_LEN)?);

    let disc_len = r.u16_be()? as usize;
    if disc_len > MAX_DISC_LEN {
        return Err(PkarrError::MalformedCanonical(
            "disc length exceeds maximum",
        ));
    }
    let disc_bytes = r.take(disc_len)?;
    let disc = core::str::from_utf8(disc_bytes)
        .map_err(|_| PkarrError::MalformedCanonical("disc is not valid UTF-8"))?
        .to_string();

    if !r.is_empty() {
        return Err(PkarrError::MalformedCanonical(
            "trailing bytes after canonical record",
        ));
    }

    Ok(OpenhostRecord {
        version,
        ts,
        dtls_fp,
        roles,
        salt,
        disc,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(PkarrError::MalformedCanonical("length overflow"))?;
        if end > self.buf.len() {
            return Err(PkarrError::MalformedCanonical("truncated canonical record"));
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

    fn u64_be(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{sample_record, RFC_SEED};

    /// Codec-flavoured reference record — distinct from the shared
    /// [`sample_record`] in that `disc` is non-empty, giving the encoded
    /// canonical bytes a non-trivial UTF-8 segment to exercise.
    fn reference_record() -> OpenhostRecord {
        OpenhostRecord {
            disc: "dht=1; relay=pkarr.example".to_string(),
            ..sample_record(1_700_000_000)
        }
    }

    #[test]
    fn round_trip_preserves_record_and_signature() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let record = reference_record();
        let signed = SignedRecord::sign(record.clone(), &sk).unwrap();

        let packet = encode(&signed, &sk).unwrap();
        let decoded = decode(&packet).unwrap();

        assert_eq!(decoded.record, record);
        assert_eq!(decoded.signature.to_bytes(), signed.signature.to_bytes());
    }

    #[test]
    fn packet_public_key_matches_signing_identity() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let pk = sk.public_key();
        let signed = SignedRecord::sign(reference_record(), &sk).unwrap();
        let packet = encode(&signed, &sk).unwrap();

        assert_eq!(packet_public_key(&packet).unwrap(), pk);
    }

    #[test]
    fn decoded_signature_verifies_against_identity_pubkey() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let pk = sk.public_key();
        let signed = SignedRecord::sign(reference_record(), &sk).unwrap();
        let packet = encode(&signed, &sk).unwrap();
        let decoded = decode(&packet).unwrap();

        decoded.verify(&pk, decoded.record.ts).expect("verifies");
    }

    #[test]
    fn packet_timestamp_is_record_ts_in_micros() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let signed = SignedRecord::sign(reference_record(), &sk).unwrap();
        let packet = encode(&signed, &sk).unwrap();

        let packet_ts_micros: u64 = packet.timestamp().into();
        assert_eq!(packet_ts_micros, signed.record.ts * MICROS_PER_SECOND);
    }

    #[test]
    fn decode_rejects_missing_openhost_record() {
        let keypair = Keypair::from_secret_key(&RFC_SEED);
        let packet = SignedPacket::builder()
            .txt(
                Name::new_unchecked("_other"),
                pkarr::dns::rdata::TXT::try_from("hello").unwrap(),
                OPENHOST_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        assert!(matches!(
            decode(&packet),
            Err(PkarrError::MissingOpenhostRecord)
        ));
    }

    #[test]
    fn decode_rejects_too_short_blob() {
        let keypair = Keypair::from_secret_key(&RFC_SEED);
        let short = URL_SAFE_NO_PAD.encode([0u8; 16]);
        let packet = SignedPacket::builder()
            .txt(
                Name::new_unchecked(OPENHOST_TXT_NAME),
                pkarr::dns::rdata::TXT::try_from(short.as_str()).unwrap(),
                OPENHOST_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        assert!(matches!(
            decode(&packet),
            Err(PkarrError::BlobTooShort { .. })
        ));
    }

    #[test]
    fn decode_rejects_multiple_openhost_records() {
        let keypair = Keypair::from_secret_key(&RFC_SEED);
        let packet = SignedPacket::builder()
            .txt(
                Name::new_unchecked(OPENHOST_TXT_NAME),
                pkarr::dns::rdata::TXT::try_from("AAA").unwrap(),
                OPENHOST_TXT_TTL,
            )
            .txt(
                Name::new_unchecked(OPENHOST_TXT_NAME),
                pkarr::dns::rdata::TXT::try_from("BBB").unwrap(),
                OPENHOST_TXT_TTL,
            )
            .sign(&keypair)
            .unwrap();

        assert!(matches!(
            decode(&packet),
            Err(PkarrError::MultipleOpenhostRecords)
        ));
    }

    #[test]
    fn bep44_sig_flip_fails_deserialization() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let signed = SignedRecord::sign(reference_record(), &sk).unwrap();
        let packet = encode(&signed, &sk).unwrap();

        // as_bytes() layout: [0..32]=pk  [32..96]=BEP44-sig  [96..104]=ts  [104..]=DNS
        let mut wire = packet.as_bytes().to_vec();
        wire[32] ^= 0xFF; // flip first byte of the BEP44 Ed25519 signature

        // pkarr rejects the tampered bytes before we even get to decode().
        assert!(
            SignedPacket::deserialize(&wire).is_err(),
            "tampered BEP44 sig must fail pkarr deserialization"
        );
    }

    /// Sanity-check: a v2 record with a maxed-out `disc` still encodes
    /// successfully — the main record alone can't overflow the BEP44
    /// packet budget. The actual overflow + eviction path now lives in
    /// `offer::tests::encode_evicts_oldest_when_overflow` (PR #15
    /// introduced fragment eviction; v2 records are small enough that
    /// the main record by itself can't trip the 1000-byte cap).
    #[test]
    fn max_disc_record_still_encodes() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let mut record = reference_record();
        record.disc = "x".repeat(MAX_DISC_LEN);
        let signed = SignedRecord::sign(record, &sk).unwrap();
        assert!(encode(&signed, &sk).is_ok());
    }
}
