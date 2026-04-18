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
use openhost_core::identity::{PublicKey, SigningKey, PUBLIC_KEY_LEN, SIGNING_KEY_LEN};
use openhost_core::pkarr_record::{
    IceBlob, OpenhostRecord, SignedRecord, ALLOW_ENTRY_LEN, CLIENT_HASH_LEN, DTLS_FINGERPRINT_LEN,
    MAX_DISC_LEN, PROTOCOL_VERSION, SALT_LEN,
};
use pkarr::dns::Name;
use pkarr::{Keypair, SignedPacket, Timestamp};

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

    let seed: [u8; SIGNING_KEY_LEN] = signing_key.to_bytes();
    let keypair = Keypair::from_secret_key(&seed);

    let name = Name::new_unchecked(OPENHOST_TXT_NAME);
    let txt = pkarr::dns::rdata::TXT::try_from(encoded.as_str())
        .map_err(|e| PkarrError::MalformedCanonical(txt_build_err(e)))?;

    let ts = Timestamp::from(signed.record.ts.saturating_mul(MICROS_PER_SECOND));

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
/// Verification of the outer BEP44 signature has already happened inside the
/// pkarr crate by the time a `SignedPacket` exists. The inner openhost
/// signature is copied verbatim into the returned [`SignedRecord`]; callers
/// (typically the resolver) are responsible for calling
/// [`SignedRecord::verify`] with a `now_ts` to validate the openhost-layer
/// freshness window.
///
/// Returns [`PkarrError::MissingOpenhostRecord`] if no `_openhost` TXT record
/// is present, and [`PkarrError::BlobTooShort`] if the decoded blob is shorter
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
    let mut saw_any = false;
    let mut out = String::new();

    for rr in packet.resource_records(OPENHOST_TXT_NAME) {
        saw_any = true;
        if let pkarr::dns::rdata::RData::TXT(txt) = &rr.rdata {
            for (key, value) in txt.iter_raw() {
                out.push_str(core::str::from_utf8(key).map_err(|_| PkarrError::InvalidUtf8)?);
                if let Some(v) = value {
                    out.push('=');
                    out.push_str(core::str::from_utf8(v).map_err(|_| PkarrError::InvalidUtf8)?);
                }
            }
        }
    }

    if !saw_any {
        return Err(PkarrError::MissingOpenhostRecord);
    }

    Ok(out)
}

fn txt_build_err(_e: pkarr::dns::SimpleDnsError) -> &'static str {
    "failed to build _openhost TXT record"
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

    let allow_count = r.u16_be()? as usize;
    let mut allow = Vec::with_capacity(allow_count);
    for _ in 0..allow_count {
        let mut entry = [0u8; ALLOW_ENTRY_LEN];
        entry.copy_from_slice(r.take(ALLOW_ENTRY_LEN)?);
        allow.push(entry);
    }

    let ice_count = r.u16_be()? as usize;
    let mut ice = Vec::with_capacity(ice_count);
    for _ in 0..ice_count {
        let client_hash = r.take(CLIENT_HASH_LEN)?.to_vec();
        let ct_len = r.u32_be()? as usize;
        let ciphertext = r.take(ct_len)?.to_vec();
        ice.push(IceBlob {
            client_hash,
            ciphertext,
        });
    }

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
        allow,
        ice,
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

    fn u32_be(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
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
    use openhost_core::crypto::allowlist_hash;
    use openhost_core::pkarr_record::{
        IceBlob, OpenhostRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn reference_record() -> OpenhostRecord {
        let salt = [0x11u8; SALT_LEN];
        let client_pk = [0xAAu8; 32];
        let hash = allowlist_hash(&salt, &client_pk);
        OpenhostRecord {
            version: PROTOCOL_VERSION,
            ts: 1_700_000_000,
            dtls_fp: [0x42u8; DTLS_FINGERPRINT_LEN],
            roles: "server".to_string(),
            salt,
            allow: vec![hash],
            ice: vec![IceBlob {
                client_hash: hash.to_vec(),
                ciphertext: vec![0xEE; 72],
            }],
            disc: "dht=1; relay=pkarr.example".to_string(),
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
    fn packet_too_large_is_rejected() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let mut record = reference_record();
        // Pad `ice` with many large blobs until the encoded packet breaches the
        // 1000-byte BEP44 limit.
        record.ice = (0..30)
            .map(|i| IceBlob {
                client_hash: vec![i as u8; CLIENT_HASH_LEN],
                ciphertext: vec![0xEE; 200],
            })
            .collect();
        let signed = SignedRecord::sign(record, &sk).unwrap();

        let err = encode(&signed, &sk).unwrap_err();
        // Either our own PacketTooLarge, or pkarr's own Build error raised during sign.
        assert!(matches!(
            err,
            PkarrError::PacketTooLarge { .. } | PkarrError::Build(_)
        ));
    }
}
