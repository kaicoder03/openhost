//! Record resolver: races the configured Pkarr relays + the Mainline DHT for
//! the most-recent `SignedPacket` under a given public key, decodes it back to
//! a `SignedRecord`, and applies openhost-layer validation.
//!
//! Substrate racing is delegated to `pkarr::Client::resolve_most_recent`,
//! which internally queries all configured relays and the DHT and returns the
//! highest-`seq` response (per `spec/03-pkarr-records.md §3`). The resolver
//! wraps that with:
//!
//! 1. Decode via [`codec::decode`].
//! 2. Cross-check that the pkarr packet's timestamp (in seconds) matches
//!    `record.ts` within ±1s — guards against cache drift.
//! 3. [`SignedRecord::verify`] — 2-hour freshness window + Ed25519 signature +
//!    internal consistency.
//! 4. If the caller supplied a `cached_seq`, reject any record whose
//!    `record.ts < cached_seq` (spec §3 rule 5).
//!
//! A [`Resolve`] trait lets tests plug a fake client. The real `pkarr::Client`
//! is adapted by [`PkarrResolve`].

use crate::codec;
use crate::error::{PkarrError, Result};
use async_trait::async_trait;
use openhost_core::identity::{PublicKey, PUBLIC_KEY_LEN};
use openhost_core::pkarr_record::SignedRecord;
use pkarr::{Client, SignedPacket};
use std::sync::Arc;

/// Abstracts over the pkarr substrate-resolve surface for testability.
#[async_trait]
pub trait Resolve: Send + Sync + 'static {
    /// Query all configured substrates in parallel and return the most-recent
    /// packet (by BEP44 `seq` / `Timestamp`) for the given pkarr public key.
    async fn resolve_most_recent(&self, public_key: &pkarr::PublicKey) -> Option<SignedPacket>;
}

/// Adapter around a real `pkarr::Client`.
pub struct PkarrResolve {
    client: Arc<Client>,
}

impl PkarrResolve {
    /// Wrap an already-built `pkarr::Client`.
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Resolve for PkarrResolve {
    async fn resolve_most_recent(&self, public_key: &pkarr::PublicKey) -> Option<SignedPacket> {
        self.client.resolve_most_recent(public_key).await
    }
}

/// The resolver.
pub struct Resolver {
    client: Arc<dyn Resolve>,
}

impl Resolver {
    /// Construct a new resolver wrapping the given substrate client.
    pub fn new(client: Arc<dyn Resolve>) -> Self {
        Self { client }
    }

    /// Resolve the openhost record for `pubkey`.
    ///
    /// - `now_ts` is the verifier's current Unix timestamp in seconds. Pass
    ///   `std::time::SystemTime::now()` converted to seconds.
    /// - `cached_seq` is the highest `record.ts` (= BEP44 `seq`) this caller
    ///   has previously accepted for this pubkey. Resolver rejects any record
    ///   whose `ts` is strictly less than this, preventing stale substrates
    ///   from overwriting fresher cached state.
    pub async fn resolve(
        &self,
        pubkey: &PublicKey,
        now_ts: u64,
        cached_seq: Option<u64>,
    ) -> Result<SignedRecord> {
        let pk_bytes: [u8; PUBLIC_KEY_LEN] = pubkey.to_bytes();
        let pkarr_pk = pkarr::PublicKey::try_from(&pk_bytes)
            .map_err(|_| PkarrError::MalformedCanonical("pkarr PublicKey conversion"))?;

        let packet = self
            .client
            .resolve_most_recent(&pkarr_pk)
            .await
            .ok_or(PkarrError::NotFound)?;

        let signed = codec::decode(&packet)?;

        let packet_ts_micros: u64 = packet.timestamp().into();
        let packet_ts_secs = packet_ts_micros / codec::MICROS_PER_SECOND;
        let drift = packet_ts_secs.abs_diff(signed.record.ts);
        if drift > 1 {
            return Err(PkarrError::TimestampDrift {
                packet_ts: packet_ts_secs,
                record_ts: signed.record.ts,
            });
        }

        signed.verify(pubkey, now_ts)?;

        if let Some(cached) = cached_seq {
            if signed.record.ts < cached {
                return Err(PkarrError::SeqRegression {
                    record_ts: signed.record.ts,
                    cached_seq: cached,
                });
            }
        }

        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode;
    use openhost_core::crypto::allowlist_hash;
    use openhost_core::identity::SigningKey;
    use openhost_core::pkarr_record::{
        IceBlob, OpenhostRecord, DTLS_FINGERPRINT_LEN, MAX_RECORD_AGE_SECS, PROTOCOL_VERSION,
        SALT_LEN,
    };

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn sample_record(ts: u64) -> OpenhostRecord {
        let salt = [0x11u8; SALT_LEN];
        let hash = allowlist_hash(&salt, &[0xAA; 32]);
        OpenhostRecord {
            version: PROTOCOL_VERSION,
            ts,
            dtls_fp: [0x42u8; DTLS_FINGERPRINT_LEN],
            roles: "server".to_string(),
            salt,
            allow: vec![hash],
            ice: vec![IceBlob {
                client_hash: hash.to_vec(),
                ciphertext: vec![0xEE; 72],
            }],
            disc: String::new(),
        }
    }

    struct FakeResolve {
        packet: Option<SignedPacket>,
    }

    #[async_trait]
    impl Resolve for FakeResolve {
        async fn resolve_most_recent(&self, _pk: &pkarr::PublicKey) -> Option<SignedPacket> {
            // SignedPacket doesn't implement Clone; round-trip via serialize.
            self.packet
                .as_ref()
                .map(|p| SignedPacket::deserialize(&p.serialize()).unwrap())
        }
    }

    fn packet_for(ts: u64) -> (SigningKey, SignedPacket) {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let signed =
            openhost_core::pkarr_record::SignedRecord::sign(sample_record(ts), &sk).unwrap();
        let packet = encode(&signed, &sk).unwrap();
        (sk, packet)
    }

    #[tokio::test]
    async fn resolves_fresh_record() {
        let ts = 1_700_000_000;
        let (sk, packet) = packet_for(ts);
        let resolver = Resolver::new(Arc::new(FakeResolve {
            packet: Some(packet),
        }));

        let record = resolver
            .resolve(&sk.public_key(), ts, None)
            .await
            .expect("resolves");
        assert_eq!(record.record.ts, ts);
    }

    #[tokio::test]
    async fn returns_not_found_when_substrate_empty() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let resolver = Resolver::new(Arc::new(FakeResolve { packet: None }));
        let err = resolver
            .resolve(&sk.public_key(), 1_700_000_000, None)
            .await
            .unwrap_err();
        assert!(matches!(err, PkarrError::NotFound));
    }

    #[tokio::test]
    async fn rejects_stale_record() {
        let ts = 1_700_000_000;
        let (sk, packet) = packet_for(ts);
        let resolver = Resolver::new(Arc::new(FakeResolve {
            packet: Some(packet),
        }));

        let err = resolver
            .resolve(&sk.public_key(), ts + MAX_RECORD_AGE_SECS + 1, None)
            .await
            .unwrap_err();
        assert!(matches!(err, PkarrError::Core(_)));
    }

    #[tokio::test]
    async fn rejects_seq_regression() {
        let ts = 1_700_000_000;
        let (sk, packet) = packet_for(ts);
        let resolver = Resolver::new(Arc::new(FakeResolve {
            packet: Some(packet),
        }));

        let err = resolver
            .resolve(&sk.public_key(), ts, Some(ts + 1))
            .await
            .unwrap_err();
        assert!(matches!(err, PkarrError::SeqRegression { .. }));
    }

    #[tokio::test]
    async fn accepts_cached_seq_equal_to_record_ts() {
        let ts = 1_700_000_000;
        let (sk, packet) = packet_for(ts);
        let resolver = Resolver::new(Arc::new(FakeResolve {
            packet: Some(packet),
        }));

        let record = resolver
            .resolve(&sk.public_key(), ts, Some(ts))
            .await
            .expect("equal cached_seq is allowed (monotonic non-decreasing)");
        assert_eq!(record.record.ts, ts);
    }
}
