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
        let pkarr_pk =
            pkarr::PublicKey::try_from(&pk_bytes).map_err(|_| PkarrError::PublicKeyConversion)?;

        // TODO(M3): `pkarr::Client::resolve_most_recent` returns as soon as it
        // has a validated response; it does not implement the 1.5-second
        // grace window from spec §3 rule 5 ("continue waiting on in-flight
        // queries for up to 1.5 seconds after the first accepted record; if
        // a later-arriving record has a higher `seq`, prefer it"). Adding
        // that requires either a custom race over individual substrate calls
        // or an upstream pkarr change.
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
    use crate::test_support::{sample_record, RFC_SEED};
    use openhost_core::identity::SigningKey;
    use openhost_core::pkarr_record::MAX_RECORD_AGE_SECS;

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

    #[tokio::test]
    async fn rejects_timestamp_drift_between_packet_and_record() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let sk = SigningKey::from_bytes(&RFC_SEED);
        let record_ts = 1_700_000_000u64;
        let signed =
            openhost_core::pkarr_record::SignedRecord::sign(sample_record(record_ts), &sk)
                .unwrap();

        // Re-implement the encode path but pin the outer pkarr timestamp at
        // a value that disagrees with `record.ts` by more than 1s. We hold
        // the signing key, so the outer BEP44 signature still validates —
        // the drift guard in the resolver is what should catch this.
        let canonical = signed.record.canonical_signing_bytes().unwrap();
        let mut blob = Vec::with_capacity(64 + canonical.len());
        blob.extend_from_slice(&signed.signature.to_bytes());
        blob.extend_from_slice(&canonical);
        let encoded = URL_SAFE_NO_PAD.encode(&blob);

        let keypair = pkarr::Keypair::from_secret_key(&sk.to_bytes());
        let drifted_micros = (record_ts + 5) * codec::MICROS_PER_SECOND;
        let packet = SignedPacket::builder()
            .txt(
                pkarr::dns::Name::new_unchecked(codec::OPENHOST_TXT_NAME),
                pkarr::dns::rdata::TXT::try_from(encoded.as_str()).unwrap(),
                codec::OPENHOST_TXT_TTL,
            )
            .timestamp(pkarr::Timestamp::from(drifted_micros))
            .sign(&keypair)
            .unwrap();

        let resolver = Resolver::new(Arc::new(FakeResolve {
            packet: Some(packet),
        }));

        let err = resolver
            .resolve(&sk.public_key(), record_ts, None)
            .await
            .unwrap_err();
        assert!(matches!(err, PkarrError::TimestampDrift { .. }));
    }
}
