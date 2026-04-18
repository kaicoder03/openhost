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
//! 5. **Grace window** — after accepting the first validated record, wait
//!    [`GRACE_WINDOW`] for a higher-`seq` straggler from a slower
//!    substrate and prefer it if one arrives. Implements the "continue
//!    waiting on in-flight queries for up to 1.5 seconds" rule from
//!    `spec/01-wire-format.md §3` rule 5.
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
use std::time::Duration;

/// Default grace window per `spec/01-wire-format.md §3` rule 5: once the
/// resolver has an accepted record, it waits this long for a potentially
/// higher-`seq` response from a slower substrate before committing.
///
/// Callers that prefer snappy latency over spec-strict grace behaviour can
/// pass a shorter duration (or [`Duration::ZERO`]) via
/// [`Resolver::with_grace_window`]. The 1500 ms default is what spec §3
/// recommends.
pub const GRACE_WINDOW: Duration = Duration::from_millis(1500);

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
    grace: Duration,
}

impl Resolver {
    /// Construct a new resolver wrapping the given substrate client. Uses
    /// the default [`GRACE_WINDOW`]; see [`with_grace_window`] to override.
    ///
    /// [`with_grace_window`]: Resolver::with_grace_window
    pub fn new(client: Arc<dyn Resolve>) -> Self {
        Self {
            client,
            grace: GRACE_WINDOW,
        }
    }

    /// Override the grace window applied after the first validated record.
    ///
    /// Pass [`Duration::ZERO`] to skip the second substrate race entirely —
    /// useful for latency-sensitive consumers (browser extensions, CLI
    /// one-shots) where the safety the grace window buys is less valuable
    /// than the 1.5 s cost.
    pub fn with_grace_window(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
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

        // First race: fail-fast if NotFound or first packet fails validation.
        // `resolve_most_recent` already queries all configured substrates in
        // parallel and returns the highest-seq response it saw within its
        // internal timeout.
        let first_packet = self
            .client
            .resolve_most_recent(&pkarr_pk)
            .await
            .ok_or(PkarrError::NotFound)?;
        let first = self.validate_packet(first_packet, pubkey, now_ts, cached_seq)?;

        // Grace window disabled: callers that asked for Duration::ZERO
        // skip the second race entirely. Spec §3 rule 5 is SHOULD, not
        // MUST, and the 1.5 s tax is not always the right trade-off.
        if self.grace.is_zero() {
            return Ok(first);
        }

        // Grace window (spec §3 rule 5): give any substrate that didn't
        // respond in the first race up to `self.grace` to deliver a
        // higher-seq record.
        //
        // The timeout below caps total resolve() latency at `grace +
        // first-race latency + validation`, regardless of pkarr's internal
        // per-substrate timeout. Without it a slow second race could push
        // total latency well past the window spec authors intended.
        tokio::time::sleep(self.grace).await;

        let second_packet = match tokio::time::timeout(
            self.grace,
            self.client.resolve_most_recent(&pkarr_pk),
        )
        .await
        {
            Ok(Some(p)) => p,
            Ok(None) | Err(_) => return Ok(first),
        };

        match self.validate_packet(second_packet, pubkey, now_ts, cached_seq) {
            Ok(second) if second.record.ts > first.record.ts => Ok(second),
            Ok(_) => Ok(first),
            Err(err) => {
                // A malicious substrate serving malformed records under a
                // valid-identity pubkey would silently lose to `first`
                // here; a warn! makes the event observable for debugging.
                tracing::warn!(
                    ?err,
                    "openhost-pkarr: second-race packet failed validation; keeping first"
                );
                Ok(first)
            }
        }
    }

    /// Decode + validate one `SignedPacket` against the caller's `pubkey`,
    /// `now_ts`, and `cached_seq`. Factored out so the grace-window path
    /// can apply identical checks to both races.
    fn validate_packet(
        &self,
        packet: SignedPacket,
        pubkey: &PublicKey,
        now_ts: u64,
        cached_seq: Option<u64>,
    ) -> Result<SignedRecord> {
        let packet_ts_micros: u64 = packet.timestamp().into();
        let packet_ts_secs = packet_ts_micros / codec::MICROS_PER_SECOND;

        let signed = codec::decode(&packet)?;

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

    #[tokio::test(start_paused = true)]
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

    #[tokio::test(start_paused = true)]
    async fn returns_not_found_when_substrate_empty() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let resolver = Resolver::new(Arc::new(FakeResolve { packet: None }));
        let err = resolver
            .resolve(&sk.public_key(), 1_700_000_000, None)
            .await
            .unwrap_err();
        assert!(matches!(err, PkarrError::NotFound));
    }

    #[tokio::test(start_paused = true)]
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

    #[tokio::test(start_paused = true)]
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

    #[tokio::test(start_paused = true)]
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

    #[tokio::test(start_paused = true)]
    async fn rejects_timestamp_drift_between_packet_and_record() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let sk = SigningKey::from_bytes(&RFC_SEED);
        let record_ts = 1_700_000_000u64;
        let signed =
            openhost_core::pkarr_record::SignedRecord::sign(sample_record(record_ts), &sk).unwrap();

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

    // -- Grace-window tests ----------------------------------------------
    //
    // `TwoPhaseResolve` answers the first `resolve_most_recent` call with
    // `first` and every subsequent call with `second`. Lets us simulate a
    // slow substrate delivering a higher-`seq` straggler inside the 1.5s
    // window.

    use std::sync::Mutex;

    struct TwoPhaseResolve {
        first: Mutex<Option<SignedPacket>>,
        second: Mutex<Option<SignedPacket>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl TwoPhaseResolve {
        fn new(first: Option<SignedPacket>, second: Option<SignedPacket>) -> Self {
            Self {
                first: Mutex::new(first),
                second: Mutex::new(second),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Resolve for TwoPhaseResolve {
        async fn resolve_most_recent(&self, _pk: &pkarr::PublicKey) -> Option<SignedPacket> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // First call drains `first`; every later call reads `second`.
            if let Some(p) = self.first.lock().unwrap().take() {
                return Some(SignedPacket::deserialize(&p.serialize()).unwrap());
            }
            self.second
                .lock()
                .unwrap()
                .as_ref()
                .map(|p| SignedPacket::deserialize(&p.serialize()).unwrap())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn grace_window_prefers_higher_seq_straggler() {
        let (sk, first) = packet_for(1_700_000_000);
        let (_, second) = packet_for(1_700_000_010);
        let client = Arc::new(TwoPhaseResolve::new(Some(first), Some(second)));
        let resolver = Resolver::new(client.clone());

        let record = resolver
            .resolve(&sk.public_key(), 1_700_000_010, None)
            .await
            .expect("resolves");

        assert_eq!(
            record.record.ts, 1_700_000_010,
            "higher-seq straggler inside the grace window must win"
        );
        assert_eq!(
            client.call_count(),
            2,
            "resolver must race the substrates twice (first + after grace)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn grace_window_keeps_first_if_second_has_lower_seq() {
        let (sk, first) = packet_for(1_700_000_050);
        let (_, second) = packet_for(1_700_000_010);
        let client = Arc::new(TwoPhaseResolve::new(Some(first), Some(second)));
        let resolver = Resolver::new(client.clone());

        let record = resolver
            .resolve(&sk.public_key(), 1_700_000_050, None)
            .await
            .expect("resolves");

        assert_eq!(record.record.ts, 1_700_000_050);
    }

    #[tokio::test(start_paused = true)]
    async fn grace_window_keeps_first_if_second_returns_nothing() {
        let (sk, first) = packet_for(1_700_000_000);
        let client = Arc::new(TwoPhaseResolve::new(Some(first), None));
        let resolver = Resolver::new(client.clone());

        let record = resolver
            .resolve(&sk.public_key(), 1_700_000_000, None)
            .await
            .expect("resolves");

        assert_eq!(record.record.ts, 1_700_000_000);
        assert_eq!(client.call_count(), 2, "grace-window race still fires");
    }

    #[tokio::test(start_paused = true)]
    async fn grace_window_keeps_first_if_second_fails_validation() {
        // Second packet has a drift > 1s between outer timestamp and inner
        // record.ts — validate_packet rejects it. Resolver must fall back
        // to the valid first packet.
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let (sk, first) = packet_for(1_700_000_000);

        let signed =
            openhost_core::pkarr_record::SignedRecord::sign(sample_record(1_700_000_010), &sk)
                .unwrap();
        let canonical = signed.record.canonical_signing_bytes().unwrap();
        let mut blob = Vec::with_capacity(64 + canonical.len());
        blob.extend_from_slice(&signed.signature.to_bytes());
        blob.extend_from_slice(&canonical);
        let encoded = URL_SAFE_NO_PAD.encode(&blob);
        let keypair = pkarr::Keypair::from_secret_key(&sk.to_bytes());
        // Outer ts drifts 5s from inner record.ts=1_700_000_010 → rejected.
        let drifted_micros = (1_700_000_010 + 5) * codec::MICROS_PER_SECOND;
        let second = SignedPacket::builder()
            .txt(
                pkarr::dns::Name::new_unchecked(codec::OPENHOST_TXT_NAME),
                pkarr::dns::rdata::TXT::try_from(encoded.as_str()).unwrap(),
                codec::OPENHOST_TXT_TTL,
            )
            .timestamp(pkarr::Timestamp::from(drifted_micros))
            .sign(&keypair)
            .unwrap();

        let client = Arc::new(TwoPhaseResolve::new(Some(first), Some(second)));
        let resolver = Resolver::new(client.clone());

        let record = resolver
            .resolve(&sk.public_key(), 1_700_000_000, None)
            .await
            .expect("first packet remains valid even though second fails validation");
        assert_eq!(record.record.ts, 1_700_000_000);
    }

    #[tokio::test(start_paused = true)]
    async fn grace_window_skipped_when_first_not_found() {
        // If the first race returns None, the resolver fast-fails with
        // NotFound — no point waiting 1.5s for a straggler that nobody
        // has reason to believe exists.
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let client = Arc::new(TwoPhaseResolve::new(None, None));
        let resolver = Resolver::new(client.clone());

        let err = resolver
            .resolve(&sk.public_key(), 1_700_000_000, None)
            .await
            .unwrap_err();

        assert!(matches!(err, PkarrError::NotFound));
        assert_eq!(
            client.call_count(),
            1,
            "NotFound on first race must NOT trigger a second substrate poll"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_grace_window_skips_second_race() {
        // Callers that opt out of the grace window should never see the
        // second substrate poll — zero 1.5 s tax on the happy path.
        let (sk, first) = packet_for(1_700_000_000);
        let (_, second) = packet_for(1_700_000_010);
        let client = Arc::new(TwoPhaseResolve::new(Some(first), Some(second)));
        let resolver = Resolver::new(client.clone()).with_grace_window(Duration::ZERO);

        let record = resolver
            .resolve(&sk.public_key(), 1_700_000_010, None)
            .await
            .expect("resolves");

        assert_eq!(
            record.record.ts, 1_700_000_000,
            "zero grace window means first wins even if a higher-seq straggler was queued"
        );
        assert_eq!(
            client.call_count(),
            1,
            "zero grace window must skip the second substrate race"
        );
    }

    /// Resolve client whose second call never returns (simulates a hung
    /// relay). Used to verify the tokio::time::timeout cap on the second
    /// race.
    struct HangingSecondResolve {
        first: Mutex<Option<SignedPacket>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl HangingSecondResolve {
        fn new(first: SignedPacket) -> Self {
            Self {
                first: Mutex::new(Some(first)),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl Resolve for HangingSecondResolve {
        async fn resolve_most_recent(&self, _pk: &pkarr::PublicKey) -> Option<SignedPacket> {
            let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if n == 0 {
                self.first
                    .lock()
                    .unwrap()
                    .take()
                    .map(|p| SignedPacket::deserialize(&p.serialize()).unwrap())
            } else {
                // Second+ call: hang forever. The resolver's timeout must
                // cap this or the test would never complete.
                std::future::pending().await
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn second_race_timeout_falls_back_to_first() {
        let (sk, first) = packet_for(1_700_000_000);
        let client = Arc::new(HangingSecondResolve::new(first));
        let resolver = Resolver::new(client.clone());

        let record = resolver
            .resolve(&sk.public_key(), 1_700_000_000, None)
            .await
            .expect("timeout-bounded resolve still returns first");
        assert_eq!(record.record.ts, 1_700_000_000);
    }
}
