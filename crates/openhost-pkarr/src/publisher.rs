//! Record publisher: signs an [`OpenhostRecord`], encodes it into a
//! [`pkarr::SignedPacket`], and fans out to relays + DHT via the upstream
//! pkarr client (or any other [`Transport`] implementor).
//!
//! Republish cadence is 30 minutes as required by `spec/03-pkarr-records.md
//! §1`, with immediate republish on demand via [`PublisherHandle::trigger`]
//! (intended for the daemon to wire up to ICE / DTLS-fingerprint / allowlist
//! change events in M3).
//!
//! The [`Transport`] trait abstracts over `pkarr::Client` so tests can inject
//! a fake without touching the network. The real `pkarr::Client` impl is
//! provided by [`PkarrTransport`].

use crate::codec;
use crate::error::{PkarrError, Result};
use async_trait::async_trait;
use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{OpenhostRecord, SignedRecord};
use pkarr::{Client, SignedPacket, Timestamp};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::interval;

/// Default republish interval: 30 minutes (per spec §1).
pub const REPUBLISH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Number of attempts (including the first try) for the initial publish.
/// After this many consecutive failures the publisher falls back to the
/// normal 30-minute republish cadence.
pub const INITIAL_PUBLISH_ATTEMPTS: u32 = 3;

/// Base delay for the initial-publish exp-backoff schedule. Attempt N
/// waits `INITIAL_PUBLISH_BACKOFF * 2.pow(N-1)` before firing.
///   attempt 1 → immediate
///   attempt 2 → 500 ms
///   attempt 3 → 1000 ms
///
/// No jitter: the retry budget is bounded (3 attempts) and a single
/// daemon starting up does not contend for relay capacity against
/// itself, so the textbook "jitter to avoid thundering herd" argument
/// doesn't apply. Deterministic timing also makes the behaviour easy
/// to test.
pub const INITIAL_PUBLISH_BACKOFF: Duration = Duration::from_millis(500);

/// Abstracts over anything that can publish a signed pkarr packet. Implemented
/// by [`PkarrTransport`] (wrapping `pkarr::Client`) and by test fakes.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Publish `packet` to the underlying substrates.
    ///
    /// `cas` is the previously-observed timestamp for compare-and-swap
    /// semantics. On cold start the publisher passes `None`.
    async fn publish(&self, packet: &SignedPacket, cas: Option<Timestamp>) -> Result<()>;
}

/// Adapter around a real `pkarr::Client`.
pub struct PkarrTransport {
    client: Arc<Client>,
}

impl PkarrTransport {
    /// Wrap an already-built `pkarr::Client`.
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Transport for PkarrTransport {
    async fn publish(&self, packet: &SignedPacket, cas: Option<Timestamp>) -> Result<()> {
        self.client
            .publish(packet, cas)
            .await
            .map_err(PkarrError::from)
    }
}

/// Produces a fresh `OpenhostRecord` each time the publisher fires.
///
/// Typed as a boxed `FnMut` so callers can close over mutable state (e.g. the
/// current `allow` list) and set a fresh `ts` per publication.
pub type RecordSource = Box<dyn FnMut() -> OpenhostRecord + Send>;

/// Handle returned from [`Publisher::spawn`] — keeps the background task
/// alive and provides a trigger channel for on-demand republishes.
///
/// Dropping the handle aborts the background task; explicit [`shutdown`]
/// does the same and additionally awaits task completion.
///
/// [`shutdown`]: PublisherHandle::shutdown
pub struct PublisherHandle {
    trigger_tx: mpsc::Sender<()>,
    // `Option` so `shutdown` can `take()` the `JoinHandle` to await it,
    // while `Drop` still has something to `abort()` on the non-shutdown
    // path. On the shutdown path the handle is `None` by the time `Drop`
    // fires and the abort is a no-op.
    task: Option<JoinHandle<()>>,
}

impl PublisherHandle {
    /// Request an immediate republish. Non-blocking; ignored if the trigger
    /// channel is full (a publish is already queued).
    pub fn trigger(&self) {
        let _ = self.trigger_tx.try_send(());
    }

    /// Abort the background republish task and await its completion.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for PublisherHandle {
    fn drop(&mut self) {
        // If the caller never invoked `shutdown`, make sure the background
        // task is cancelled — otherwise it would keep republishing with the
        // `Arc<SigningKey>` until process exit, because the tokio `interval`
        // arm inside `spawn` never resolves to an error that could trigger
        // `select!`'s `else` branch on its own.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// The publisher.
pub struct Publisher {
    transport: Arc<dyn Transport>,
    signing_key: Arc<SigningKey>,
    record_source: RecordSource,
    last_seq: Option<u64>,
    interval: Duration,
}

impl Publisher {
    /// Construct a new `Publisher`.
    ///
    /// `initial_last_seq` seeds the CAS value. On first ever publish for a
    /// pubkey it should be `None`; if the caller has persisted the previous
    /// `record.ts` across restarts it should be `Some(prev_ts)`.
    pub fn new(
        transport: Arc<dyn Transport>,
        signing_key: Arc<SigningKey>,
        record_source: RecordSource,
        initial_last_seq: Option<u64>,
    ) -> Self {
        Self {
            transport,
            signing_key,
            record_source,
            last_seq: initial_last_seq,
            interval: REPUBLISH_INTERVAL,
        }
    }

    /// Override the republish interval. Intended for tests.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Sign, encode, and publish a single record **now**. Updates `last_seq`
    /// on success.
    pub async fn publish_once(&mut self) -> Result<u64> {
        let record = (self.record_source)();
        let ts = record.ts;
        let signed = SignedRecord::sign(record, &self.signing_key)?;
        let packet = codec::encode(&signed, &self.signing_key)?;
        let cas = self
            .last_seq
            .map(|s| Timestamp::from(s * codec::MICROS_PER_SECOND));
        self.transport.publish(&packet, cas).await?;
        self.last_seq = Some(ts);
        Ok(ts)
    }

    /// Spawn the background republish loop. Returns a handle that fires an
    /// immediate publish and thereafter republishes every `self.interval`,
    /// plus whenever [`PublisherHandle::trigger`] is called.
    pub fn spawn(mut self) -> PublisherHandle {
        let (trigger_tx, mut trigger_rx) = mpsc::channel::<()>(1);
        let period = self.interval;

        let task = tokio::spawn(async move {
            // Fire an immediate publish so a freshly-spawned publisher is
            // reachable without waiting for the first tick.
            //
            // Exp-backoff retry: a single transient relay blip shouldn't
            // leave the host undiscoverable until the next scheduled
            // tick. Cap is intentionally low — after three consecutive
            // failures the next attempt is the regular 30-minute tick
            // anyway, and a loud warn! is the right signal for operators.
            initial_publish_with_retry(&mut self).await;

            let mut ticker = interval(period);
            // The first tick returns immediately; skip it so we don't republish
            // twice back-to-back.
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if let Err(err) = self.publish_once().await {
                            tracing::warn!(?err, "openhost-pkarr: scheduled republish failed");
                        }
                    }
                    trigger = trigger_rx.recv() => match trigger {
                        Some(()) => {
                            if let Err(err) = self.publish_once().await {
                                tracing::warn!(?err, "openhost-pkarr: triggered republish failed");
                            }
                        }
                        // Trigger channel closed: the `PublisherHandle` was
                        // dropped without calling `shutdown`. `Drop` for the
                        // handle already aborts us, but exit the loop cleanly
                        // in case someone kept the handle alive only through
                        // the task itself.
                        None => break,
                    }
                }
            }
        });

        PublisherHandle {
            trigger_tx,
            task: Some(task),
        }
    }
}

/// Drive the first publish through [`INITIAL_PUBLISH_ATTEMPTS`] tries with
/// `INITIAL_PUBLISH_BACKOFF * 2^(n-1)` between attempts. Logs at `info!` on
/// the first success, `warn!` on every intermediate failure, `error!` if
/// every attempt fails.
async fn initial_publish_with_retry(publisher: &mut Publisher) {
    for attempt in 1..=INITIAL_PUBLISH_ATTEMPTS {
        match publisher.publish_once().await {
            Ok(_) => {
                tracing::info!(attempt, "openhost-pkarr: initial publish succeeded");
                return;
            }
            Err(err) => {
                let last = attempt == INITIAL_PUBLISH_ATTEMPTS;
                if last {
                    tracing::error!(
                        ?err,
                        attempt,
                        "openhost-pkarr: initial publish failed after {INITIAL_PUBLISH_ATTEMPTS} attempts; \
                         host will be undiscoverable until the next scheduled republish"
                    );
                    return;
                }
                let backoff = INITIAL_PUBLISH_BACKOFF * 2u32.pow(attempt - 1);
                tracing::warn!(
                    ?err,
                    attempt,
                    retry_in_ms = backoff.as_millis() as u64,
                    "openhost-pkarr: initial publish failed, retrying",
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{sample_record, RFC_SEED};
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeTransport {
        calls: Mutex<Vec<(u64, Option<u64>)>>,
    }

    #[async_trait]
    impl Transport for FakeTransport {
        async fn publish(&self, packet: &SignedPacket, cas: Option<Timestamp>) -> Result<()> {
            let pkt_ts: u64 = packet.timestamp().into();
            let pkt_secs = pkt_ts / codec::MICROS_PER_SECOND;
            let cas_secs = cas.map(|t| u64::from(t) / codec::MICROS_PER_SECOND);
            self.calls.lock().unwrap().push((pkt_secs, cas_secs));
            Ok(())
        }
    }

    #[tokio::test]
    async fn publish_once_updates_last_seq_and_sends_cas_next_time() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));

        let ts1: u64 = 1_700_000_000;
        let ts2: u64 = ts1 + 600;
        let counter = std::sync::atomic::AtomicU64::new(0);
        let record_source: RecordSource = Box::new(move || {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            sample_record(if i == 0 { ts1 } else { ts2 })
        });

        let mut publisher = Publisher::new(transport.clone(), sk, record_source, None);

        let first = publisher.publish_once().await.unwrap();
        assert_eq!(first, ts1);
        let second = publisher.publish_once().await.unwrap();
        assert_eq!(second, ts2);

        let calls = transport.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 2);
        // First publish: no CAS (cold start).
        assert_eq!(calls[0], (ts1, None));
        // Second publish: CAS carries the previous seq.
        assert_eq!(calls[1], (ts2, Some(ts1)));
    }

    #[tokio::test]
    async fn trigger_causes_additional_publish() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));

        // Use a very long interval so only our trigger produces a second publish.
        let counter = std::sync::atomic::AtomicU64::new(0);
        let record_source: RecordSource = Box::new(move || {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            sample_record(1_700_000_000 + i * 10)
        });

        let publisher = Publisher::new(transport.clone(), sk, record_source, None)
            .with_interval(Duration::from_secs(3600));
        let handle = publisher.spawn();

        // Wait for the initial publish to land.
        tokio::time::sleep(Duration::from_millis(30)).await;
        handle.trigger();
        tokio::time::sleep(Duration::from_millis(30)).await;

        let calls = transport.calls.lock().unwrap().clone();
        assert!(
            calls.len() >= 2,
            "expected ≥2 publishes (initial + trigger), saw {}",
            calls.len()
        );

        handle.shutdown().await;
    }

    /// Transport that always reports a publish failure — lets us verify that
    /// `publish_once` leaves `last_seq` unchanged after an error.
    struct FailingTransport;

    #[async_trait]
    impl Transport for FailingTransport {
        async fn publish(&self, _packet: &SignedPacket, _cas: Option<Timestamp>) -> Result<()> {
            Err(PkarrError::NotFound)
        }
    }

    #[tokio::test]
    async fn publish_failure_leaves_last_seq_unchanged() {
        let transport = Arc::new(FailingTransport);
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));

        let seed_ts: u64 = 1_699_000_000;
        let counter = std::sync::atomic::AtomicU64::new(0);
        let record_source: RecordSource = Box::new(move || {
            let i = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            sample_record(1_700_000_000 + i * 10)
        });

        let mut publisher = Publisher::new(transport.clone(), sk, record_source, Some(seed_ts));

        // First publish fails — `last_seq` MUST remain at the seeded value
        // so the next attempt still sends the correct CAS.
        assert!(publisher.publish_once().await.is_err());
        assert_eq!(publisher.last_seq, Some(seed_ts));

        // Second failure: same invariant, regardless of the record_source
        // having moved forward.
        assert!(publisher.publish_once().await.is_err());
        assert_eq!(publisher.last_seq, Some(seed_ts));
    }

    /// Transport that fails the first `fail_count` calls and then succeeds.
    /// Counts every call so the caller can assert how many attempts landed.
    struct FlakyTransport {
        calls: std::sync::atomic::AtomicUsize,
        fail_count: usize,
    }

    impl FlakyTransport {
        fn new(fail_count: usize) -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                fail_count,
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Transport for FlakyTransport {
        async fn publish(&self, _packet: &SignedPacket, _cas: Option<Timestamp>) -> Result<()> {
            let attempt = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if attempt < self.fail_count {
                Err(PkarrError::NotFound)
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initial_publish_retries_until_success() {
        // Fail the first two attempts; the third must succeed inside the
        // retry budget (attempts 1/2/3 at 0ms / 500ms / 1500ms virtual).
        let transport = Arc::new(FlakyTransport::new(2));
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let record_source: RecordSource = Box::new(|| sample_record(1_700_000_000));

        let publisher = Publisher::new(transport.clone(), sk, record_source, None)
            .with_interval(Duration::from_secs(3600)); // keep the ticker out
        let handle = publisher.spawn();

        // Advance virtual time past the two 500ms / 1000ms backoffs.
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(
            transport.call_count(),
            3,
            "expected attempt 1 (fail) + attempt 2 (fail) + attempt 3 (success)"
        );

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn initial_publish_gives_up_after_max_attempts() {
        // All-fail: publisher attempts exactly INITIAL_PUBLISH_ATTEMPTS
        // times, then falls through to the 30-min ticker without taking
        // down the task.
        let transport = Arc::new(FlakyTransport::new(usize::MAX));
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let record_source: RecordSource = Box::new(|| sample_record(1_700_000_000));

        let publisher = Publisher::new(transport.clone(), sk, record_source, None)
            .with_interval(Duration::from_secs(3600));
        let handle = publisher.spawn();

        // Cover the full retry schedule: 0ms + 500ms + 1000ms = 1.5s. 2s is
        // comfortably past.
        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(
            transport.call_count(),
            INITIAL_PUBLISH_ATTEMPTS as usize,
            "publisher must not exceed its retry budget"
        );

        // The task must still be alive — a later tick could still succeed.
        // Verify by triggering an immediate republish and confirming one
        // more call fires.
        handle.trigger();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            transport.call_count(),
            INITIAL_PUBLISH_ATTEMPTS as usize + 1,
            "task must still be running and able to service triggers after a failed initial publish"
        );

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn initial_last_seq_is_honored() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));

        let seed_ts: u64 = 1_699_000_000;
        let record_source: RecordSource = Box::new(move || sample_record(1_700_000_000));

        let mut publisher = Publisher::new(transport.clone(), sk, record_source, Some(seed_ts));
        publisher.publish_once().await.unwrap();

        let calls = transport.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, Some(seed_ts));
    }
}
