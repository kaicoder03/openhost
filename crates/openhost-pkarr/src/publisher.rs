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
use crate::offer::{encode_with_answers, AnswerEntry};
use async_trait::async_trait;
use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{OpenhostRecord, SignedRecord};
use pkarr::{Client, SignedPacket, Timestamp};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::interval;

/// Default republish interval: 30 minutes (per spec §1).
pub const REPUBLISH_INTERVAL: Duration = Duration::from_secs(30 * 60);

/// Number of attempts (including the first try) for the initial publish.
/// After this many consecutive failures the publisher falls back to the
/// normal 30-minute republish cadence.
pub const INITIAL_PUBLISH_ATTEMPTS: u32 = 3;

/// Base delay for the initial-publish exp-backoff schedule. After each
/// failed attempt the publisher sleeps `INITIAL_PUBLISH_BACKOFF * 2.pow(N-1)`
/// before the next try, where N is the attempt that just failed.
///
/// Concrete schedule with `INITIAL_PUBLISH_ATTEMPTS = 3`:
/// - attempt 1 fires at t = 0
/// - if it fails, sleep 500 ms
/// - attempt 2 fires at t = 500 ms
/// - if it fails, sleep 1000 ms
/// - attempt 3 fires at t = 1500 ms
/// - if it fails, fall through to the regular republish ticker
///
/// No jitter: the retry budget is bounded (3 attempts) and a single
/// daemon starting up does not contend for relay capacity against
/// itself, so the textbook "jitter to avoid thundering herd" argument
/// doesn't apply. Deterministic timing also makes the behaviour easy
/// to test.
pub const INITIAL_PUBLISH_BACKOFF: Duration = Duration::from_millis(500);

/// Outcome of the initial-publish retry loop. Observable via
/// [`PublisherHandle::await_initial_publish`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialPublishOutcome {
    /// At least one attempt succeeded. Inner value is the published
    /// `record.ts` (= BEP44 `seq`).
    Succeeded(u64),
    /// Every attempt in the retry budget failed. The publisher task is
    /// still running; subsequent triggers or scheduled republishes can
    /// still succeed.
    Exhausted,
}

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

/// Produces a snapshot of the daemon's per-client answer records each
/// publish cycle (PR #7a). The returned entries are folded into the
/// same [`SignedPacket`] as the main `_openhost` TXT; see
/// [`crate::offer::encode_with_answers`] for the layout.
///
/// Typical producer: a closure over the daemon's `SharedState` that
/// calls `snapshot_answers`. Publishers without an answer source
/// (the common case before PR #7a) pass `None`.
pub type AnswerSource = Box<dyn FnMut() -> Vec<AnswerEntry> + Send>;

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
    /// `None` until the initial-publish retry loop produces a terminal
    /// outcome; `Some(_)` thereafter. Exposed via
    /// [`PublisherHandle::await_initial_publish`] so supervisors can
    /// gate startup on reachability without scraping logs.
    initial_publish_rx: watch::Receiver<Option<InitialPublishOutcome>>,
}

impl PublisherHandle {
    /// Request an immediate republish. Non-blocking; ignored if the trigger
    /// channel is full (a publish is already queued).
    pub fn trigger(&self) {
        let _ = self.trigger_tx.try_send(());
    }

    /// Return a cloneable `Arc<dyn Fn() + Send + Sync>` that, when
    /// called, triggers a republish. Useful for handing into other
    /// subsystems (e.g. the daemon's offer poller) without coupling
    /// them to `PublisherHandle` directly.
    pub fn trigger_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        let tx = self.trigger_tx.clone();
        Arc::new(move || {
            let _ = tx.try_send(());
        })
    }

    /// Abort the background republish task and await its completion.
    pub async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }

    /// Wait until the initial-publish retry loop produces a terminal
    /// outcome. Returns [`InitialPublishOutcome::Succeeded`] when any
    /// attempt lands and [`InitialPublishOutcome::Exhausted`] after the
    /// final retry fails.
    ///
    /// Typical use: the daemon's `App::build` awaits this with a timeout
    /// before declaring "openhostd: up", so a slow relay doesn't leave
    /// the daemon claiming to be reachable while it still isn't.
    /// Supervisors that want a fire-and-forget bootstrap can skip calling
    /// this entirely.
    ///
    /// Safe to call multiple times and from multiple tasks (the method
    /// clones the underlying `watch::Receiver`).
    pub async fn await_initial_publish(&self) -> InitialPublishOutcome {
        let mut rx = self.initial_publish_rx.clone();
        loop {
            if let Some(outcome) = *rx.borrow_and_update() {
                return outcome;
            }
            if rx.changed().await.is_err() {
                // Sender dropped (task exited before publishing anything,
                // e.g. aborted). Treat as Exhausted — the contract is
                // "we won't make more attempts", which is truthful.
                return InitialPublishOutcome::Exhausted;
            }
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
    answer_source: Option<AnswerSource>,
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
            answer_source: None,
            last_seq: initial_last_seq,
            interval: REPUBLISH_INTERVAL,
        }
    }

    /// Override the republish interval. Intended for tests.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Install an [`AnswerSource`]. When set, every publish folds the
    /// source's snapshot into the same `SignedPacket` as the main
    /// `_openhost` record.
    pub fn with_answer_source(mut self, source: AnswerSource) -> Self {
        self.answer_source = Some(source);
        self
    }

    /// Sign, encode, and publish a single record **now**. Updates `last_seq`
    /// on success.
    ///
    /// When an answer source is installed via [`with_answer_source`], the
    /// emitted packet carries one `_answer._<client-hash>` TXT per entry
    /// alongside the main `_openhost` TXT.
    ///
    /// **Timestamp monotonicity.** BEP44's `seq` is the record's `ts` in
    /// seconds; two back-to-back publishes within the same wall-clock
    /// second would share a seq and fail CAS. `publish_once` defends
    /// against that by bumping `record.ts` to `last_seq + 1` when the
    /// source returns a non-monotonic value. A backward system-clock
    /// jump of N seconds manifests as `record.ts` drifting up to N
    /// seconds ahead of wall time until the clock catches up — visible
    /// in `warn!` logs, but publishes keep succeeding.
    ///
    /// [`with_answer_source`]: Publisher::with_answer_source
    pub async fn publish_once(&mut self) -> Result<u64> {
        let record = (self.record_source)();
        let ts = record.ts;
        // Bump the record ts forward if it would collide with the last
        // published seq (BEP44 CAS requires strictly monotonic seq).
        // This matters under PR #7a's 1 Hz poll cadence: two offers
        // arriving within the same wall-clock second would otherwise
        // share a seq and the second publish would fail with a CAS
        // conflict.
        let ts = match self.last_seq {
            Some(last) if ts <= last => {
                let bumped = last.saturating_add(1);
                tracing::warn!(
                    previous = last,
                    would_be = ts,
                    bumped_to = bumped,
                    "openhost-pkarr: record.ts would collide with last seq; bumping",
                );
                bumped
            }
            _ => ts,
        };
        let mut record = record;
        record.ts = ts;
        let signed = SignedRecord::sign(record, &self.signing_key)?;
        let answers = match self.answer_source.as_mut() {
            Some(source) => source(),
            None => Vec::new(),
        };
        let packet = if answers.is_empty() {
            codec::encode(&signed, &self.signing_key)?
        } else {
            encode_with_answers(&signed, &self.signing_key, &answers)?
        };
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
        let (initial_publish_tx, initial_publish_rx) =
            watch::channel::<Option<InitialPublishOutcome>>(None);
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
            // `initial_publish_tx` is notified on every terminal outcome
            // so supervisors that called `await_initial_publish` can
            // proceed without scraping logs.
            initial_publish_with_retry(&mut self, &initial_publish_tx).await;

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
            initial_publish_rx,
        }
    }
}

// --- Helpers --------------------------------------------------------------

/// Drive the first publish through [`INITIAL_PUBLISH_ATTEMPTS`] tries with
/// `INITIAL_PUBLISH_BACKOFF * 2^(n-1)` between attempts. Logs at `info!` on
/// the first success, `warn!` on every intermediate failure, `error!` if
/// every attempt fails. In every terminal branch the outcome is published
/// on `outcome_tx` so waiters on [`PublisherHandle::await_initial_publish`]
/// can unblock.
async fn initial_publish_with_retry(
    publisher: &mut Publisher,
    outcome_tx: &watch::Sender<Option<InitialPublishOutcome>>,
) {
    for attempt in 1..=INITIAL_PUBLISH_ATTEMPTS {
        match publisher.publish_once().await {
            Ok(ts) => {
                tracing::info!(attempt, "openhost-pkarr: initial publish succeeded");
                let _ = outcome_tx.send(Some(InitialPublishOutcome::Succeeded(ts)));
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
                    let _ = outcome_tx.send(Some(InitialPublishOutcome::Exhausted));
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

    #[tokio::test(start_paused = true)]
    async fn await_initial_publish_returns_succeeded_on_first_try() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let expected_ts = 1_700_000_000u64;
        let record_source: RecordSource = Box::new(move || sample_record(expected_ts));

        let publisher = Publisher::new(transport.clone(), sk, record_source, None)
            .with_interval(Duration::from_secs(3600));
        let handle = publisher.spawn();

        // The virtual-time runtime will auto-advance past the publisher
        // task's await points; `await_initial_publish` must resolve once
        // the first attempt returns Ok.
        match handle.await_initial_publish().await {
            InitialPublishOutcome::Succeeded(ts) => assert_eq!(ts, expected_ts),
            other => panic!("expected Succeeded, got {other:?}"),
        }

        handle.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn await_initial_publish_returns_exhausted_after_all_fail() {
        let transport = Arc::new(FlakyTransport::new(usize::MAX));
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let record_source: RecordSource = Box::new(|| sample_record(1_700_000_000));

        let publisher = Publisher::new(transport.clone(), sk, record_source, None)
            .with_interval(Duration::from_secs(3600));
        let handle = publisher.spawn();

        match handle.await_initial_publish().await {
            InitialPublishOutcome::Exhausted => {}
            other => panic!("expected Exhausted, got {other:?}"),
        }
        assert_eq!(
            transport.call_count(),
            INITIAL_PUBLISH_ATTEMPTS as usize,
            "Exhausted should only fire after the full retry budget"
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

    // ---- Answer-source hook (PR #7a) ----

    /// Transport that captures the full serialized packet bytes so tests
    /// can decode and inspect the TXT records the publisher emitted.
    #[derive(Default)]
    struct CapturingTransport {
        packets: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl Transport for CapturingTransport {
        async fn publish(&self, packet: &SignedPacket, _cas: Option<Timestamp>) -> Result<()> {
            // Use `serialize()` (not `as_bytes()`) so the captured bytes
            // round-trip through `SignedPacket::deserialize`: the former
            // prepends the 8-byte last_seen that deserialize expects.
            self.packets.lock().unwrap().push(packet.serialize());
            Ok(())
        }
    }

    #[tokio::test]
    async fn publish_once_without_answer_source_matches_plain_codec() {
        let transport = Arc::new(CapturingTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let record_source: RecordSource = Box::new(|| sample_record(1_700_000_000));
        let mut publisher = Publisher::new(transport.clone(), sk, record_source, None);
        publisher.publish_once().await.unwrap();
        // Rebuild the expected packet via plain codec::encode and compare
        // against the captured packet's `as_bytes()` view (i.e. strip the
        // 8-byte last_seen prefix the capture prepended).
        let captured = &transport.packets.lock().unwrap()[0];
        let captured_core = &captured[8..];
        let expected = codec::encode(
            &SignedRecord::sign(
                sample_record(1_700_000_000),
                &SigningKey::from_bytes(&RFC_SEED),
            )
            .unwrap(),
            &SigningKey::from_bytes(&RFC_SEED),
        )
        .unwrap();
        assert_eq!(captured_core, expected.as_bytes());
    }

    #[tokio::test]
    async fn publish_once_folds_in_answer_entries() {
        use crate::offer::{hash_offer_sdp, AnswerEntry, AnswerPlaintext};
        use openhost_core::pkarr_record::SALT_LEN;
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let transport = Arc::new(CapturingTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let daemon_pk = sk.public_key();
        let record_source: RecordSource = Box::new(|| sample_record(1_700_000_000));

        let client_sk = SigningKey::from_bytes(&[0x77u8; 32]);
        let client_pk = client_sk.public_key();
        let salt = [0x11u8; SALT_LEN];
        let answer_sdp = "v=0\r\na=setup:passive\r\n";
        let plaintext = AnswerPlaintext {
            daemon_pk,
            offer_sdp_hash: hash_offer_sdp("v=0\r\na=setup:active\r\n"),
            answer_sdp: answer_sdp.to_string(),
        };
        let mut rng = StdRng::from_seed([0x42; 32]);
        let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, 42).unwrap();

        let answer_source: AnswerSource = {
            let entry = entry.clone();
            Box::new(move || vec![entry.clone()])
        };
        let mut publisher = Publisher::new(transport.clone(), sk, record_source, None)
            .with_answer_source(answer_source);
        publisher.publish_once().await.unwrap();

        let raw = &transport.packets.lock().unwrap()[0];
        let packet = SignedPacket::deserialize(raw).unwrap();
        let decoded = crate::offer::decode_answer_from_packet(&packet, &salt, &client_pk)
            .unwrap()
            .expect("answer TXT present");
        let opened = decoded.open(&client_sk).unwrap();
        assert_eq!(opened.answer_sdp, answer_sdp);
    }

    #[tokio::test]
    async fn publish_once_bumps_colliding_ts() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        // Both record_source calls return the SAME ts — simulates two
        // offers processed in the same wall-clock second under the
        // PR #7a poll cadence.
        let record_source: RecordSource = Box::new(|| sample_record(1_700_000_000));
        let mut publisher = Publisher::new(transport.clone(), sk, record_source, None);

        let first = publisher.publish_once().await.unwrap();
        let second = publisher.publish_once().await.unwrap();
        assert_eq!(first, 1_700_000_000);
        // The second publish's ts MUST be strictly greater than the first,
        // otherwise BEP44 CAS would reject it.
        assert!(second > first, "colliding ts must bump forward");
    }
}
