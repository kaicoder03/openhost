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
            // TODO(M3): retry the initial publish with exponential backoff (3
            // attempts) before falling back to the 30-minute cadence. A single
            // transient relay failure here leaves the host undiscoverable until
            // the next scheduled tick.
            if let Err(err) = self.publish_once().await {
                tracing::warn!(?err, "openhost-pkarr: initial publish failed");
            }

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

        let mut publisher =
            Publisher::new(transport.clone(), sk, record_source, Some(seed_ts));

        // First publish fails — `last_seq` MUST remain at the seeded value
        // so the next attempt still sends the correct CAS.
        assert!(publisher.publish_once().await.is_err());
        assert_eq!(publisher.last_seq, Some(seed_ts));

        // Second failure: same invariant, regardless of the record_source
        // having moved forward.
        assert!(publisher.publish_once().await.is_err());
        assert_eq!(publisher.last_seq, Some(seed_ts));
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
