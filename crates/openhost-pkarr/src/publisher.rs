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
pub struct PublisherHandle {
    trigger_tx: mpsc::Sender<()>,
    task: JoinHandle<()>,
}

impl PublisherHandle {
    /// Request an immediate republish. Non-blocking; ignored if the trigger
    /// channel is full (a publish is already queued).
    pub fn trigger(&self) {
        let _ = self.trigger_tx.try_send(());
    }

    /// Abort the background republish task and await its completion.
    pub async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }

    /// Borrow the underlying `JoinHandle` for callers that want their own
    /// shutdown semantics.
    pub fn task(&self) -> &JoinHandle<()> {
        &self.task
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
                    Some(()) = trigger_rx.recv() => {
                        if let Err(err) = self.publish_once().await {
                            tracing::warn!(?err, "openhost-pkarr: triggered republish failed");
                        }
                    }
                    else => break,
                }
            }
        });

        PublisherHandle { trigger_tx, task }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::crypto::allowlist_hash;
    use openhost_core::pkarr_record::{
        IceBlob, OpenhostRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };
    use std::sync::Mutex;

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn sample_record(ts: u64) -> OpenhostRecord {
        let salt = [0x11u8; SALT_LEN];
        let client_pk = [0xAAu8; 32];
        let hash = allowlist_hash(&salt, &client_pk);
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
            disc: "dht=1".to_string(),
        }
    }

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
