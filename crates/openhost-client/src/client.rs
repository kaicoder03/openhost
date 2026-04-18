//! High-level client API for resolving openhost host records.
//!
//! Wraps [`openhost_pkarr::Resolver`] with an `oh://`-URL surface so
//! callers don't have to decode z-base-32 themselves or pick a `pkarr::Client`
//! configuration. Read-only for now — WebRTC dialling is PR #8.

use crate::error::{ClientError, Result};
use openhost_core::identity::OpenhostUrl;
use openhost_core::pkarr_record::SignedRecord;
use openhost_pkarr::{PkarrResolve, Resolve, Resolver, DEFAULT_RELAYS, GRACE_WINDOW};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Clock closure. Returns the verifier's current Unix timestamp in
/// seconds. Default is [`SystemTime::now()`]; tests override via
/// [`ClientBuilder::now_fn`] so they can pin the 2-hour freshness window
/// without waiting wall-clock time or mutating fixtures.
pub type NowFn = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_now_fn() -> NowFn {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    })
}

/// Builder for [`Client`]. Configure relays + grace window + optional
/// clock override before calling [`ClientBuilder::build`] or
/// [`ClientBuilder::build_with_resolve`].
pub struct ClientBuilder {
    relays: Vec<String>,
    grace: Duration,
    now_fn: NowFn,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self {
            relays: Vec::new(),
            grace: GRACE_WINDOW,
            now_fn: system_now_fn(),
        }
    }
}

impl ClientBuilder {
    /// Replace the relay list. Empty falls back to [`DEFAULT_RELAYS`].
    /// URLs are validated when [`Self::build`] constructs the underlying
    /// `pkarr::Client`.
    pub fn relays<I, S>(mut self, relays: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.relays = relays.into_iter().map(Into::into).collect();
        self
    }

    /// Override the resolver's grace window. Pass [`Duration::ZERO`] for
    /// the snappy "return the first validated record and don't wait for
    /// stragglers" behaviour.
    pub fn grace_window(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Override the clock closure. Production code never needs this.
    ///
    /// Tests use it to pass the fixture's baked `ts` (e.g. `1_700_000_000`)
    /// so the resolver's 2-hour freshness check passes without wall-clock
    /// dependency or fixture mutation. Replay / simulation callers
    /// (debugging a record that was valid when captured) use it too.
    pub fn now_fn<F>(mut self, f: F) -> Self
    where
        F: Fn() -> u64 + Send + Sync + 'static,
    {
        self.now_fn = Arc::new(f);
        self
    }

    /// Build a [`Client`] backed by a real `pkarr::Client`.
    pub fn build(self) -> Result<Client> {
        let relays: Vec<&str> = if self.relays.is_empty() {
            DEFAULT_RELAYS.to_vec()
        } else {
            self.relays.iter().map(String::as_str).collect()
        };

        let mut builder = pkarr::Client::builder();
        builder
            .relays(&relays)
            .map_err(|e| ClientError::ClientBuild(format!("invalid relay URL: {e}")))?;
        let client = builder
            .build()
            .map_err(|e| ClientError::ClientBuild(e.to_string()))?;

        let resolve: Arc<dyn Resolve> = Arc::new(PkarrResolve::new(Arc::new(client)));
        Ok(Client {
            resolver: Resolver::new(resolve).with_grace_window(self.grace),
            now_fn: self.now_fn,
        })
    }

    /// Build a [`Client`] against a caller-supplied [`Resolve`] impl.
    /// Intended for integration tests that need to pin the substrate
    /// response without touching the network.
    pub fn build_with_resolve(self, resolve: Arc<dyn Resolve>) -> Client {
        Client {
            resolver: Resolver::new(resolve).with_grace_window(self.grace),
            now_fn: self.now_fn,
        }
    }
}

/// Client for reading openhost host records.
pub struct Client {
    resolver: Resolver,
    now_fn: NowFn,
}

impl Client {
    /// Start a new [`ClientBuilder`] with default relays + grace window +
    /// system clock.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Resolve the openhost record for `url.pubkey`. Uses the clock
    /// configured on the builder (default: `SystemTime::now()`).
    pub async fn resolve(
        &self,
        url: &OpenhostUrl,
        cached_seq: Option<u64>,
    ) -> Result<SignedRecord> {
        let now_ts = (self.now_fn)();
        self.resolver
            .resolve(&url.pubkey, now_ts, cached_seq)
            .await
            .map_err(Into::into)
    }

    /// Parse `oh_url` and resolve it in one call. Returns
    /// [`ClientError::UrlParse`] if the URL doesn't parse.
    pub async fn resolve_url(&self, oh_url: &str, cached_seq: Option<u64>) -> Result<SignedRecord> {
        let url = OpenhostUrl::parse(oh_url)?;
        self.resolve(&url, cached_seq).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openhost_core::crypto::allowlist_hash;
    use openhost_core::identity::SigningKey;
    use openhost_core::pkarr_record::{
        IceBlob, OpenhostRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };
    use openhost_pkarr::encode;
    use pkarr::SignedPacket;

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// Fixed test timestamp — avoids any dependency on the wall clock
    /// so tests are deterministic under `start_paused = true`.
    const FIXED_TS: u64 = 1_700_000_000;

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

    struct FixedResolve {
        packet: Option<SignedPacket>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl FixedResolve {
        fn new(packet: Option<SignedPacket>) -> Self {
            Self {
                packet,
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Resolve for FixedResolve {
        async fn resolve_most_recent(&self, _pk: &pkarr::PublicKey) -> Option<SignedPacket> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    async fn resolve_url_happy_path() {
        let (sk, packet) = packet_for(FIXED_TS);
        let client = Client::builder()
            .grace_window(Duration::ZERO)
            .now_fn(|| FIXED_TS)
            .build_with_resolve(Arc::new(FixedResolve::new(Some(packet))));

        let pk_zbase = sk.public_key().to_zbase32();
        let record = client
            .resolve_url(&format!("oh://{pk_zbase}/"), None)
            .await
            .expect("resolves");

        assert_eq!(record.record.roles, "server");
        assert_eq!(record.record.dtls_fp, [0x42; DTLS_FINGERPRINT_LEN]);
        assert_eq!(record.record.ts, FIXED_TS);
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_url_rejects_garbage() {
        let client = Client::builder()
            .grace_window(Duration::ZERO)
            .build_with_resolve(Arc::new(FixedResolve::new(None)));

        let err = client.resolve_url("not-an-oh-url", None).await.unwrap_err();
        assert!(matches!(err, ClientError::UrlParse(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn resolve_url_propagates_not_found() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let client = Client::builder()
            .grace_window(Duration::ZERO)
            .build_with_resolve(Arc::new(FixedResolve::new(None)));

        let err = client
            .resolve_url(&format!("oh://{}/", sk.public_key().to_zbase32()), None)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ClientError::Pkarr(openhost_pkarr::PkarrError::NotFound)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn builder_rejects_non_https_relays() {
        // Not a parseable URL — pkarr builder should reject before the
        // pkarr::Client is ever constructed. `Client` is not `Debug`, so
        // pattern-match the Result rather than `.unwrap_err()`.
        let result = Client::builder().relays(["not a url at all"]).build();
        assert!(matches!(result, Err(ClientError::ClientBuild(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn propagates_seq_regression_from_resolver() {
        let (sk, packet) = packet_for(FIXED_TS);
        let client = Client::builder()
            .grace_window(Duration::ZERO)
            .now_fn(|| FIXED_TS)
            .build_with_resolve(Arc::new(FixedResolve::new(Some(packet))));

        // Caller has already seen a newer record — resolver must reject
        // this one on seq-regression grounds, and the error must propagate
        // through `Client` unchanged.
        let err = client
            .resolve_url(
                &format!("oh://{}/", sk.public_key().to_zbase32()),
                Some(FIXED_TS + 1),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            ClientError::Pkarr(openhost_pkarr::PkarrError::SeqRegression { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn grace_window_zero_threads_through_to_resolver() {
        // A Duration::ZERO grace window must cause the underlying
        // Resolver to skip the second substrate race — observable by the
        // fake's call_count remaining at 1 after a successful resolve.
        let (sk, packet) = packet_for(FIXED_TS);
        let fake = Arc::new(FixedResolve::new(Some(packet)));
        let client = Client::builder()
            .grace_window(Duration::ZERO)
            .now_fn(|| FIXED_TS)
            .build_with_resolve(fake.clone());

        client
            .resolve_url(&format!("oh://{}/", sk.public_key().to_zbase32()), None)
            .await
            .expect("resolves");

        assert_eq!(
            fake.call_count(),
            1,
            "Duration::ZERO grace must skip the second resolve_most_recent call"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn default_grace_window_triggers_second_race() {
        // Conversely, with the default GRACE_WINDOW the resolver must
        // call the substrate twice. Guards against accidental regressions
        // in the `Resolver::with_grace_window` default.
        let (sk, packet) = packet_for(FIXED_TS);
        let fake = Arc::new(FixedResolve::new(Some(packet)));
        let client = Client::builder()
            .now_fn(|| FIXED_TS)
            .build_with_resolve(fake.clone());

        client
            .resolve_url(&format!("oh://{}/", sk.public_key().to_zbase32()), None)
            .await
            .expect("resolves");

        assert_eq!(
            fake.call_count(),
            2,
            "default grace window must run the second substrate race"
        );
    }
}
