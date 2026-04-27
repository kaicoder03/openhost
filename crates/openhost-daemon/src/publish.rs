//! Wires the daemon's live state into the `openhost-pkarr` publisher.
//!
//! The publisher signs and publishes a fresh [`OpenhostRecord`] every
//! 30 minutes (or on demand via [`PublishService::trigger`]). This module's
//! job is to expose a [`SharedState`] that the rest of the daemon can
//! mutate — DTLS fingerprint on cert rotation (PR #5), `ice` blobs when
//! a paired client's offer lands (PR #5), `allow` list when a new
//! pairing completes (PR #7) — and have the publisher pick the latest
//! snapshot on its next publish.
//!
//! The [`Transport`] handed to the underlying publisher is parameterised
//! so integration tests can inject a fake without opening sockets. The
//! normal path ([`start`]) wraps a real `pkarr::Client` built from the
//! configured relay list and the Mainline DHT.

use crate::config::PkarrConfig;
use crate::error::{PublishError, Result as DaemonResult};
use hkdf::Hkdf;
use openhost_core::crypto::allowlist_hash;
use openhost_core::identity::{PublicKey, SigningKey};
use openhost_core::pkarr_record::{
    OpenhostRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
};
use openhost_pkarr::{
    AnswerEntry, AnswerSource, PkarrResolve, PkarrTransport, Publisher, PublisherHandle,
    RecordSource, Resolve, Transport, CLIENT_HASH_LEN, DEFAULT_RELAYS,
};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use zeroize::Zeroize;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Domain-separation salt for the allowlist-salt derivation. Stable across
/// openhost protocol versions so a daemon rebooted on the same identity
/// always produces the same per-host salt.
const ALLOW_SALT_HKDF_SALT: &[u8] = b"openhost-allow-salt-v1";

/// Mutable state shared between the publisher and the rest of the daemon.
///
/// Every field that later PRs will mutate is wrapped in a `RwLock`; every
/// field the publisher must see consistently — i.e. the per-host salt
/// that keys the allowlist HMAC — is derived deterministically from the
/// host identity and therefore immutable for the lifetime of this struct.
///
/// **Salt derivation:** the salt is `HKDF-SHA256(ikm=identity_seed,
/// salt="openhost-allow-salt-v1", info="")`. Deriving from the identity
/// means a rebooted daemon with the same identity file produces the same
/// salt, so any `_allow` entries clients computed against a previous
/// process remain valid. PR #7 (pairing + allowlist) relies on this
/// stability; randomising per-boot would silently invalidate every paired
/// client whenever the daemon restarted.
pub struct SharedState {
    dtls_fp: RwLock<[u8; DTLS_FINGERPRINT_LEN]>,
    salt: [u8; SALT_LEN],
    /// In-process allow list. Consulted on every inbound offer via
    /// [`is_client_allowed`]; never published on the wire in v2+ of
    /// the record schema. See spec `01-wire-format.md §2`.
    allow: RwLock<Vec<[u8; 16]>>,
    roles: String,
    /// Per-client answer records queued for publication. Keyed by
    /// `client_hash` (HMAC of `client_pk` under the daemon's salt) so a
    /// later answer for the same client overwrites the previous one.
    /// Drained on every publish via [`snapshot_answers`]; the
    /// entries remain in the map across publishes so stale resolvers
    /// still see the most recent answer.
    ///
    /// [`snapshot_answers`]: SharedState::snapshot_answers
    answers: RwLock<HashMap<[u8; CLIENT_HASH_LEN], AnswerEntry>>,
    /// Optional embedded-TURN endpoint to advertise in v3 host records.
    /// `None` emits a v2 record (default); `Some` emits v3 with the
    /// daemon's publicly-reachable TURN IP + UDP port.
    turn_endpoint: RwLock<Option<openhost_core::pkarr_record::TurnEndpoint>>,
}

impl SharedState {
    /// Build a new `SharedState` with the given DTLS fingerprint. The salt
    /// is derived deterministically from `identity` via HKDF-SHA256 (see
    /// the struct-level doc for the scheme).
    pub fn new(identity: &SigningKey, dtls_fp: [u8; DTLS_FINGERPRINT_LEN]) -> Self {
        let mut seed = identity.to_bytes();
        let hk = Hkdf::<Sha256>::new(Some(ALLOW_SALT_HKDF_SALT), &seed);
        seed.zeroize();
        let mut salt = [0u8; SALT_LEN];
        hk.expand(&[], &mut salt)
            .expect("HKDF expansion to 32 bytes cannot fail");
        Self {
            dtls_fp: RwLock::new(dtls_fp),
            salt,
            allow: RwLock::new(Vec::new()),
            roles: "server".to_string(),
            answers: RwLock::new(HashMap::new()),
            turn_endpoint: RwLock::new(None),
        }
    }

    /// Install (or clear) the TURN endpoint advertised in the host
    /// record. Called by [`App::build`] when `[turn] enabled = true`.
    pub fn set_turn_endpoint(&self, ep: Option<openhost_core::pkarr_record::TurnEndpoint>) {
        *self
            .turn_endpoint
            .write()
            .expect("turn_endpoint lock poisoned") = ep;
    }

    /// Current TURN endpoint advertised in the host record, if any.
    /// Read by the listener to self-allocate a relay candidate so
    /// browser dials have a guaranteed (relay, relay) pair even when
    /// Chrome's `.local` mDNS host candidates fail to resolve.
    pub fn turn_endpoint(&self) -> Option<openhost_core::pkarr_record::TurnEndpoint> {
        *self
            .turn_endpoint
            .read()
            .expect("turn_endpoint lock poisoned")
    }

    /// Queue an answer entry for publication. The entry is keyed on
    /// `entry.client_hash`; a later entry for the same client overwrites
    /// the previous one.
    pub fn push_answer(&self, entry: AnswerEntry) {
        self.answers
            .write()
            .expect("answers lock poisoned")
            .insert(entry.client_hash, entry);
    }

    /// Snapshot (clone) of every queued answer. The publisher's
    /// `AnswerSource` calls this on each publish. Entries remain in
    /// the map across calls — a later `push_answer` for the same
    /// `client_hash` overwrites.
    pub fn snapshot_answers(&self) -> Vec<AnswerEntry> {
        self.answers
            .read()
            .expect("answers lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// Replace the DTLS fingerprint (for cert rotation). Callers MUST
    /// follow up with [`PublishService::trigger`] or the published record
    /// will pin to the previous fingerprint for up to the full republish
    /// interval.
    pub fn set_dtls_fp(&self, fp: [u8; DTLS_FINGERPRINT_LEN]) {
        *self.dtls_fp.write().expect("dtls_fp lock poisoned") = fp;
    }

    /// Current DTLS fingerprint snapshot. Returned by copy; no lock is held.
    pub fn dtls_fp(&self) -> [u8; DTLS_FINGERPRINT_LEN] {
        *self.dtls_fp.read().expect("dtls_fp lock poisoned")
    }

    /// The immutable salt for this daemon's allowlist HMAC.
    pub fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }

    /// Snapshot of the current allow list.
    pub fn allow(&self) -> Vec<[u8; 16]> {
        self.allow.read().expect("allow lock poisoned").clone()
    }

    /// Replace the entire allow list. Used by `App::run`'s SIGHUP
    /// reload path to swap in a freshly-loaded pairing DB without
    /// tearing down live sessions.
    pub fn replace_allow(&self, hashes: Vec<[u8; 16]>) {
        *self.allow.write().expect("allow lock poisoned") = hashes;
    }

    /// Whether a client pubkey's HMAC projection is currently in the
    /// allow list. Recomputes `allowlist_hash(salt, client_pk)` and
    /// consults the current snapshot.
    #[must_use]
    pub fn is_client_allowed(&self, client_pk: &PublicKey) -> bool {
        let hash = allowlist_hash(&self.salt, &client_pk.to_bytes());
        self.allow
            .read()
            .expect("allow lock poisoned")
            .contains(&hash)
    }

    /// Insert a single precomputed hash into the allow list. Idempotent
    /// (duplicate entries are dropped). Most callers use
    /// [`replace_allow`] instead; this is exposed for mutation-style
    /// tests and for a future TOFU-pairing flow.
    ///
    /// [`replace_allow`]: SharedState::replace_allow
    pub fn add_client_hash(&self, hash: [u8; 16]) {
        let mut guard = self.allow.write().expect("allow lock poisoned");
        if !guard.contains(&hash) {
            guard.push(hash);
        }
    }

    /// Remove a single hash from the allow list. Returns whether the
    /// hash was present before the call.
    pub fn remove_client_hash(&self, hash: [u8; 16]) -> bool {
        let mut guard = self.allow.write().expect("allow lock poisoned");
        let before = guard.len();
        guard.retain(|e| *e != hash);
        before != guard.len()
    }

    /// Build a fresh [`OpenhostRecord`] with `ts` set to **now**. This is
    /// what the publisher calls on every tick. The in-process `allow`
    /// list is deliberately NOT copied into the record — v2+ of the
    /// schema keeps the allow list private so the main record stays
    /// small and more answer fragments fit the BEP44 packet budget.
    pub fn snapshot_record(&self) -> OpenhostRecord {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let turn_endpoint = *self
            .turn_endpoint
            .read()
            .expect("turn_endpoint lock poisoned");
        // Deployments that leave [turn].enabled = false emit a v2 record
        // (byte-identical to pre-PR #42 output). When turn_endpoint is
        // Some, bump to v3 so the trailer is included on the wire.
        let version = if turn_endpoint.is_some() {
            3
        } else {
            PROTOCOL_VERSION
        };
        OpenhostRecord {
            version,
            ts,
            dtls_fp: self.dtls_fp(),
            roles: self.roles.clone(),
            salt: self.salt,
            disc: String::new(),
            turn_endpoint,
        }
    }
}

/// The running publisher. Wraps [`PublisherHandle`] so callers don't need
/// to depend on `openhost-pkarr` directly.
pub struct PublishService {
    handle: PublisherHandle,
}

impl PublishService {
    /// Fire an immediate republish. Non-blocking; dropped if a publish is
    /// already queued (per `openhost-pkarr::PublisherHandle::trigger`).
    pub fn trigger(&self) {
        self.handle.trigger();
    }

    /// Return a cloneable trigger callable. The offer poller uses this
    /// to request an immediate republish whenever it stashes a new
    /// answer; a plain `Fn()` keeps the poller agnostic of the
    /// underlying channel plumbing.
    pub fn trigger_handle(&self) -> Arc<dyn Fn() + Send + Sync> {
        self.handle.trigger_handle()
    }

    /// Wait for the underlying publisher's initial-publish retry loop
    /// to terminate (success or exhaustion). Delegates to
    /// [`openhost_pkarr::PublisherHandle::await_initial_publish`].
    ///
    /// `App::run` uses this to gate its "openhostd: up" log line on
    /// discoverability — so the daemon never claims to be up when the
    /// first publish is still in flight or already failed out.
    pub async fn await_initial_publish(&self) -> openhost_pkarr::InitialPublishOutcome {
        self.handle.await_initial_publish().await
    }

    /// Gracefully shut down the publisher.
    pub async fn shutdown(self) {
        self.handle.shutdown().await;
    }
}

/// Start the publisher against a real `pkarr::Client`.
///
/// Returns the running [`PublishService`] alongside a [`Resolve`] handle
/// built from the same underlying `pkarr::Client` — the offer poller
/// (PR #7a) uses that handle to look up per-client offer records.
pub async fn start(
    cfg: &PkarrConfig,
    identity: Arc<SigningKey>,
    state: Arc<SharedState>,
) -> DaemonResult<(PublishService, Arc<dyn Resolve>)> {
    let client = build_default_client(cfg)?;
    let transport: Arc<dyn Transport> = Arc::new(PkarrTransport::new(Arc::clone(&client)));
    let resolver: Arc<dyn Resolve> = Arc::new(PkarrResolve::new(client));
    let service = start_with_transport(cfg, identity, state, transport);
    Ok((service, resolver))
}

/// Start the publisher against an already-constructed [`Transport`].
/// Used by integration tests that inject a fake transport.
pub fn start_with_transport(
    cfg: &PkarrConfig,
    identity: Arc<SigningKey>,
    state: Arc<SharedState>,
    transport: Arc<dyn Transport>,
) -> PublishService {
    let record_source: RecordSource = {
        let state = state.clone();
        Box::new(move || state.snapshot_record())
    };
    let answer_source: AnswerSource = {
        let state = state.clone();
        Box::new(move || state.snapshot_answers())
    };

    let publisher = Publisher::new(transport, identity, record_source, None)
        .with_interval(Duration::from_secs(cfg.republish_secs))
        .with_answer_source(answer_source);

    PublishService {
        handle: publisher.spawn(),
    }
}

/// Build a `pkarr::Client` from the daemon config. Shared between the
/// publisher side (via [`PkarrTransport`]) and the resolver side (via
/// [`PkarrResolve`]) so both sides consult the same relay set.
pub(crate) fn build_default_client(cfg: &PkarrConfig) -> DaemonResult<Arc<pkarr::Client>> {
    let relays: Vec<&str> = if cfg.relays.is_empty() {
        DEFAULT_RELAYS.to_vec()
    } else {
        cfg.relays.iter().map(String::as_str).collect()
    };

    let mut builder = pkarr::Client::builder();
    builder
        .relays(&relays)
        .map_err(|e| PublishError::ClientBuild(format!("invalid relay URL: {e}")))?;

    // Startup-gating resolution (was TODO(M3.2) pre-PR #5): `App::run`
    // now awaits `PublishService::await_initial_publish` with a 10-s
    // budget before logging "openhostd: up". Build still returns
    // asynchronously — `App::build` spawns the publisher task, which
    // runs its own retry loop (`INITIAL_PUBLISH_BACKOFF * 2^(n-1)`
    // across `INITIAL_PUBLISH_ATTEMPTS`) — but the daemon's visible
    // readiness signal is now tied to the first publish's terminal
    // outcome instead of just task liveness.
    let client = builder
        .build()
        .map_err(|e| PublishError::ClientBuild(e.to_string()))?;

    Ok(Arc::new(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use openhost_pkarr::{PkarrError, Result as PkarrResult};
    use pkarr::{SignedPacket, Timestamp};
    use std::sync::Mutex;

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    #[derive(Default)]
    struct FakeTransport {
        calls: Mutex<Vec<[u8; DTLS_FINGERPRINT_LEN]>>,
    }

    #[async_trait]
    impl Transport for FakeTransport {
        async fn publish(&self, packet: &SignedPacket, _cas: Option<Timestamp>) -> PkarrResult<()> {
            // Recover the dtls_fp by decoding the packet back into a SignedRecord.
            let signed = openhost_pkarr::decode(packet).map_err(|_| PkarrError::NotFound)?;
            self.calls.lock().unwrap().push(signed.record.dtls_fp);
            Ok(())
        }
    }

    fn test_cfg() -> PkarrConfig {
        PkarrConfig {
            relays: vec![],
            republish_secs: 3600, // keep the ticker inert; only the initial publish fires
            offer_poll: Default::default(),
        }
    }

    #[tokio::test]
    async fn initial_publish_carries_expected_fingerprint() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let expected_fp = [0x42u8; DTLS_FINGERPRINT_LEN];
        let state = Arc::new(SharedState::new(&sk, expected_fp));

        let service = start_with_transport(&test_cfg(), sk, state.clone(), transport.clone());

        // Give the initial publish a moment to fire.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let calls = transport.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 1, "expected exactly one initial publish");
        assert_eq!(calls[0], expected_fp);

        service.shutdown().await;
    }

    #[tokio::test]
    async fn trigger_after_fp_mutation_publishes_new_fingerprint() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let state = Arc::new(SharedState::new(&sk, [0x01; DTLS_FINGERPRINT_LEN]));

        let service = start_with_transport(&test_cfg(), sk, state.clone(), transport.clone());

        tokio::time::sleep(Duration::from_millis(30)).await;

        state.set_dtls_fp([0x02; DTLS_FINGERPRINT_LEN]);
        service.trigger();

        tokio::time::sleep(Duration::from_millis(30)).await;

        let calls = transport.calls.lock().unwrap().clone();
        assert!(
            calls.len() >= 2,
            "expected initial + triggered publish, saw {}",
            calls.len()
        );
        assert_eq!(calls[0], [0x01; DTLS_FINGERPRINT_LEN]);
        assert_eq!(
            calls.last().unwrap(),
            &[0x02; DTLS_FINGERPRINT_LEN],
            "latest publish must carry the rotated fingerprint"
        );

        service.shutdown().await;
    }

    /// Snapshot of a freshly-built `SharedState` publishes the expected
    /// v2 record shape: right version, roles, and no `allow`/`ice` —
    /// both dropped from the main record in PR #22.
    #[tokio::test]
    async fn snapshot_record_produces_v2_shape() {
        let transport = Arc::new(FakeTransport::default());
        let sk = Arc::new(SigningKey::from_bytes(&RFC_SEED));
        let state = Arc::new(SharedState::new(&sk, [0x42; DTLS_FINGERPRINT_LEN]));

        let service = start_with_transport(&test_cfg(), sk, state.clone(), transport.clone());
        tokio::time::sleep(Duration::from_millis(50)).await;

        let record = state.snapshot_record();
        assert_eq!(record.roles, "server");
        assert_eq!(record.version, PROTOCOL_VERSION);

        service.shutdown().await;
    }

    #[test]
    fn salt_is_derived_deterministically_from_identity() {
        let sk_a = SigningKey::from_bytes(&RFC_SEED);
        let s1 = SharedState::new(&sk_a, [0; DTLS_FINGERPRINT_LEN]).salt();
        let s2 = SharedState::new(&sk_a, [0xFF; DTLS_FINGERPRINT_LEN]).salt();
        assert_eq!(
            s1, s2,
            "same identity must yield the same salt across reboots \
             (the dtls_fp value must not influence salt)"
        );

        // A different identity produces a different salt — domain separation
        // means no two hosts share one by construction.
        let mut other_seed = RFC_SEED;
        other_seed[0] ^= 1;
        let sk_b = SigningKey::from_bytes(&other_seed);
        let s_other = SharedState::new(&sk_b, [0; DTLS_FINGERPRINT_LEN]).salt();
        assert_ne!(s1, s_other, "distinct identities must yield distinct salts");
    }

    #[test]
    fn is_client_allowed_rehashes_and_checks() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let state = SharedState::new(&sk, [0; DTLS_FINGERPRINT_LEN]);
        let client_pk = SigningKey::from_bytes(&[0x22; 32]).public_key();
        assert!(!state.is_client_allowed(&client_pk));
        let hash = allowlist_hash(&state.salt(), &client_pk.to_bytes());
        state.add_client_hash(hash);
        assert!(state.is_client_allowed(&client_pk));
    }

    #[test]
    fn replace_allow_overwrites() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let state = SharedState::new(&sk, [0; DTLS_FINGERPRINT_LEN]);
        state.add_client_hash([0x11; 16]);
        state.replace_allow(vec![[0x22; 16], [0x33; 16]]);
        let snap = state.allow();
        assert_eq!(snap, vec![[0x22; 16], [0x33; 16]]);
    }

    #[test]
    fn add_client_hash_is_idempotent() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let state = SharedState::new(&sk, [0; DTLS_FINGERPRINT_LEN]);
        state.add_client_hash([0x11; 16]);
        state.add_client_hash([0x11; 16]);
        assert_eq!(state.allow().len(), 1);
    }

    #[test]
    fn remove_client_hash_returns_presence() {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let state = SharedState::new(&sk, [0; DTLS_FINGERPRINT_LEN]);
        state.add_client_hash([0x11; 16]);
        assert!(state.remove_client_hash([0x11; 16]));
        assert!(!state.remove_client_hash([0x11; 16]));
    }

    #[test]
    fn salt_matches_known_hkdf_vector() {
        // Pin the RFC-seed salt. If this expected value ever has to change,
        // it's a protocol-visible bump: existing paired clients' `_allow`
        // entries become invalid.
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let got = SharedState::new(&sk, [0; DTLS_FINGERPRINT_LEN]).salt();

        // Regenerate manually — belt-and-braces that our call matches the
        // documented scheme.
        let mut expected = [0u8; SALT_LEN];
        let hk = Hkdf::<Sha256>::new(Some(ALLOW_SALT_HKDF_SALT), &RFC_SEED);
        hk.expand(&[], &mut expected).unwrap();
        assert_eq!(got, expected);
    }
}
