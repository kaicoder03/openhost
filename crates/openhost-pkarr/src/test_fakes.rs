//! In-memory pkarr substrate for integration tests (PR #8).
//!
//! Two halves of the openhost protocol run as separate `tokio` tasks in
//! the same process, but the daemon publishes and the client resolves
//! via the pkarr fan-out. Real relays + DHT would make the test suite
//! flaky + slow; this module provides a trivial `HashMap<pubkey,
//! SignedPacket>` that implements both [`Transport`] (what publishers
//! write to) and [`Resolve`] (what resolvers read from). A single
//! [`MemoryPkarrNetwork`] instance held by both halves is enough to
//! drive the full handshake.
//!
//! Gated behind the `test-fakes` Cargo feature so it never appears in a
//! release binary.
//!
//! ```ignore
//! let net = MemoryPkarrNetwork::new();
//! let transport = net.as_transport();
//! let resolver = net.as_resolve();
//! // Hand `transport` to the daemon's publisher and `resolver` to the
//! // client's dialer. Both sides see the same store.
//! ```

use crate::publisher::Transport;
use crate::resolver::Resolve;
use crate::Result;
use async_trait::async_trait;
use pkarr::{SignedPacket, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Shared in-memory pkarr store. Holds serialized `SignedPacket` bytes
/// keyed by the packet's 32-byte Ed25519 pubkey. Serialized (rather
/// than owned `SignedPacket`) because the pkarr crate's `SignedPacket`
/// is not `Clone`.
#[derive(Clone, Default)]
pub struct MemoryPkarrNetwork {
    inner: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

impl MemoryPkarrNetwork {
    /// Create an empty network. Clone the returned handle freely — the
    /// underlying `Arc<RwLock<..>>` is shared across all clones.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a [`Transport`] handle that writes into this network.
    #[must_use]
    pub fn as_transport(&self) -> Arc<dyn Transport> {
        Arc::new(MemoryTransport {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Return a [`Resolve`] handle that reads from this network.
    #[must_use]
    pub fn as_resolve(&self) -> Arc<dyn Resolve> {
        Arc::new(MemoryResolve {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Snapshot every currently-stored packet as `(pubkey_bytes, serialized_bytes)`
    /// pairs. Useful for ad-hoc assertions in tests.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<[u8; 32], Vec<u8>> {
        self.inner.read().expect("memory net lock poisoned").clone()
    }

    /// Remove the stored packet for `pubkey_bytes`, if any. Returns
    /// whether an entry was removed.
    pub fn clear_pubkey(&self, pubkey_bytes: &[u8; 32]) -> bool {
        self.inner
            .write()
            .expect("memory net lock poisoned")
            .remove(pubkey_bytes)
            .is_some()
    }
}

struct MemoryTransport {
    inner: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

#[async_trait]
impl Transport for MemoryTransport {
    async fn publish(&self, packet: &SignedPacket, _cas: Option<Timestamp>) -> Result<()> {
        // Ignore the CAS — the in-memory store doesn't serialize
        // out-of-order writes across tasks, and tests that care about
        // CAS semantics should use the `FakeTransport` unit tests in
        // `publisher.rs` instead.
        let key = *packet.public_key().as_bytes();
        self.inner
            .write()
            .expect("memory net lock poisoned")
            .insert(key, packet.serialize());
        Ok(())
    }
}

struct MemoryResolve {
    inner: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
}

#[async_trait]
impl Resolve for MemoryResolve {
    async fn resolve_most_recent(&self, public_key: &pkarr::PublicKey) -> Option<SignedPacket> {
        let key = *public_key.as_bytes();
        let serialized = self
            .inner
            .read()
            .expect("memory net lock poisoned")
            .get(&key)
            .cloned()?;
        SignedPacket::deserialize(&serialized).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode;
    use openhost_core::identity::SigningKey;
    use openhost_core::pkarr_record::{
        OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };

    const SEED: [u8; 32] = [0x42u8; 32];

    fn sample_packet(ts: u64) -> (SigningKey, SignedPacket) {
        let sk = SigningKey::from_bytes(&SEED);
        let record = OpenhostRecord {
            version: PROTOCOL_VERSION,
            ts,
            dtls_fp: [0x11; DTLS_FINGERPRINT_LEN],
            roles: "server".to_string(),
            salt: [0x22; SALT_LEN],
            disc: String::new(),
            turn_endpoint: None,
        };
        let signed = SignedRecord::sign(record, &sk).unwrap();
        let packet = encode(&signed, &sk).unwrap();
        (sk, packet)
    }

    #[tokio::test]
    async fn publish_and_resolve_roundtrip() {
        let net = MemoryPkarrNetwork::new();
        let (sk, packet) = sample_packet(1_700_000_000);
        net.as_transport().publish(&packet, None).await.unwrap();

        let key_bytes = sk.public_key().to_bytes();
        let pkarr_pk = pkarr::PublicKey::try_from(&key_bytes).unwrap();
        let fetched = net.as_resolve().resolve_most_recent(&pkarr_pk).await;
        let got = fetched.expect("resolved");
        assert_eq!(got.as_bytes(), packet.as_bytes());
    }

    #[tokio::test]
    async fn second_publish_overwrites_first() {
        let net = MemoryPkarrNetwork::new();
        let (_sk, first) = sample_packet(1_700_000_000);
        let (sk, second) = sample_packet(1_700_000_060);
        net.as_transport().publish(&first, None).await.unwrap();
        net.as_transport().publish(&second, None).await.unwrap();

        let key_bytes = sk.public_key().to_bytes();
        let pkarr_pk = pkarr::PublicKey::try_from(&key_bytes).unwrap();
        let fetched = net
            .as_resolve()
            .resolve_most_recent(&pkarr_pk)
            .await
            .unwrap();
        assert_eq!(fetched.as_bytes(), second.as_bytes());
    }

    #[tokio::test]
    async fn distinct_pubkeys_isolated() {
        let net = MemoryPkarrNetwork::new();
        let (sk_a, packet_a) = sample_packet(1_700_000_000);
        net.as_transport().publish(&packet_a, None).await.unwrap();

        // A different identity → different pubkey → different slot.
        let sk_b = SigningKey::from_bytes(&[0x99u8; 32]);
        let key_b = sk_b.public_key().to_bytes();
        let pkarr_pk_b = pkarr::PublicKey::try_from(&key_b).unwrap();
        assert!(net
            .as_resolve()
            .resolve_most_recent(&pkarr_pk_b)
            .await
            .is_none());

        let key_a = sk_a.public_key().to_bytes();
        let pkarr_pk_a = pkarr::PublicKey::try_from(&key_a).unwrap();
        assert!(net
            .as_resolve()
            .resolve_most_recent(&pkarr_pk_a)
            .await
            .is_some());
    }

    #[tokio::test]
    async fn clear_pubkey_removes_entry() {
        let net = MemoryPkarrNetwork::new();
        let (sk, packet) = sample_packet(1_700_000_000);
        net.as_transport().publish(&packet, None).await.unwrap();

        let key = sk.public_key().to_bytes();
        assert!(net.clear_pubkey(&key));
        assert!(!net.clear_pubkey(&key)); // already gone

        let pkarr_pk = pkarr::PublicKey::try_from(&key).unwrap();
        assert!(net
            .as_resolve()
            .resolve_most_recent(&pkarr_pk)
            .await
            .is_none());
    }
}
