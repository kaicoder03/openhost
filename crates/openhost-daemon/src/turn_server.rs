//! Embedded TURN relay (PR #42.2).
//!
//! When `[turn] enabled = true` in `config.toml`, the daemon stands
//! up a small TURN server bound to a UDP port. Clients dialling
//! through pkarr read the `turn_endpoint` field from the v3 host
//! record, add a TURN ICE server to their `RTCPeerConnection`
//! configuration, and get a relay fallback path when direct
//! hole-punching fails (symmetric NAT, UDP-blocking middleboxes,
//! CGNAT asymmetry, etc.).
//!
//! Authentication is intentionally thin: the realm, username, and
//! password are all derivable from the daemon's public Ed25519
//! identity key, which any client already knows from the `oh://`
//! URL. This means ANY openhost-aware client can allocate a relay
//! on the daemon — the goal is not secrecy but rate-limit
//! defensibility (the daemon's upstream HTTP is still gated by the
//! existing openhost auth handshake inside the WebRTC datachannel;
//! TURN is a transport primitive, not an authorisation boundary).
//!
//! If abuse becomes a problem, PR #43+ will tighten the scheme with
//! short-lived credentials signed by the daemon key.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use openhost_core::identity::PublicKey;
use tokio::net::UdpSocket;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use turn::Error as TurnError;
use webrtc_util::vnet::net::Net;

/// Realm the daemon's TURN server advertises. Fixed string so clients
/// can compute credentials without reading the host record twice.
pub const TURN_REALM: &str = "openhost";

/// Username clients must present. Single shared username because
/// TURN clients authenticate with STUN MESSAGE-INTEGRITY that hashes
/// `username:realm:password`; opaque usernames would require extra
/// wire to distribute per-client credentials.
pub const TURN_USERNAME: &str = "openhost";

/// Compute the TURN long-term credential password for a given daemon
/// public key. Both sides — daemon (`auth_handle`) and client
/// (`openhost-client` / extension ICE config) — run this identical
/// function, so no secret transport is needed.
///
/// Construction: `lower_hex(sha256("openhost-turn-v1" || daemon_pk))`
/// truncated to 32 hex chars (128 bits). Strictly deterministic;
/// strictly derivable from public state. The value is not secret —
/// it exists solely so the TURN MESSAGE-INTEGRITY HMAC has the same
/// input on both sides.
pub fn password_for_daemon(daemon_pk: &PublicKey) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"openhost-turn-v1");
    h.update(daemon_pk.to_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

/// Auth handler that resolves every STUN `LongTermCredentials` request
/// to the same daemon-pk-derived credential. The TURN server stores
/// a single HMAC-MD5 key derived from (username, realm, password);
/// `auth_handle` hands that back whenever the username matches.
struct DaemonAuthHandler {
    // Store the already-computed HMAC-MD5 digest (`generate_auth_key`)
    // so we don't recompute on every inbound STUN transaction.
    key: Vec<u8>,
}

impl AuthHandler for DaemonAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> Result<Vec<u8>, TurnError> {
        if username == TURN_USERNAME {
            Ok(self.key.clone())
        } else {
            Err(TurnError::ErrFakeErr)
        }
    }
}

/// A running TURN server. Drop the handle to shut down the server.
pub struct TurnHandle {
    server: Server,
    local_addr: SocketAddr,
}

impl TurnHandle {
    /// Stop the server and release the UDP socket.
    pub async fn shutdown(self) -> Result<(), TurnError> {
        self.server.close().await
    }

    /// Return the UDP socket address the relay is bound to. Useful
    /// when callers passed `:0` for an OS-assigned port and need
    /// to know the real port for their host record.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Configuration for the embedded TURN relay.
#[derive(Debug, Clone)]
pub struct TurnRuntimeConfig {
    /// UDP socket address to bind on locally. For AWS-like deployments
    /// this is `0.0.0.0:<port>`; the security group takes care of
    /// what reaches this port from outside.
    pub bind_addr: SocketAddr,
    /// Publicly-reachable IPv4 address the TURN server advertises as
    /// the relay's IP in the XOR-RELAYED-ADDRESS attribute returned
    /// to clients. For EC2 this is the Elastic IP; for a home box
    /// it's the router's public IP.
    pub public_ip: Ipv4Addr,
}

/// Spawn a TURN server on the configured socket with auth keyed by
/// the daemon's public identity.
///
/// The returned [`TurnHandle`] owns the server; dropping it OR calling
/// [`TurnHandle::shutdown`] releases the socket. Typical usage:
/// store on `App` state for the process lifetime.
pub async fn spawn(
    cfg: &TurnRuntimeConfig,
    daemon_pk: &PublicKey,
) -> Result<TurnHandle, TurnError> {
    let conn = Arc::new(UdpSocket::bind(cfg.bind_addr).await?);
    let local_addr = conn.local_addr()?;
    tracing::info!(
        addr = %local_addr,
        public_ip = %cfg.public_ip,
        "openhostd: TURN relay listening"
    );

    let password = password_for_daemon(daemon_pk);
    let key = generate_auth_key(TURN_USERNAME, TURN_REALM, &password);

    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: IpAddr::V4(cfg.public_ip),
                address: "0.0.0.0".to_owned(),
                net: Arc::new(Net::new(None)),
            }),
        }],
        realm: TURN_REALM.to_owned(),
        auth_handler: Arc::new(DaemonAuthHandler { key }),
        channel_bind_timeout: std::time::Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await?;

    Ok(TurnHandle { server, local_addr })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::identity::SigningKey;

    #[test]
    fn password_is_deterministic_per_daemon() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let pk = sk.public_key();
        let a = password_for_daemon(&pk);
        let b = password_for_daemon(&pk);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32); // 16 bytes hex = 32 chars
    }

    #[test]
    fn password_differs_across_daemons() {
        let sk_a = SigningKey::from_bytes(&[0x11u8; 32]);
        let sk_b = SigningKey::from_bytes(&[0x22u8; 32]);
        assert_ne!(
            password_for_daemon(&sk_a.public_key()),
            password_for_daemon(&sk_b.public_key())
        );
    }

    #[tokio::test]
    async fn spawn_and_shutdown_cleanly() {
        let sk = SigningKey::from_bytes(&[0x33u8; 32]);
        let cfg = TurnRuntimeConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            public_ip: Ipv4Addr::new(127, 0, 0, 1),
        };
        let handle = spawn(&cfg, &sk.public_key()).await.expect("spawn succeeds");
        handle.shutdown().await.expect("shutdown succeeds");
    }
}
