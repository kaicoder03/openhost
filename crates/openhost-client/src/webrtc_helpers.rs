//! webrtc-rs glue used by [`crate::dialer::Dialer`].
//!
//! Kept as a narrow `pub(crate)` surface so the Dialer body stays
//! readable.

use std::sync::{Arc, Once};
use tokio::sync::mpsc;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice::mdns::MulticastDnsMode;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::RTCPeerConnection;

/// Process-global sentinel so the rustls `ring` provider is installed
/// at most once across the entire process. webrtc-dtls + reqwest
/// (transitive via pkarr) both demand a `CryptoProvider`; if neither
/// the daemon nor any other test has already installed one, the
/// client does it here. Subsequent calls observe the `Once` as done.
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

pub(crate) fn install_crypto_provider_once() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => tracing::debug!("openhost-client: installed rustls `ring` crypto provider"),
            Err(_existing) => tracing::debug!(
                "openhost-client: rustls CryptoProvider already installed; using existing"
            ),
        }
    });
}

/// Build a client-side `webrtc::API`. Uses the default `SettingEngine`
/// — the client is the offerer and webrtc-rs picks `setup:actpass` for
/// the SDP, which the daemon's pre-check at `check_setup_role_is_active`
/// accepts.
pub(crate) fn build_client_api() -> Arc<API> {
    install_crypto_provider_once();
    let mut engine = SettingEngine::default();
    // IP filter applied to every ICE candidate webrtc-rs gathers.
    // Rejects:
    //
    //   1. **All IPv6.** Multi-family candidate sets push the sealed
    //      offer past BEP44's 1000-byte `v` cap on dual-stack hosts;
    //      IPv4 with STUN srflx reaches the same peers in practice.
    //      Covers both link-local (`fe80::/10`, unbind-able without
    //      scope id) and public IPv6 host candidates. Revisit when
    //      the offer encoder gains more fragmentation headroom.
    //
    //   2. **Docker Desktop macOS virtual bridges.**
    //      - `bridge100` at `192.168.64.0/24` (Docker Desktop default)
    //      - `bridge101` at `192.168.65.0/24` (Docker Desktop 4.30+)
    //      These are Mac-local interfaces unreachable by a remote
    //      peer; gathering them produces "phantom" candidates that
    //      ICE burns connectivity-check time on before giving up.
    //
    // Narrow ranges (not a broad RFC 1918 sweep): a real LAN peer
    // legitimately on `192.168.64.x` would want those candidates
    // kept, so we filter the exact Docker Desktop bridge subnets
    // rather than carpet-bombing RFC 1918.
    engine.set_ip_filter(Box::new(|ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V4(v4) => !is_docker_desktop_bridge_v4(&v4),
        std::net::IpAddr::V6(_) => false,
    }));
    // Disable mDNS gathering (`<uuid>.local` candidates). The raw IP
    // variant (`MulticastDnsMode::Disabled`) uses real IP addresses
    // in candidates, which trades a privacy cost (the peer learns
    // your IP — which it was going to need anyway to connect) for a
    // ~70 byte savings per candidate. Remote-side mDNS candidates
    // would fail to resolve cross-host anyway.
    engine.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
    Arc::new(APIBuilder::new().with_setting_engine(engine).build())
}

/// Extracted for unit-test coverage. `true` if `ip` falls inside
/// either of Docker Desktop's macOS virtual-bridge subnets.
fn is_docker_desktop_bridge_v4(ip: &std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 192 && o[1] == 168 && (o[2] == 64 || o[2] == 65)
}

#[cfg(test)]
mod filter_tests {
    use super::is_docker_desktop_bridge_v4;
    use std::net::Ipv4Addr;

    #[test]
    fn docker_desktop_ranges_excluded() {
        assert!(is_docker_desktop_bridge_v4(&Ipv4Addr::new(192, 168, 64, 1)));
        assert!(is_docker_desktop_bridge_v4(&Ipv4Addr::new(
            192, 168, 64, 255
        )));
        assert!(is_docker_desktop_bridge_v4(&Ipv4Addr::new(192, 168, 65, 5)));
    }

    #[test]
    fn real_lan_ranges_preserved() {
        // A home router on 192.168.1.x should NOT be excluded.
        assert!(!is_docker_desktop_bridge_v4(&Ipv4Addr::new(
            192, 168, 1, 154
        )));
        // 192.168.66.x is not a Docker Desktop default — keep.
        assert!(!is_docker_desktop_bridge_v4(&Ipv4Addr::new(
            192, 168, 66, 7
        )));
        // 10/8 private unaffected.
        assert!(!is_docker_desktop_bridge_v4(&Ipv4Addr::new(10, 0, 0, 1)));
        // Public unaffected.
        assert!(!is_docker_desktop_bridge_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    }
}

/// Install an `on_peer_connection_state_change` handler that forwards
/// every transition into an `mpsc::Receiver`. The receiver ends when
/// the PC is dropped (the handler's clone of the sender goes with it).
pub(crate) fn state_change_receiver(
    pc: &Arc<RTCPeerConnection>,
) -> mpsc::UnboundedReceiver<RTCPeerConnectionState> {
    let (tx, rx) = mpsc::unbounded_channel();
    pc.on_peer_connection_state_change(Box::new(move |state| {
        let _ = tx.send(state);
        Box::pin(async {})
    }));
    rx
}

/// Install an `on_open` handler that fires a one-shot `Notify` when
/// the data channel becomes open. Uses `notify_one` so a permit is
/// stored if `open` fires before any waiter awaits — the next
/// `notified().await` returns immediately in that case.
pub(crate) fn dc_open_signal(dc: &Arc<RTCDataChannel>) -> Arc<tokio::sync::Notify> {
    let notify = Arc::new(tokio::sync::Notify::new());
    let inner = Arc::clone(&notify);
    dc.on_open(Box::new(move || {
        let inner = Arc::clone(&inner);
        Box::pin(async move {
            inner.notify_one();
        })
    }));
    notify
}
