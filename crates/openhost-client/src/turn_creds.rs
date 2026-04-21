//! Client-side TURN credential derivation (PR #42.3).
//!
//! Mirrors `openhost-daemon::turn_server` — both sides compute the
//! same password from the daemon's public Ed25519 identity, so a
//! client with only the `oh://<daemon-pk>/` URL can authenticate
//! against the daemon's embedded TURN relay without any pre-shared
//! secret. The password is not actually secret (anyone who knows the
//! daemon pubkey can compute it), but TURN long-term auth requires
//! MESSAGE-INTEGRITY HMAC with matching inputs on both peers; this
//! function provides that matching input.

use openhost_core::identity::PublicKey;

/// Fixed TURN realm advertised by openhost daemons.
pub const TURN_REALM: &str = "openhost";

/// Fixed TURN username clients must present.
pub const TURN_USERNAME: &str = "openhost";

/// Compute the long-term TURN password for a daemon, from its public
/// key. See `openhost-daemon::turn_server::password_for_daemon` — the
/// two functions MUST agree byte-for-byte.
pub fn password_for_daemon(daemon_pk: &PublicKey) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"openhost-turn-v1");
    h.update(daemon_pk.to_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::identity::SigningKey;

    #[test]
    fn deterministic_per_daemon() {
        let sk = SigningKey::from_bytes(&[0x11u8; 32]);
        let pk = sk.public_key();
        assert_eq!(password_for_daemon(&pk), password_for_daemon(&pk));
    }

    #[test]
    fn differs_across_daemons() {
        let sk_a = SigningKey::from_bytes(&[0x11u8; 32]);
        let sk_b = SigningKey::from_bytes(&[0x22u8; 32]);
        assert_ne!(
            password_for_daemon(&sk_a.public_key()),
            password_for_daemon(&sk_b.public_key())
        );
    }
}
