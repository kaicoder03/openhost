//! Role-specific signing keys derived from a [`PairingCode`].
//!
//! A file transfer has an asymmetric wire layout even though pairing
//! is symmetric: the SENDER runs the openhost listener (advertises a
//! pkarr "host record" under its pubkey, waits for offers), while
//! the RECEIVER runs the openhost dialer (publishes an offer sealed
//! to the sender's pubkey, polls for the answer).
//!
//! To reuse the existing asymmetric listener/dialer plumbing without
//! either side needing a persistent identity, both roles get a
//! fresh ephemeral Ed25519 keypair derived from the pairing code.
//! The sender's pubkey names the zone the receiver dials; the
//! receiver's pubkey goes into the sender's `watched_clients` so the
//! offer-poller picks up the sealed offer.
//!
//! Derivation uses HKDF-SHA256 with the same salt as
//! [`crate::mailbox::MailboxKey`] but distinct `info` tags, so
//! compromise of one derived key does not reveal the others.
//!
//! [`PairingCode`]: crate::code::PairingCode

use crate::code::PairingCode;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF salt — version the derivation schedule. Identical to the
/// mailbox derivation's salt so all `openhost-peer/v1` keys share a
/// single namespace.
const ROLES_SALT: &[u8] = b"openhost-peer/v1";

/// HKDF `info` tag for the sender role's Ed25519 seed.
const SENDER_INFO: &[u8] = b"openhost-peer/v1/role-sender";

/// HKDF `info` tag for the receiver role's Ed25519 seed.
const RECEIVER_INFO: &[u8] = b"openhost-peer/v1/role-receiver";

/// Ephemeral role-specific signing keys for one file transfer.
///
/// Both peers hold the same [`PairingCode`] and therefore derive
/// the same `Roles` struct. The sender uses [`Roles::sender`]
/// as its listener identity; the receiver uses [`Roles::receiver`]
/// as its dialer identity. Each role's pubkey is trivially
/// recoverable from the code, so sender and receiver can cite each
/// other's pubkeys in pkarr configuration without any additional
/// exchange.
///
/// Both seeds are zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Roles {
    sender_seed: [u8; 32],
    receiver_seed: [u8; 32],
}

impl Roles {
    /// Derive both role keys from a pairing code. Deterministic: the
    /// two peers produce bit-identical `Roles` from the same code.
    pub fn derive(code: &PairingCode) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(ROLES_SALT), code.as_bytes());
        let mut sender_seed = [0u8; 32];
        hk.expand(SENDER_INFO, &mut sender_seed)
            .expect("HKDF-SHA256 supports up to 255*32 bytes of output");
        let mut receiver_seed = [0u8; 32];
        hk.expand(RECEIVER_INFO, &mut receiver_seed)
            .expect("HKDF-SHA256 supports up to 255*32 bytes of output");
        Self {
            sender_seed,
            receiver_seed,
        }
    }

    /// The sender-side signing key. Names the pkarr zone the sender
    /// publishes host records to; the receiver dials
    /// `oh://<sender-pubkey-zbase32>/`.
    pub fn sender(&self) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&self.sender_seed)
    }

    /// The receiver-side signing key. The sender's offer-poller
    /// watches this pubkey so any sealed offer under the receiver's
    /// pkarr zone is picked up and answered.
    pub fn receiver(&self) -> Ed25519SigningKey {
        Ed25519SigningKey::from_bytes(&self.receiver_seed)
    }

    /// Borrow the raw sender seed. Useful for writing the seed into
    /// a tempfile keystore the existing daemon expects.
    pub fn sender_seed(&self) -> &[u8; 32] {
        &self.sender_seed
    }

    /// Borrow the raw receiver seed. Useful for writing the seed into
    /// a tempfile keystore the existing client expects.
    pub fn receiver_seed(&self) -> &[u8; 32] {
        &self.receiver_seed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn derivation_is_deterministic_in_the_secret() {
        let code = PairingCode::generate();
        let a = Roles::derive(&code);
        let b = Roles::derive(&code);
        assert_eq!(a.sender_seed, b.sender_seed);
        assert_eq!(a.receiver_seed, b.receiver_seed);
    }

    #[test]
    fn sender_and_receiver_seeds_are_distinct() {
        let roles = Roles::derive(&PairingCode::generate());
        assert_ne!(
            roles.sender_seed, roles.receiver_seed,
            "sender and receiver must diverge via HKDF info domain separation",
        );
    }

    #[test]
    fn distinct_codes_produce_distinct_roles() {
        let c1 = PairingCode::generate();
        let c2 = PairingCode::generate();
        let r1 = Roles::derive(&c1);
        let r2 = Roles::derive(&c2);
        assert_ne!(r1.sender_seed, r2.sender_seed);
        assert_ne!(r1.receiver_seed, r2.receiver_seed);
    }

    #[test]
    fn role_keys_are_functional_ed25519() {
        // Belt-and-suspenders — verify the HKDF output isn't
        // rejected by ed25519-dalek. (It shouldn't be, since any
        // 32-byte seed is valid, but a zero-seed would be a
        // footgun if we ever regressed the HKDF tags.)
        let roles = Roles::derive(&PairingCode::generate());
        for sk in [roles.sender(), roles.receiver()] {
            let msg = b"openhost peer test";
            let sig = sk.sign(msg);
            sk.verifying_key().verify_strict(msg, &sig).unwrap();
        }
    }

    #[test]
    fn role_seeds_are_domain_separated_from_mailbox() {
        // The Roles and MailboxKey derivations share a salt but
        // use different info tags, so their outputs must differ.
        // Catches an accidental copy-paste of info strings.
        use crate::mailbox::MailboxKey;
        let code = PairingCode::generate();
        let roles = Roles::derive(&code);
        let mailbox = MailboxKey::derive(&code);
        let mbox_pk = mailbox.public_key_bytes();
        let sender_pk = roles.sender().verifying_key().to_bytes();
        let receiver_pk = roles.receiver().verifying_key().to_bytes();
        assert_ne!(mbox_pk, sender_pk);
        assert_ne!(mbox_pk, receiver_pk);
        assert_ne!(sender_pk, receiver_pk);
    }

    /// Known-answer: all-zero secret produces non-zero role keys.
    /// Catches HKDF/ed25519 regressions.
    #[test]
    fn known_answer_all_zero_secret() {
        let roles = Roles::derive(&PairingCode::from_bytes([0u8; 16]));
        assert_ne!(roles.sender_seed, [0u8; 32]);
        assert_ne!(roles.receiver_seed, [0u8; 32]);
    }
}
