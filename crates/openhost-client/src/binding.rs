//! Client-side channel-binding handshake (spec §7.1, PR #5.5).
//!
//! The host's `openhost-daemon::channel_binding::ChannelBinder` drives
//! the other half of the handshake. This module mirrors that API from
//! the client's perspective:
//!
//! 1. Daemon sends `AuthNonce` (32 random bytes) as its first frame on
//!    the data channel.
//! 2. Client calls [`ClientBinder::sign_auth_client`] with the nonce +
//!    the RFC 5705 DTLS exporter secret, producing the 96-byte
//!    `AuthClient` payload (32-byte `client_pk` || 64-byte signature
//!    over `auth_bytes`).
//! 3. Daemon verifies + replies with `AuthHost` (64-byte signature).
//! 4. Client calls [`ClientBinder::verify_auth_host`] to confirm the
//!    daemon controls the identity key it's advertising.
//!
//! `auth_bytes` is
//! [`openhost_core::crypto::auth_bytes_bound`] — the PR #5.5 variant
//! that folds `host_pk || client_pk || nonce` into HKDF `info` because
//! `webrtc-dtls` rejects non-empty exporter context.

use ed25519_dalek::{Signature, Signer};
use openhost_core::channel_binding_wire::{
    AUTH_CLIENT_PAYLOAD_LEN, AUTH_HOST_PAYLOAD_LEN, AUTH_NONCE_LEN, EXPORTER_SECRET_LEN,
};
use openhost_core::crypto::auth_bytes_bound;
use openhost_core::identity::{PublicKey, SigningKey};
use std::sync::Arc;
use thiserror::Error;

/// Re-export the wire-level constants so callers can
/// `use openhost_client::binding::{AUTH_NONCE_LEN, ...}` without
/// reaching into `openhost-core` directly.
pub use openhost_core::channel_binding_wire::{
    AUTH_CLIENT_PAYLOAD_LEN as AUTH_CLIENT_LEN, AUTH_HOST_PAYLOAD_LEN as AUTH_HOST_LEN,
    AUTH_NONCE_LEN as NONCE_LEN, BINDING_TIMEOUT_SECS, EXPORTER_LABEL,
    EXPORTER_SECRET_LEN as EXPORTER_LEN,
};

/// Client-side binder. Cheap to construct; holds only the client's
/// Ed25519 signing key plus the host's public key cached for the
/// `auth_bytes_bound` computation.
pub struct ClientBinder {
    identity: Arc<SigningKey>,
    client_pk_bytes: [u8; 32],
    host_pk_bytes: [u8; 32],
}

impl ClientBinder {
    /// Build a binder that signs with `identity` and verifies the
    /// daemon's response against `host_pk`.
    #[must_use]
    pub fn new(identity: Arc<SigningKey>, host_pk: PublicKey) -> Self {
        let client_pk_bytes = identity.public_key().to_bytes();
        let host_pk_bytes = host_pk.to_bytes();
        Self {
            identity,
            client_pk_bytes,
            host_pk_bytes,
        }
    }

    /// Produce the `AuthClient` payload: 32-byte `client_pk` ||
    /// 64-byte signature over `auth_bytes`. The caller supplies the
    /// DTLS exporter secret extracted from its `RTCDtlsTransport`.
    pub fn sign_auth_client(
        &self,
        exporter_secret: &[u8],
        nonce: &[u8; AUTH_NONCE_LEN],
    ) -> Result<Vec<u8>, ClientBindingError> {
        let auth = derive_auth(
            exporter_secret,
            &self.host_pk_bytes,
            &self.client_pk_bytes,
            nonce,
        )?;
        let signature = self.identity.as_dalek().sign(&auth);
        let mut payload = Vec::with_capacity(AUTH_CLIENT_PAYLOAD_LEN);
        payload.extend_from_slice(&self.client_pk_bytes);
        payload.extend_from_slice(&signature.to_bytes());
        Ok(payload)
    }

    /// Verify the `AuthHost` payload (64-byte signature) against the
    /// same exporter-derived `auth_bytes` using the host's public key.
    pub fn verify_auth_host(
        &self,
        exporter_secret: &[u8],
        nonce: &[u8; AUTH_NONCE_LEN],
        payload: &[u8],
    ) -> Result<(), ClientBindingError> {
        if payload.len() != AUTH_HOST_PAYLOAD_LEN {
            return Err(ClientBindingError::MalformedAuthHost(payload.len()));
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(payload);
        let auth = derive_auth(
            exporter_secret,
            &self.host_pk_bytes,
            &self.client_pk_bytes,
            nonce,
        )?;

        let host_pk = PublicKey::from_bytes(&self.host_pk_bytes)
            .map_err(|_| ClientBindingError::MalformedHostPk)?;
        let signature = Signature::from_bytes(&sig_bytes);
        host_pk
            .as_dalek()
            .verify_strict(&auth, &signature)
            .map_err(|_| ClientBindingError::VerifyFailed)
    }

    /// The client's own public key bytes.
    #[must_use]
    pub fn client_pk_bytes(&self) -> &[u8; 32] {
        &self.client_pk_bytes
    }
}

/// Why the client-side binding step failed.
#[derive(Debug, Error)]
pub enum ClientBindingError {
    /// `RTCDtlsTransport::export_keying_material` returned an error —
    /// typically "no live DTLS connection" or an internal exporter
    /// failure.
    #[error("DTLS exporter failed: {0}")]
    Exporter(String),

    /// The exporter returned the wrong number of bytes.
    #[error("DTLS exporter returned {0} bytes, expected {EXPORTER_SECRET_LEN}")]
    ExporterLength(usize),

    /// Core-level HKDF failure. Unreachable in practice at the 32-byte
    /// output length; retained for honest surfacing.
    #[error("auth_bytes derivation failed: {0}")]
    Core(#[from] openhost_core::Error),

    /// `AuthHost` payload is not 64 bytes.
    #[error("AuthHost payload is {0} bytes, expected {AUTH_HOST_PAYLOAD_LEN}")]
    MalformedAuthHost(usize),

    /// Cached host pubkey didn't round-trip through `from_bytes` — this
    /// is defensive: `ClientBinder::new` accepts a validated
    /// `PublicKey`, so the stored bytes should always re-parse.
    #[error("host_pk bytes failed to re-parse as a canonical Ed25519 point")]
    MalformedHostPk,

    /// Signature did not verify against the daemon's advertised host
    /// pubkey and the exporter-derived `auth_bytes`. Either the daemon
    /// doesn't hold the private key, or the TLS exporter secrets
    /// differ — both cases mean RFC 8844 has fired and the channel
    /// MUST be torn down.
    #[error("host signature failed to verify against host_pk")]
    VerifyFailed,

    /// Daemon took longer than the configured budget to respond.
    #[error("channel binding did not complete within {0} s")]
    Timeout(u64),

    /// An unexpected frame type arrived during binding.
    #[error("unexpected frame type 0x{0:02x} during channel binding")]
    UnexpectedFrame(u8),
}

fn derive_auth(
    exporter_secret: &[u8],
    host_pk: &[u8; 32],
    client_pk: &[u8; 32],
    nonce: &[u8; AUTH_NONCE_LEN],
) -> Result<[u8; 32], ClientBindingError> {
    match auth_bytes_bound(exporter_secret, host_pk, client_pk, nonce) {
        Ok(auth) => Ok(auth),
        Err(openhost_core::Error::BufferTooSmall { have, .. }) => {
            Err(ClientBindingError::ExporterLength(have))
        }
        Err(other) => Err(ClientBindingError::Core(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::identity::SigningKey;

    const EXPORTER: [u8; 32] = [0x33; 32];
    const NONCE: [u8; 32] = [0x44; 32];

    fn make_binder() -> (SigningKey, SigningKey, ClientBinder) {
        let host_sk = SigningKey::from_bytes(&[0x11; 32]);
        let client_sk = SigningKey::from_bytes(&[0x22; 32]);
        let binder = ClientBinder::new(
            Arc::new(SigningKey::from_bytes(&[0x22; 32])),
            host_sk.public_key(),
        );
        (host_sk, client_sk, binder)
    }

    #[test]
    fn sign_auth_client_roundtrip_against_daemon_binder() {
        use ed25519_dalek::Signature;

        let (host_sk, _client_sk, binder) = make_binder();
        let payload = binder.sign_auth_client(&EXPORTER, &NONCE).unwrap();
        assert_eq!(payload.len(), AUTH_CLIENT_PAYLOAD_LEN);

        // Verify the AuthClient signature by hand — mirrors what
        // `openhost-daemon::channel_binding::ChannelBinder::verify_client_sig`
        // does.
        let claimed_pk_bytes: [u8; 32] = payload[..32].try_into().unwrap();
        assert_eq!(claimed_pk_bytes, *binder.client_pk_bytes());
        let sig_bytes: [u8; 64] = payload[32..].try_into().unwrap();

        let auth = auth_bytes_bound(
            &EXPORTER,
            &host_sk.public_key().to_bytes(),
            &claimed_pk_bytes,
            &NONCE,
        )
        .unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        let client_pk = openhost_core::identity::PublicKey::from_bytes(&claimed_pk_bytes).unwrap();
        client_pk
            .as_dalek()
            .verify_strict(&auth, &signature)
            .unwrap();
    }

    #[test]
    fn verify_auth_host_accepts_good_signature() {
        let (host_sk, _client_sk, binder) = make_binder();

        // Build what the daemon would send: sign `auth_bytes` with
        // host's Ed25519 identity.
        let auth = auth_bytes_bound(
            &EXPORTER,
            &host_sk.public_key().to_bytes(),
            binder.client_pk_bytes(),
            &NONCE,
        )
        .unwrap();
        let sig = host_sk.as_dalek().sign(&auth);

        binder
            .verify_auth_host(&EXPORTER, &NONCE, &sig.to_bytes())
            .unwrap();
    }

    #[test]
    fn verify_auth_host_rejects_tampered_sig() {
        let (host_sk, _client_sk, binder) = make_binder();
        let auth = auth_bytes_bound(
            &EXPORTER,
            &host_sk.public_key().to_bytes(),
            binder.client_pk_bytes(),
            &NONCE,
        )
        .unwrap();
        let mut sig_bytes = host_sk.as_dalek().sign(&auth).to_bytes();
        sig_bytes[0] ^= 0x01;
        let err = binder
            .verify_auth_host(&EXPORTER, &NONCE, &sig_bytes)
            .unwrap_err();
        assert!(matches!(err, ClientBindingError::VerifyFailed));
    }

    #[test]
    fn verify_auth_host_rejects_wrong_length() {
        let (_host_sk, _client_sk, binder) = make_binder();
        let err = binder
            .verify_auth_host(&EXPORTER, &NONCE, &[0u8; 63])
            .unwrap_err();
        assert!(matches!(err, ClientBindingError::MalformedAuthHost(63)));
    }

    #[test]
    fn sign_auth_client_rejects_wrong_exporter_length() {
        let (_host_sk, _client_sk, binder) = make_binder();
        let err = binder.sign_auth_client(&[0u8; 31], &NONCE).unwrap_err();
        assert!(matches!(err, ClientBindingError::ExporterLength(31)));
    }
}
