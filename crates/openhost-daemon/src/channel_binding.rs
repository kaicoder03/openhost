//! Channel-binding handshake (spec §7.1 / RFC 8844 mitigation).
//!
//! After the DTLS transport reaches `Connected`, the daemon and client
//! exchange three frames over the data channel to prove each holds the
//! Ed25519 private key associated with the published identity AND that
//! both endpoints see the same DTLS master secret (so a MITM with a
//! different TLS session cannot impersonate either side):
//!
//! ```text
//! daemon  → client  AuthNonce  (0x30)  | 32 random bytes
//! client  → daemon  AuthClient (0x31)  | 32-byte client_pk || 64-byte sig_client
//! daemon  → client  AuthHost   (0x32)  | 64-byte sig_host
//! ```
//!
//! Each side signs `auth_bytes = HKDF-SHA256(salt="openhost-auth-v1",
//! ikm=exporter_secret, info="openhost-auth-v1" || host_pk || client_pk
//! || nonce)` with its Ed25519 identity key. The verifier derives the
//! same `auth_bytes` from its own exporter and checks the signature.
//!
//! # TODO(v0.1 freeze)
//!
//! 1. Message order is **client-first**. Spec §3 step 9 reads
//!    "daemon signs first, client replies." We invert that here so PR #5.5
//!    can ship without PR #7's offer-record plumbing: without an offer
//!    record, the daemon has no source of truth for `client_pk` before
//!    the client speaks. Once PR #7 lands, the spec text and this flow
//!    should reunify.
//! 2. Binding bytes are folded into HKDF `info`, not the DTLS exporter
//!    `context`. webrtc-dtls v0.17.x returns `ContextUnsupported` for a
//!    non-empty `context`. Equivalent security (exporter secret is
//!    session-unique; HKDF still commits to `host_pk || client_pk ||
//!    nonce`) but the spec text layers it the other way.
//!
//! # What this module does NOT do
//!
//! - **Authorization.** Any syntactically valid Ed25519 keypair passes
//!   binding — PR #5.5 proves the signer holds the corresponding private
//!   key, nothing more. The allowlist lands in PR #7 and is what
//!   determines whether `client_pk` is *allowed* to connect.

use ed25519_dalek::Signature;
use openhost_core::crypto::auth_bytes_bound;
use openhost_core::identity::{PublicKey, SigningKey};
use rand_core::RngCore;
use std::sync::Arc;
use thiserror::Error;

// Wire-level constants shared with `openhost-client`'s client-side
// binder. The canonical source is `openhost-core::channel_binding_wire`;
// re-exported here to keep existing daemon imports
// (`channel_binding::AUTH_NONCE_LEN`, etc.) working unchanged.
pub use openhost_core::channel_binding_wire::{
    AUTH_CLIENT_PAYLOAD_LEN, AUTH_HOST_PAYLOAD_LEN, AUTH_NONCE_LEN, BINDING_TIMEOUT_SECS,
    EXPORTER_LABEL, EXPORTER_SECRET_LEN,
};

/// Why the channel-binding handshake failed.
#[derive(Debug, Error)]
pub enum ChannelBindingError {
    /// `RTCDtlsTransport::export_keying_material` returned an error —
    /// typically "no live DTLS connection" before the handshake completed
    /// or an internal exporter failure.
    #[error("DTLS exporter failed: {0}")]
    Exporter(String),

    /// The exporter returned the wrong number of bytes. openhost requests
    /// exactly 32 bytes; anything else signals either a misuse or a
    /// webrtc-rs regression.
    #[error("DTLS exporter returned {0} bytes, expected {EXPORTER_SECRET_LEN}")]
    ExporterLength(usize),

    /// Core-level HKDF failure. Almost always unreachable (32-byte
    /// HKDF-SHA256 expansion never runs out of entropy), but retained so
    /// the surfaced error type is honest.
    #[error("auth_bytes derivation failed: {0}")]
    Core(#[from] openhost_core::Error),

    /// `AuthClient` payload was not 96 bytes. Malformed client.
    #[error("AuthClient payload is {0} bytes, expected {AUTH_CLIENT_PAYLOAD_LEN}")]
    MalformedAuthClient(usize),

    /// Claimed `client_pk` was not a canonical Ed25519 point. Malformed
    /// client (or a RFC-8032-invalid test vector).
    #[error("client_pk is not a canonical Ed25519 point")]
    MalformedClientPk,

    /// Signature did not verify against the stated `client_pk` and
    /// derived `auth_bytes`. Either the client doesn't hold the private
    /// key, or the TLS exporter secrets differ — both failure modes must
    /// tear the channel down.
    #[error("client signature failed to verify against client_pk")]
    VerifyFailed,

    /// Client took longer than [`BINDING_TIMEOUT_SECS`] to reply.
    #[error("channel binding did not complete within {0} s")]
    Timeout(u64),

    /// An unexpected frame type arrived before `AuthClient`. The daemon
    /// MUST refuse to process REQUEST_* / WS_* frames until binding is
    /// authenticated.
    #[error("unexpected frame type 0x{0:02x} before channel binding completed")]
    UnexpectedFrameBeforeAuth(u8),
}

/// Per-daemon helper that wraps the identity key plus channel-binding
/// operations. Hold behind an `Arc` to share across data channels; the
/// struct itself is two words (one `Arc` + a 32-byte array) and carries
/// no runtime state.
pub struct ChannelBinder {
    identity: Arc<SigningKey>,
    host_pk_bytes: [u8; 32],
}

impl ChannelBinder {
    /// Build a binder that signs with `identity`'s private key.
    #[must_use]
    pub fn new(identity: Arc<SigningKey>) -> Self {
        let host_pk_bytes = identity.public_key().to_bytes();
        Self {
            identity,
            host_pk_bytes,
        }
    }

    /// The host's public key bytes (cached from the identity).
    #[must_use]
    pub fn host_pk_bytes(&self) -> &[u8; 32] {
        &self.host_pk_bytes
    }

    /// Generate a fresh 32-byte nonce from the OS CSPRNG.
    #[must_use]
    pub fn fresh_nonce() -> [u8; AUTH_NONCE_LEN] {
        let mut nonce = [0u8; AUTH_NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Verify the client's `AuthClient` payload: 32-byte claimed
    /// `client_pk` || 64-byte signature over `auth_bytes`. The caller
    /// supplies the already-extracted DTLS exporter secret so this module
    /// stays unit-testable without a live WebRTC stack.
    ///
    /// Returns the validated `client_pk` on success; the caller should
    /// persist it to include in the subsequent `AuthHost` signature.
    pub fn verify_client_sig(
        &self,
        exporter_secret: &[u8],
        nonce: &[u8; AUTH_NONCE_LEN],
        payload: &[u8],
    ) -> Result<PublicKey, ChannelBindingError> {
        if payload.len() != AUTH_CLIENT_PAYLOAD_LEN {
            return Err(ChannelBindingError::MalformedAuthClient(payload.len()));
        }
        let mut client_pk_bytes = [0u8; 32];
        client_pk_bytes.copy_from_slice(&payload[..32]);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&payload[32..]);

        let client_pk = PublicKey::from_bytes(&client_pk_bytes)
            .map_err(|_| ChannelBindingError::MalformedClientPk)?;

        let auth = derive_auth(
            exporter_secret,
            &self.host_pk_bytes,
            &client_pk_bytes,
            nonce,
        )?;

        let signature = Signature::from_bytes(&sig_bytes);
        client_pk
            .as_dalek()
            .verify_strict(&auth, &signature)
            .map_err(|_| ChannelBindingError::VerifyFailed)?;

        Ok(client_pk)
    }

    /// Produce the `AuthHost` payload: 64-byte signature over
    /// `auth_bytes` with the host's identity key. Caller supplies the
    /// same exporter secret + nonce used for `verify_client_sig`.
    pub fn sign_host(
        &self,
        exporter_secret: &[u8],
        nonce: &[u8; AUTH_NONCE_LEN],
        client_pk: &PublicKey,
    ) -> Result<[u8; AUTH_HOST_PAYLOAD_LEN], ChannelBindingError> {
        let client_pk_bytes = client_pk.to_bytes();
        let auth = derive_auth(
            exporter_secret,
            &self.host_pk_bytes,
            &client_pk_bytes,
            nonce,
        )?;
        let signature = self.identity.sign(&auth);
        Ok(signature.to_bytes())
    }
}

fn derive_auth(
    exporter_secret: &[u8],
    host_pk: &[u8; 32],
    client_pk: &[u8; 32],
    nonce: &[u8; AUTH_NONCE_LEN],
) -> Result<[u8; 32], ChannelBindingError> {
    match auth_bytes_bound(exporter_secret, host_pk, client_pk, nonce) {
        Ok(auth) => Ok(auth),
        Err(openhost_core::Error::BufferTooSmall { have, .. }) => {
            Err(ChannelBindingError::ExporterLength(have))
        }
        Err(other) => Err(ChannelBindingError::Core(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use openhost_core::crypto::auth_bytes_bound;

    const HOST_SEED: [u8; 32] = [0x11; 32];
    const CLIENT_SEED: [u8; 32] = [0x22; 32];
    const EXPORTER_SECRET: [u8; 32] = [0x33; 32];
    const NONCE: [u8; 32] = [0x44; 32];

    fn host_binder() -> ChannelBinder {
        ChannelBinder::new(Arc::new(SigningKey::from_bytes(&HOST_SEED)))
    }

    fn signed_auth_client_payload(
        host_pk: &[u8; 32],
        client_sk: &SigningKey,
        exporter: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let client_pk = client_sk.public_key().to_bytes();
        let auth = auth_bytes_bound(exporter, host_pk, &client_pk, nonce).unwrap();
        let sig = client_sk.as_dalek().sign(&auth);
        let mut out = Vec::with_capacity(AUTH_CLIENT_PAYLOAD_LEN);
        out.extend_from_slice(&client_pk);
        out.extend_from_slice(&sig.to_bytes());
        out
    }

    #[test]
    fn exporter_label_matches_core_auth_context() {
        // The daemon hands `EXPORTER_LABEL` (a `&str`) to webrtc-rs, while
        // openhost-core's test vectors reference the same constant as
        // `AUTH_CONTEXT_LABEL` bytes. If they ever drift, the bytes
        // signed on the daemon side would no longer match what a
        // spec-conformant client expects.
        assert_eq!(
            EXPORTER_LABEL.as_bytes(),
            openhost_core::crypto::AUTH_CONTEXT_LABEL
        );
    }

    #[test]
    fn fresh_nonce_is_non_zero_and_varies() {
        let a = ChannelBinder::fresh_nonce();
        let b = ChannelBinder::fresh_nonce();
        assert_eq!(a.len(), AUTH_NONCE_LEN);
        assert_ne!(a, [0u8; AUTH_NONCE_LEN], "nonce must not be all-zeros");
        assert_ne!(a, b, "two consecutive nonces must differ");
    }

    #[test]
    fn verify_client_sig_happy_path() {
        let binder = host_binder();
        let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
        let payload = signed_auth_client_payload(
            binder.host_pk_bytes(),
            &client_sk,
            &EXPORTER_SECRET,
            &NONCE,
        );
        let got = binder
            .verify_client_sig(&EXPORTER_SECRET, &NONCE, &payload)
            .expect("valid signature verifies");
        assert_eq!(got.to_bytes(), client_sk.public_key().to_bytes());
    }

    #[test]
    fn verify_client_sig_rejects_tampered_signature() {
        let binder = host_binder();
        let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
        let mut payload = signed_auth_client_payload(
            binder.host_pk_bytes(),
            &client_sk,
            &EXPORTER_SECRET,
            &NONCE,
        );
        // Flip one bit in the signature half.
        payload[64] ^= 0x01;
        assert!(matches!(
            binder.verify_client_sig(&EXPORTER_SECRET, &NONCE, &payload),
            Err(ChannelBindingError::VerifyFailed)
        ));
    }

    #[test]
    fn verify_client_sig_rejects_wrong_client_pk() {
        // Signature was computed by client A; payload carries client_pk = B.
        let binder = host_binder();
        let client_a = SigningKey::from_bytes(&CLIENT_SEED);
        let client_b = SigningKey::from_bytes(&[0x55; 32]);

        // Derive auth_bytes for (host, B, nonce) — the bytes the verifier
        // will compute from the stated client_pk.
        let auth_for_b = auth_bytes_bound(
            &EXPORTER_SECRET,
            binder.host_pk_bytes(),
            &client_b.public_key().to_bytes(),
            &NONCE,
        )
        .unwrap();
        // But sign those bytes with A's key.
        let sig = client_a.as_dalek().sign(&auth_for_b);

        let mut payload = Vec::with_capacity(AUTH_CLIENT_PAYLOAD_LEN);
        payload.extend_from_slice(&client_b.public_key().to_bytes());
        payload.extend_from_slice(&sig.to_bytes());

        assert!(matches!(
            binder.verify_client_sig(&EXPORTER_SECRET, &NONCE, &payload),
            Err(ChannelBindingError::VerifyFailed)
        ));
    }

    #[test]
    fn verify_client_sig_rejects_malformed_length() {
        let binder = host_binder();
        assert!(matches!(
            binder.verify_client_sig(&EXPORTER_SECRET, &NONCE, &[0u8; 95]),
            Err(ChannelBindingError::MalformedAuthClient(95))
        ));
        assert!(matches!(
            binder.verify_client_sig(&EXPORTER_SECRET, &NONCE, &[0u8; 97]),
            Err(ChannelBindingError::MalformedAuthClient(97))
        ));
        assert!(matches!(
            binder.verify_client_sig(&EXPORTER_SECRET, &NONCE, &[]),
            Err(ChannelBindingError::MalformedAuthClient(0))
        ));
    }

    #[test]
    fn sign_host_produces_verifiable_signature() {
        let binder = host_binder();
        let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
        let client_pk = client_sk.public_key();
        let sig_bytes = binder
            .sign_host(&EXPORTER_SECRET, &NONCE, &client_pk)
            .expect("sign");

        let host_pk = binder.identity.public_key();
        let auth = auth_bytes_bound(
            &EXPORTER_SECRET,
            binder.host_pk_bytes(),
            &client_pk.to_bytes(),
            &NONCE,
        )
        .unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        host_pk
            .as_dalek()
            .verify_strict(&auth, &sig)
            .expect("host signature verifies");
    }

    #[test]
    fn exporter_length_mismatch_surfaces_as_exporter_length() {
        let binder = host_binder();
        let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
        let payload = signed_auth_client_payload(
            binder.host_pk_bytes(),
            &client_sk,
            &EXPORTER_SECRET,
            &NONCE,
        );
        // Wrong length exporter secret.
        assert!(matches!(
            binder.verify_client_sig(&[0u8; 31], &NONCE, &payload),
            Err(ChannelBindingError::ExporterLength(31))
        ));
    }
}
