//! Channel-binding construction for the post-DTLS handshake (spec §8.3 step 9).
//!
//! The handshake obtains an RFC 5705 TLS exporter secret from the DTLS 1.3 transport,
//! binding it to both participant public keys and a server-chosen nonce so a man-in-the-
//! middle with a different TLS session cannot present a valid authentication signature
//! (the RFC 8844 mitigation).
//!
//! openhost specifies:
//!
//! ```text
//! tls_exporter_secret = DTLS_exporter(
//!                         label   = "EXPORTER-openhost-auth-v1",
//!                         context = host_pk || client_pk || nonce,
//!                         length  = 32)
//!
//! auth_bytes          = HKDF-SHA256(
//!                         salt   = "openhost-auth-v1",
//!                         ikm    = tls_exporter_secret,
//!                         info   = "openhost-auth-v1",
//!                         length = 32)
//! ```
//!
//! Each party signs `auth_bytes` with its Ed25519 private key; the counterparty verifies
//! the signature against the expected pubkey obtained from the Pkarr record (for the
//! host) or from the allowlist (for the client).
//!
//! The TLS exporter secret must be derived by the caller — openhost-core does not touch
//! the DTLS layer. This module performs only the HKDF step.

use crate::{Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;

/// Length of the channel-binding authentication bytes.
pub const AUTH_BYTES_LEN: usize = 32;

/// Salt passed to HKDF when deriving `auth_bytes`.
pub const AUTH_HKDF_SALT: &[u8] = b"openhost-auth-v1";

/// Info passed to HKDF when deriving `auth_bytes`.
pub const AUTH_HKDF_INFO: &[u8] = b"openhost-auth-v1";

/// Exporter label passed to RFC 5705 when deriving the TLS exporter secret.
pub const AUTH_CONTEXT_LABEL: &[u8] = b"EXPORTER-openhost-auth-v1";

/// Derive `auth_bytes` from a TLS exporter secret.
///
/// `tls_exporter_secret` must be exactly 32 bytes — the length openhost clients and
/// daemons request from the DTLS layer. Shorter or longer inputs are rejected.
///
/// # Errors
///
/// Returns [`Error::BufferTooSmall`] if the exporter secret has the wrong length.
/// HKDF cannot otherwise fail at the requested 32-byte output length.
pub fn auth_bytes(tls_exporter_secret: &[u8]) -> Result<[u8; AUTH_BYTES_LEN]> {
    if tls_exporter_secret.len() != AUTH_BYTES_LEN {
        return Err(Error::BufferTooSmall {
            have: tls_exporter_secret.len(),
            need: AUTH_BYTES_LEN,
        });
    }
    let hk = Hkdf::<Sha256>::new(Some(AUTH_HKDF_SALT), tls_exporter_secret);
    let mut out = [0u8; AUTH_BYTES_LEN];
    hk.expand(AUTH_HKDF_INFO, &mut out)
        .expect("32-byte HKDF expansion always fits");
    Ok(out)
}

/// Build the context string a caller must hand to their TLS exporter when deriving the
/// 32-byte `tls_exporter_secret`. This is purely a helper — the actual exporter call is
/// performed by whichever DTLS implementation the platform uses.
#[must_use]
pub fn exporter_context(
    host_public_key: &[u8; 32],
    client_public_key: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; 96] {
    let mut out = [0u8; 96];
    out[0..32].copy_from_slice(host_public_key);
    out[32..64].copy_from_slice(client_public_key);
    out[64..96].copy_from_slice(nonce);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_output() {
        let secret = [7u8; 32];
        let a = auth_bytes(&secret).expect("valid length");
        let b = auth_bytes(&secret).expect("valid length");
        assert_eq!(a, b);
    }

    #[test]
    fn changes_with_exporter_secret() {
        let a = auth_bytes(&[0x11u8; 32]).expect("ok");
        let b = auth_bytes(&[0x22u8; 32]).expect("ok");
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(auth_bytes(&[0u8; 16]).is_err());
        assert!(auth_bytes(&[0u8; 64]).is_err());
        assert!(auth_bytes(&[]).is_err());
    }

    #[test]
    fn exporter_context_layout() {
        let host = [0xAAu8; 32];
        let client = [0xBBu8; 32];
        let nonce = [0xCCu8; 32];
        let ctx = exporter_context(&host, &client, &nonce);
        assert_eq!(&ctx[0..32], &host);
        assert_eq!(&ctx[32..64], &client);
        assert_eq!(&ctx[64..96], &nonce);
    }
}
