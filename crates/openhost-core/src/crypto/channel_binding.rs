//! Channel-binding construction for the post-DTLS handshake (spec §8.3 step 9).
//!
//! The handshake obtains an RFC 5705 TLS exporter secret from the DTLS 1.3 transport,
//! binding it to both participant public keys and a server-chosen nonce so a man-in-the-
//! middle with a different TLS session cannot present a valid authentication signature
//! (the RFC 8844 mitigation).
//!
//! openhost specifies (spec text):
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
//! TODO(v0.1 freeze / spec): webrtc-dtls v0.17.x rejects non-empty exporter
//! `context` (`ContextUnsupported`). Until we land a fix in the vendored
//! DTLS crate, the reference implementation folds the binding bytes into
//! HKDF `info` instead via [`auth_bytes_bound`]. Functionally equivalent
//! (exporter_secret is session-unique; HKDF input still unambiguously
//! commits to host_pk || client_pk || nonce) but the spec text has to be
//! updated to reflect the layering change.
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

/// Derive `auth_bytes` with binding bytes folded into HKDF `info`.
///
/// Equivalent to [`auth_bytes`] except `info = "openhost-auth-v1" ||
/// host_pk || client_pk || nonce`. Used in PR #5.5 because the vendored
/// webrtc-dtls implementation rejects a non-empty exporter `context`
/// parameter (`ContextUnsupported`). Folding the binding into HKDF keeps
/// the security property (a MITM with a different TLS session cannot
/// forge the signature — the exporter secret still differs per session)
/// while sidestepping the DTLS-crate limitation.
///
/// # Errors
///
/// Returns [`Error::BufferTooSmall`] if the exporter secret has the wrong length.
pub fn auth_bytes_bound(
    tls_exporter_secret: &[u8],
    host_public_key: &[u8; 32],
    client_public_key: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; AUTH_BYTES_LEN]> {
    if tls_exporter_secret.len() != AUTH_BYTES_LEN {
        return Err(Error::BufferTooSmall {
            have: tls_exporter_secret.len(),
            need: AUTH_BYTES_LEN,
        });
    }
    let mut info = [0u8; 16 + 96];
    info[..16].copy_from_slice(AUTH_HKDF_INFO);
    info[16..48].copy_from_slice(host_public_key);
    info[48..80].copy_from_slice(client_public_key);
    info[80..112].copy_from_slice(nonce);
    let hk = Hkdf::<Sha256>::new(Some(AUTH_HKDF_SALT), tls_exporter_secret);
    let mut out = [0u8; AUTH_BYTES_LEN];
    hk.expand(&info, &mut out)
        .expect("32-byte HKDF expansion always fits");
    Ok(out)
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

    #[test]
    fn auth_bytes_bound_deterministic() {
        let secret = [7u8; 32];
        let host = [0xAAu8; 32];
        let client = [0xBBu8; 32];
        let nonce = [0xCCu8; 32];
        let a = auth_bytes_bound(&secret, &host, &client, &nonce).unwrap();
        let b = auth_bytes_bound(&secret, &host, &client, &nonce).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn auth_bytes_bound_changes_with_each_input() {
        let secret = [7u8; 32];
        let host = [0xAAu8; 32];
        let client = [0xBBu8; 32];
        let nonce = [0xCCu8; 32];
        let base = auth_bytes_bound(&secret, &host, &client, &nonce).unwrap();
        assert_ne!(
            base,
            auth_bytes_bound(&[8u8; 32], &host, &client, &nonce).unwrap(),
            "secret must influence output"
        );
        assert_ne!(
            base,
            auth_bytes_bound(&secret, &[0u8; 32], &client, &nonce).unwrap(),
            "host_pk must influence output"
        );
        assert_ne!(
            base,
            auth_bytes_bound(&secret, &host, &[0u8; 32], &nonce).unwrap(),
            "client_pk must influence output"
        );
        assert_ne!(
            base,
            auth_bytes_bound(&secret, &host, &client, &[0u8; 32]).unwrap(),
            "nonce must influence output"
        );
    }

    #[test]
    fn auth_bytes_bound_rejects_wrong_secret_length() {
        let host = [0xAAu8; 32];
        let client = [0xBBu8; 32];
        let nonce = [0xCCu8; 32];
        assert!(auth_bytes_bound(&[0u8; 31], &host, &client, &nonce).is_err());
        assert!(auth_bytes_bound(&[0u8; 33], &host, &client, &nonce).is_err());
    }

    #[test]
    fn auth_bytes_bound_differs_from_plain_auth_bytes() {
        // Folding binding into HKDF info must change the output vs the
        // context-less `auth_bytes` — otherwise the binding would be
        // cryptographically invisible.
        let secret = [7u8; 32];
        let plain = auth_bytes(&secret).unwrap();
        let bound = auth_bytes_bound(&secret, &[0xAAu8; 32], &[0xBBu8; 32], &[0xCCu8; 32]).unwrap();
        assert_ne!(plain, bound);
    }
}
