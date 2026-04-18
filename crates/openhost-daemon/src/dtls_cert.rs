//! Self-signed ECDSA P-256 DTLS certificate.
//!
//! The certificate's SHA-256 fingerprint is pinned into the host's Pkarr
//! record (`dtls_fp` field) so every client verifies the exact cert bytes
//! before the DTLS handshake completes. Because the pin is load-bearing,
//! **we persist the cert PEM verbatim** — regenerating the cert from the
//! same keypair would produce a different serial number and therefore a
//! different fingerprint, which would invalidate every published record
//! until the next republish.
//!
//! This module does **not** depend on the `webrtc` crate; that enters the
//! tree in PR #5. The PEM bundle we write here is the exact format PR #5
//! will hand off to `webrtc::peer_connection::certificate::RTCCertificate`
//! (key algorithm: `PKCS_ECDSA_P256_SHA256` — the only type webrtc-rs
//! v0.17.x accepts via `from_key_pair` that is also browser-compatible).
//!
//! Rotation policy: if the cert on disk is older than
//! [`crate::config::DtlsConfig::rotate_secs`], regenerate. Callers that
//! rotate **MUST** trigger a pkarr republish so the new fingerprint lands
//! in the next signed record — otherwise existing clients continue to
//! pin to the stale cert.

use crate::error::CertError;
use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine;
use openhost_core::pkarr_record::DTLS_FINGERPRINT_LEN;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Subject alt name on the self-signed DTLS certificate. DTLS-SRTP doesn't
/// care about DN/SAN content (fingerprint auth supersedes it), so the
/// value is cosmetic.
pub const CERT_SAN: &str = "openhost.local";

/// A daemon-owned DTLS certificate with its SHA-256 fingerprint.
#[derive(Debug, Clone)]
pub struct DtlsCertificate {
    /// Concatenated PEM: `-----BEGIN PRIVATE KEY-----` block followed by
    /// `-----BEGIN CERTIFICATE-----`. Exactly what we persist to disk and
    /// what PR #5 will hand to webrtc-rs.
    pub pem_bundle: String,
    /// SHA-256 over the certificate's DER bytes. 32 raw bytes. This is
    /// what goes into `OpenhostRecord::dtls_fp`.
    pub fingerprint_sha256: [u8; DTLS_FINGERPRINT_LEN],
    /// When the cert was generated (or most-recently persisted). Used by
    /// [`load_or_generate`] to decide whether a rotation is overdue.
    pub issued_at: SystemTime,
}

impl DtlsCertificate {
    /// Fingerprint formatted as lowercase colon-hex, matching the SDP
    /// `a=fingerprint` form webrtc-rs emits — e.g. `"ab:cd:..."`. Convenient
    /// for logging; not used by the wire layer (which carries raw bytes).
    pub fn fingerprint_colon_hex(&self) -> String {
        self.fingerprint_sha256
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Generate a fresh self-signed ECDSA P-256 cert. No I/O.
pub fn generate() -> Result<DtlsCertificate, CertError> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let params = CertificateParams::new(vec![CERT_SAN.to_string()])?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let pem_bundle = format!("{key_pem}{cert_pem}");

    let der = cert.der();
    let fingerprint_sha256: [u8; DTLS_FINGERPRINT_LEN] = Sha256::digest(der.as_ref()).into();

    Ok(DtlsCertificate {
        pem_bundle,
        fingerprint_sha256,
        issued_at: SystemTime::now(),
    })
}

/// Load the cert persisted at `path` if it exists and is within the
/// rotation window; otherwise generate a fresh one, persist it, and
/// return that.
///
/// Returns `(cert, was_rotated)` so the caller can decide whether to
/// trigger a pkarr republish. `was_rotated == true` means the caller
/// **MUST** call `publisher.trigger()` before returning to the event loop,
/// or the published record will pin to a stale fingerprint for up to the
/// full republish interval.
pub async fn load_or_generate(
    path: &Path,
    rotate_every: Duration,
) -> Result<(DtlsCertificate, bool), CertError> {
    let existing = match tokio::fs::read_to_string(path).await {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };

    if let Some(pem_bundle) = existing {
        let mtime = tokio::fs::metadata(path).await?.modified().ok();
        let age = mtime
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .unwrap_or(Duration::from_secs(0));
        if age < rotate_every {
            let cert_der = extract_pem_der(&pem_bundle, "CERTIFICATE")?;
            // Confirm the key block is present too — the daemon doesn't use
            // it this PR, but rejecting a half-written bundle here is
            // cheaper than catching it in PR #5.
            let _ = extract_pem_der(&pem_bundle, "PRIVATE KEY")?;
            let fingerprint_sha256: [u8; DTLS_FINGERPRINT_LEN] = Sha256::digest(&cert_der).into();
            return Ok((
                DtlsCertificate {
                    pem_bundle,
                    fingerprint_sha256,
                    issued_at: mtime.unwrap_or(SystemTime::now()),
                },
                false,
            ));
        }
    }

    let cert = generate()?;
    write_pem_bundle(path, &cert.pem_bundle).await?;
    Ok((cert, true))
}

/// Regenerate the cert on disk unconditionally, returning the new one.
/// Called by `openhostd identity rotate`.
pub async fn force_rotate(path: &Path) -> Result<DtlsCertificate, CertError> {
    let cert = generate()?;
    write_pem_bundle(path, &cert.pem_bundle).await?;
    Ok(cert)
}

async fn write_pem_bundle(path: &Path, pem: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, pem).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&tmp, perms).await?;
    }
    tokio::fs::rename(&tmp, path).await
}

/// Extract a single PEM block with the given label (e.g. `"CERTIFICATE"`,
/// `"PRIVATE KEY"`) and return its DER bytes. Whitespace inside the body
/// is ignored, as per RFC 7468 §2.
fn extract_pem_der(pem: &str, label: &str) -> Result<Vec<u8>, CertError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let begin_at = pem
        .find(&begin)
        .ok_or(CertError::MissingPemBlock(static_label(label)))?;
    let body_start = begin_at + begin.len();
    let rel_end = pem[body_start..]
        .find(&end)
        .ok_or(CertError::MissingPemBlock(static_label(label)))?;
    let body = &pem[body_start..body_start + rel_end];

    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    B64_STANDARD
        .decode(&b64)
        .map_err(|_| CertError::MissingPemBlock(static_label(label)))
}

/// Convert a runtime `&str` label into a `&'static str` so it fits in the
/// [`CertError::MissingPemBlock`] payload. Only the two values we
/// actually query are mapped; anything else becomes `"unknown"`.
fn static_label(label: &str) -> &'static str {
    match label {
        "CERTIFICATE" => "CERTIFICATE",
        "PRIVATE KEY" => "PRIVATE KEY",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_produces_self_consistent_fingerprint() {
        let cert = generate().expect("generate");
        assert_eq!(cert.fingerprint_sha256.len(), DTLS_FINGERPRINT_LEN);

        // Re-derive the fingerprint from the persisted PEM and confirm
        // they match — catches any divergence between `cert.der()` and
        // what we actually write to disk.
        let der = extract_pem_der(&cert.pem_bundle, "CERTIFICATE").unwrap();
        let recomputed: [u8; DTLS_FINGERPRINT_LEN] = Sha256::digest(&der).into();
        assert_eq!(cert.fingerprint_sha256, recomputed);

        // Both PEM blocks must be present.
        extract_pem_der(&cert.pem_bundle, "PRIVATE KEY").unwrap();
    }

    #[test]
    fn generate_is_non_deterministic() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(
            a.fingerprint_sha256, b.fingerprint_sha256,
            "two generate() calls must yield different certs (different keypairs)"
        );
    }

    #[tokio::test]
    async fn load_or_generate_persists_on_miss_and_reuses_inside_window() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dtls.pem");

        let (c1, rotated1) = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(rotated1, "first call should rotate (file didn't exist)");
        assert!(path.exists());

        let (c2, rotated2) = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(!rotated2, "second call inside window should reuse");
        assert_eq!(c1.fingerprint_sha256, c2.fingerprint_sha256);
        assert_eq!(c1.pem_bundle, c2.pem_bundle);
    }

    #[tokio::test]
    async fn load_or_generate_rotates_past_window() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dtls.pem");

        let (c1, _) = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap();

        // A zero-second rotation window forces every call to rotate. This
        // is a test-only shortcut — `config::validate` rejects
        // `rotate_secs == 0`, so production code can't hit this path. Do
        // not "fix" the apparent inconsistency by adding a zero-check here.
        let (c2, rotated) = load_or_generate(&path, Duration::from_secs(0))
            .await
            .unwrap();
        assert!(rotated);
        assert_ne!(c1.fingerprint_sha256, c2.fingerprint_sha256);
    }

    #[tokio::test]
    async fn force_rotate_always_regenerates() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dtls.pem");

        let (c1, _) = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap();
        let c2 = force_rotate(&path).await.unwrap();
        assert_ne!(c1.fingerprint_sha256, c2.fingerprint_sha256);

        let persisted = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(persisted, c2.pem_bundle);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persisted_cert_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dtls.pem");
        let _ = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap();

        let meta = tokio::fs::metadata(&path).await.unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:#o}");
    }

    #[tokio::test]
    async fn truncated_bundle_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dtls.pem");
        // Write a key-only PEM: missing the CERTIFICATE block entirely.
        tokio::fs::write(
            &path,
            "-----BEGIN PRIVATE KEY-----\naGVsbG8K\n-----END PRIVATE KEY-----\n",
        )
        .await
        .unwrap();

        let err = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap_err();
        assert!(matches!(err, CertError::MissingPemBlock("CERTIFICATE")));
    }

    #[test]
    fn colon_hex_format_matches_sdp_shape() {
        let cert = DtlsCertificate {
            pem_bundle: String::new(),
            fingerprint_sha256: [0xab; DTLS_FINGERPRINT_LEN],
            issued_at: SystemTime::now(),
        };
        let s = cert.fingerprint_colon_hex();
        // 32 bytes × "ab" + 31 colons = 95 chars
        assert_eq!(s.len(), 32 * 2 + 31);
        assert!(s.starts_with("ab:ab:"));
    }
}
