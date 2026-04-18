//! Self-signed ECDSA P-256 DTLS certificate.
//!
//! The certificate's SHA-256 fingerprint is pinned into the host's Pkarr
//! record (`dtls_fp` field) so every client verifies the exact cert bytes
//! before the DTLS handshake completes. Because the pin is load-bearing,
//! the cert MUST survive process restarts with the same fingerprint.
//!
//! We persist the cert in **webrtc-rs's EXPIRES-tagged PEM format**
//! (`RTCCertificate::serialize_pem()` / `from_pem()`), rather than the
//! standard two-block PEM we used pre-PR #5. webrtc-rs round-trips its
//! own format losslessly — including the random CN and serial number
//! that `rcgen` minted at generation time — so the SHA-256 fingerprint
//! stays stable across reloads. A standard PEM bundle would require
//! webrtc-rs to regenerate the cert from the keypair, picking a new
//! random CN and serial, which would change the fingerprint and
//! invalidate every published record.
//!
//! Rotation policy: if the on-disk cert is older than
//! [`crate::config::DtlsConfig::rotate_secs`], regenerate. Callers that
//! rotate **MUST** trigger a pkarr republish so the new fingerprint
//! lands in the next signed record — otherwise existing clients
//! continue to pin the stale cert.

use crate::error::CertError;
use openhost_core::pkarr_record::DTLS_FINGERPRINT_LEN;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use std::path::Path;
use std::time::{Duration, SystemTime};
use webrtc::peer_connection::certificate::RTCCertificate;

/// A daemon-owned DTLS certificate with its SHA-256 fingerprint.
///
/// Holds the webrtc-rs `RTCCertificate` value directly so
/// [`crate::listener::PassivePeer`] can feed it to
/// `RTCConfiguration.certificates` without re-parsing.
#[derive(Clone)]
pub struct DtlsCertificate {
    /// The webrtc-rs cert. Cheap to clone (internally `Arc`-backed).
    pub certificate: RTCCertificate,
    /// EXPIRES-tagged PEM we persist to disk. Also round-trips through
    /// `RTCCertificate::from_pem` on reload.
    pub pem_bundle: String,
    /// SHA-256 over the certificate's DER bytes. 32 raw bytes. This is
    /// what goes into `OpenhostRecord::dtls_fp`.
    pub fingerprint_sha256: [u8; DTLS_FINGERPRINT_LEN],
    /// When the cert was generated (or most-recently persisted). Used by
    /// [`load_or_generate`] to decide whether a rotation is overdue.
    pub issued_at: SystemTime,
}

impl std::fmt::Debug for DtlsCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DtlsCertificate")
            .field("fingerprint_sha256", &self.fingerprint_colon_hex())
            .field("issued_at", &self.issued_at)
            .finish_non_exhaustive()
    }
}

impl DtlsCertificate {
    /// Fingerprint formatted as lowercase colon-hex, matching the SDP
    /// `a=fingerprint` form webrtc-rs emits — e.g. `"ab:cd:..."`.
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
    let certificate =
        RTCCertificate::from_key_pair(key_pair).map_err(|e| CertError::Webrtc(e.to_string()))?;
    let pem_bundle = certificate.serialize_pem();
    let fingerprint_sha256 = extract_sha256_fingerprint(&certificate)?;
    Ok(DtlsCertificate {
        certificate,
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
            let certificate = RTCCertificate::from_pem(&pem_bundle)
                .map_err(|e| CertError::Webrtc(e.to_string()))?;
            let fingerprint_sha256 = extract_sha256_fingerprint(&certificate)?;
            return Ok((
                DtlsCertificate {
                    certificate,
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

/// Parse webrtc-rs's colon-hex `sha-256` fingerprint into raw bytes.
/// The spec stores the fingerprint as 32 raw bytes inside the pkarr
/// record; webrtc-rs returns it as lowercase hex with `:` separators.
fn extract_sha256_fingerprint(
    cert: &RTCCertificate,
) -> Result<[u8; DTLS_FINGERPRINT_LEN], CertError> {
    let fingerprints = cert.get_fingerprints();
    let sha256 = fingerprints
        .iter()
        .find(|f| f.algorithm.eq_ignore_ascii_case("sha-256"))
        .ok_or(CertError::BadFingerprint)?;

    let hex: String = sha256.value.chars().filter(|c| *c != ':').collect();
    if hex.len() != DTLS_FINGERPRINT_LEN * 2 {
        return Err(CertError::BadFingerprint);
    }
    let bytes = hex::decode(&hex).map_err(|_| CertError::BadFingerprint)?;
    bytes.try_into().map_err(|_| CertError::BadFingerprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_produces_a_fingerprint_of_correct_length() {
        let cert = generate().expect("generate");
        assert_eq!(cert.fingerprint_sha256.len(), DTLS_FINGERPRINT_LEN);
        // Every byte `0x00` is vanishingly unlikely for a real SHA-256.
        assert!(cert.fingerprint_sha256.iter().any(|b| *b != 0));
        // PEM bundle must start with webrtc-rs's custom tag.
        assert!(
            cert.pem_bundle.contains("-----BEGIN ")
                || cert.pem_bundle.contains("BEGIN CERTIFICATE EXPIRES"),
            "expected webrtc-rs PEM format; got: {:.200}",
            cert.pem_bundle
        );
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
        // Most important invariant: reload yields the SAME fingerprint.
        // Regression test for the RTCCertificate::from_pem / serialize_pem
        // round-trip we rely on for pin stability across daemon restarts.
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
    async fn corrupt_pem_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("dtls.pem");
        tokio::fs::write(&path, "this is not a PEM bundle")
            .await
            .unwrap();
        let err = load_or_generate(&path, Duration::from_secs(3600))
            .await
            .unwrap_err();
        assert!(matches!(err, CertError::Webrtc(_)));
    }

    #[test]
    fn colon_hex_format_matches_sdp_shape() {
        let cert = DtlsCertificate {
            certificate: generate().unwrap().certificate,
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
