//! `oh recv` — parse a pairing code, dial the sender, stream the
//! file to disk.
//!
//! Flow:
//! 1. Parse the user-supplied code (BIP-39 words OR `oh+pair://`
//!    URI) and derive [`Roles`].
//! 2. Build an [`openhost_client::Dialer`] with the receiver's
//!    ephemeral signing key and the sender's public key (as the
//!    `oh://` URL to dial).
//! 3. `dial()` → WebRTC + DTLS + channel-binding handshake.
//! 4. `session.request("GET /")` → pull the full response back in
//!    one round-trip.
//! 5. Write the body to `<out>`, using `Content-Disposition` as a
//!    fallback when `--out` wasn't supplied. Verify sha256 if the
//!    sender advertised it.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use openhost_client::{Dialer, DialerConfig, OpenhostUrl, SigningKey};
use openhost_peer::{PairingCode, Roles};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// How long we're willing to poll the sender's zone for its host
/// record before giving up. Longer than the default 30 s so the
/// sender has ample time to publish after the user first sees the
/// pairing code (we pause 5 s before printing it).
const RECV_DIAL_TIMEOUT: Duration = Duration::from_secs(120);

/// `oh recv` entry point.
///
/// * `code_str` — what the user pasted; either 12 BIP-39 words or a
///   `oh+pair://` URI.
/// * `out` — explicit output path from `--out`, or `None` to derive
///   a filename from the server's `Content-Disposition` header (or
///   fall back to `openhost-transfer.bin` in the CWD).
pub async fn run(code_str: &str, out: Option<PathBuf>) -> Result<()> {
    let code = PairingCode::parse(code_str).map_err(|e| anyhow!("parse pairing code: {e}"))?;
    let roles = Roles::derive(&code);

    let sender_pk =
        openhost_core::identity::PublicKey::from_bytes(&roles.sender().verifying_key().to_bytes())
            .map_err(|e| anyhow!("sender pubkey from roles: {e}"))?;
    let sender_pk_zbase32 = sender_pk.to_zbase32();
    let host_url = OpenhostUrl::parse(&format!("oh://{sender_pk_zbase32}/"))
        .map_err(|e| anyhow!("internal: generated oh:// URL did not parse: {e}"))?;

    let identity = SigningKey::from_bytes(roles.receiver_seed());

    eprintln!(
        "oh recv: dialing oh://{}/ (this can take up to {}s)…",
        sender_pk_zbase32,
        RECV_DIAL_TIMEOUT.as_secs()
    );

    let mut dialer = Dialer::builder()
        .identity(Arc::new(identity))
        .host_url(host_url)
        .relays(crate::send::default_peer_relays())
        .config(DialerConfig {
            dial_timeout: RECV_DIAL_TIMEOUT,
            // 3 s poll cadence keeps us inside the relays' per-IP
            // rate limits. Trades ~3 s of latency for reliability.
            answer_poll_interval: Duration::from_secs(3),
            webrtc_connect_timeout: Duration::from_secs(20),
            binding_timeout: Duration::from_secs(10),
        })
        .build()
        .map_err(|e| anyhow!("build dialer: {e}"))?;

    let session = dialer.dial().await.map_err(|e| anyhow!("dial: {e}"))?;

    eprintln!("oh recv: connected. Requesting file…");

    let req_head = build_get_request_head();
    let resp = session
        .request(req_head.as_bytes(), Bytes::new())
        .await
        .map_err(|e| anyhow!("HTTP round-trip: {e}"))?;

    let (status, headers) = parse_http_head(&resp.head_bytes)?;
    if !(200..300).contains(&status) {
        anyhow::bail!("sender responded with HTTP {status}");
    }

    let filename_hint = filename_from_content_disposition(&headers);
    let expected_sha = sha256_header(&headers);

    let out_path = match out {
        Some(p) => p,
        None => PathBuf::from(filename_hint.as_deref().unwrap_or("openhost-transfer.bin")),
    };

    tokio::fs::write(&out_path, &resp.body)
        .await
        .with_context(|| format!("write {}", out_path.display()))?;

    if let Some(want) = expected_sha.as_deref() {
        let got = hex::encode({
            let mut h = Sha256::new();
            h.update(&resp.body);
            h.finalize()
        });
        if got.eq_ignore_ascii_case(want) {
            eprintln!("oh recv: sha256 OK ({})", &got[..16]);
        } else {
            anyhow::bail!(
                "sha256 mismatch: expected {}, got {}; file NOT saved at expected integrity",
                want,
                got,
            );
        }
    }

    eprintln!(
        "oh recv: saved {} ({} bytes) from oh://{}/",
        out_path.display(),
        resp.body.len(),
        sender_pk_zbase32,
    );

    session.close().await;
    Ok(())
}

/// Construct the literal GET / HTTP/1.1 request head the sender's
/// daemon forwards into the ephemeral file server at
/// `http://127.0.0.1:<port>/`.
fn build_get_request_head() -> String {
    // `Host: openhost` matches what `openhost-client` uses by
    // convention — the upstream HTTP server doesn't care so long as
    // the value is syntactically valid.
    "GET / HTTP/1.1\r\nHost: openhost\r\nAccept: */*\r\n\r\n".to_owned()
}

/// Parse an HTTP/1.1 response head (as delivered by the openhost
/// wire protocol) into the status code + header list. Header keys
/// are lower-cased for consistent matching later; values are
/// preserved verbatim.
fn parse_http_head(head_bytes: &[u8]) -> Result<(u16, Vec<(String, String)>)> {
    let text = std::str::from_utf8(head_bytes).context("response head is not UTF-8")?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| anyhow!("empty response head"))?;
    let mut parts = status_line.splitn(3, ' ');
    let _http_ver = parts.next();
    let status_str = parts
        .next()
        .ok_or_else(|| anyhow!("no status code in: {status_line}"))?;
    let status: u16 = status_str
        .parse()
        .with_context(|| format!("status not a number: {status_str}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    Ok((status, headers))
}

fn filename_from_content_disposition(headers: &[(String, String)]) -> Option<String> {
    let cd = headers
        .iter()
        .find(|(k, _)| k == "content-disposition")
        .map(|(_, v)| v.as_str())?;
    // Minimal RFC 6266 parse: pick the `filename="..."` attribute.
    for part in cd.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("filename=") {
            let name = rest.trim_matches('"');
            if !name.is_empty() {
                return Some(sanitise_filename(name));
            }
        }
    }
    None
}

fn sha256_header(headers: &[(String, String)]) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k == "x-openhost-file-sha256")
        .map(|(_, v)| v.clone())
}

/// Strip directory traversal + shell metacharacters from an
/// attacker-controlled filename. Matches the server-side sanitiser
/// in `file_server.rs`.
fn sanitise_filename(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Neutralise any leftover `..` sequences so the result can't
    // be interpreted as a parent-directory traversal even if the
    // caller prepends a path.
    let cleaned = cleaned.replace("..", "__");
    // Reject the degenerate cases that survive char-level cleanup.
    if cleaned.is_empty() || cleaned == "." || cleaned.chars().all(|c| c == '.') {
        return "openhost-transfer.bin".to_owned();
    }
    cleaned
}

/// Utility used by the CLI's `--out` flag: ensure the parent dir
/// exists. Returns the original path on success.
pub async fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create parent directory: {}", parent.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(k: &str, v: &str) -> (String, String) {
        (k.to_owned(), v.to_owned())
    }

    #[test]
    fn parses_200_and_headers() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Openhost-File-Sha256: abc\r\n\r\n";
        let (status, headers) = parse_http_head(head).unwrap();
        assert_eq!(status, 200);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "content-length");
        assert_eq!(headers[1].0, "x-openhost-file-sha256");
    }

    #[test]
    fn parses_404() {
        let head = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let (status, _) = parse_http_head(head).unwrap();
        assert_eq!(status, 404);
    }

    #[test]
    fn filename_from_cd_quoted() {
        let hs = vec![hdr(
            "content-disposition",
            "attachment; filename=\"report.pdf\"",
        )];
        assert_eq!(
            filename_from_content_disposition(&hs).as_deref(),
            Some("report.pdf")
        );
    }

    #[test]
    fn filename_from_cd_unquoted() {
        let hs = vec![hdr(
            "content-disposition",
            "attachment; filename=report.pdf",
        )];
        assert_eq!(
            filename_from_content_disposition(&hs).as_deref(),
            Some("report.pdf")
        );
    }

    #[test]
    fn filename_cd_absent_returns_none() {
        let hs = vec![hdr("content-type", "application/octet-stream")];
        assert!(filename_from_content_disposition(&hs).is_none());
    }

    #[test]
    fn sanitise_rejects_traversal() {
        // `.` is a safe filename character on its own, but `..` and
        // `/` must be neutralised so the result can never resolve
        // to a parent directory on disk.
        let san = sanitise_filename("../etc/passwd");
        assert!(!san.contains('/'));
        assert!(!san.contains(".."), "got: {san}");
        // Degenerate single-char names fall back to the default.
        assert_eq!(sanitise_filename("."), "openhost-transfer.bin");
        assert_eq!(sanitise_filename(""), "openhost-transfer.bin");
        // Lone `..` collapses to `__` — 2 underscores is a safe
        // literal filename, nothing resolvable.
        assert_eq!(sanitise_filename(".."), "__");
        // Longer dot runs stay safe after the `..` replacement (no
        // `..` substring survives).
        assert!(!sanitise_filename("...").contains(".."));
    }

    #[test]
    fn sha256_header_roundtrip() {
        let hs = vec![hdr("x-openhost-file-sha256", "abc123")];
        assert_eq!(sha256_header(&hs).as_deref(), Some("abc123"));
    }

    #[test]
    fn build_get_head_is_valid_http() {
        let head = build_get_request_head();
        assert!(head.starts_with("GET / HTTP/1.1\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }
}
