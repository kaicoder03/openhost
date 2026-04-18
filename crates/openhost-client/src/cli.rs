//! Shared helpers for openhost CLI binaries.
//!
//! Only compiled behind the `cli` feature so WASM / FFI consumers of
//! the crate don't pull clap / serde_json / tracing-subscriber / hex
//! transitively.

use crate::{ClientResponse, SigningKey};
use anyhow::{anyhow, Context, Result};
use base64::Engine;
use bytes::Bytes;
use std::io::Read;
use std::path::Path;
use thiserror::Error;

/// Usage-style errors — argv / URL / identity-file / relay-scheme
/// mistakes made by the operator, distinguishable from runtime /
/// network errors so CLI binaries can map them to exit code 2 without
/// resorting to error-message string matching.
#[derive(Debug, Error)]
pub enum UsageError {
    /// Identity seed file missing, wrong size, or otherwise unreadable.
    #[error("{0}")]
    Identity(String),
}

/// Load a 32-byte raw Ed25519 seed from disk, matching the layout the
/// daemon's `FsKeyStore` writes. Returns a [`UsageError::Identity`]
/// variant when the file is missing or not exactly 32 bytes; on
/// Unix, also emits a `warn!` when the file's mode is wider than
/// `0600` (defense-in-depth — a world-readable seed is the sort of
/// smell an operator should see before it becomes an incident).
pub fn load_identity_from_file(path: &Path) -> Result<SigningKey> {
    let bytes = std::fs::read(path).map_err(|e| {
        anyhow!(UsageError::Identity(format!(
            "failed to read identity seed from {}: {e}",
            path.display()
        )))
    })?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(UsageError::Identity(format!(
            "identity seed at {} must be exactly 32 bytes, got {}",
            path.display(),
            bytes.len()
        )))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if let Ok(meta) = std::fs::metadata(path) {
            // Lower 9 bits are the rwx/rwx/rwx permission triple. 0o177
            // masks out the owner's rwx; anything left on after owner
            // permissions is group/other — wider than 0600.
            let wider_than_owner = meta.mode() & 0o077 != 0;
            if wider_than_owner {
                tracing::warn!(
                    path = %path.display(),
                    mode = format!("{:o}", meta.mode() & 0o777),
                    "openhost-client: identity seed file is readable outside its owner — narrow permissions to 0600 to avoid leaking the signing key",
                );
            }
        }
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Returns `true` when `err`'s chain carries a [`UsageError`] or a
/// [`crate::ClientError::UrlParse`]. CLI binaries use this to pick
/// exit code 2 (usage) vs 1 (runtime).
pub fn is_usage_error(err: &anyhow::Error) -> bool {
    if err.downcast_ref::<UsageError>().is_some() {
        return true;
    }
    if err
        .chain()
        .any(|e| e.downcast_ref::<UsageError>().is_some())
    {
        return true;
    }
    err.downcast_ref::<crate::ClientError>()
        .map(|ce| matches!(ce, crate::ClientError::UrlParse(_)))
        .unwrap_or(false)
}

/// Interpret a `--data` argument: `@path` reads a file, `-` reads
/// stdin to EOF, otherwise the literal argument is used as UTF-8
/// bytes. Mirrors curl's `-d` semantics.
pub fn read_body_arg(arg: &str) -> Result<Bytes> {
    if let Some(path) = arg.strip_prefix('@') {
        let bytes =
            std::fs::read(path).with_context(|| format!("failed to read body from {path}"))?;
        return Ok(Bytes::from(bytes));
    }
    if arg == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("failed to read body from stdin")?;
        return Ok(Bytes::from(buf));
    }
    Ok(Bytes::from(arg.as_bytes().to_vec()))
}

/// Parse a `-H 'Key: Value'` argument into `(name, value)`. Accepts
/// both `Key:Value` and `Key: Value` (curl accepts either). The
/// leading space on the value is stripped if present.
pub fn parse_header_arg(arg: &str) -> Result<(String, String)> {
    let (name, value) = arg
        .split_once(':')
        .ok_or_else(|| anyhow!("header {arg:?} missing ':'"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(anyhow!("header {arg:?} has empty name"));
    }
    let value = value.strip_prefix(' ').unwrap_or(value);
    Ok((name.to_string(), value.to_string()))
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// Assemble raw HTTP/1.1 request head bytes. `headers` is the
/// user-supplied `-H` list; we only auto-add `Host`, `Content-Length`,
/// and `Content-Type` when the user hasn't supplied them.
pub fn build_request_head(
    method: &str,
    path: &str,
    default_host: &str,
    headers: &[(String, String)],
    body_len: usize,
) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(method);
    out.push(' ');
    out.push_str(if path.is_empty() { "/" } else { path });
    out.push_str(" HTTP/1.1\r\n");

    if !has_header(headers, "host") {
        out.push_str("Host: ");
        out.push_str(default_host);
        out.push_str("\r\n");
    }
    for (k, v) in headers {
        out.push_str(k);
        out.push_str(": ");
        out.push_str(v);
        out.push_str("\r\n");
    }
    if body_len > 0 {
        if !has_header(headers, "content-length") {
            out.push_str(&format!("Content-Length: {body_len}\r\n"));
        }
        if !has_header(headers, "content-type") {
            out.push_str("Content-Type: application/octet-stream\r\n");
        }
    }
    out.push_str("\r\n");
    out.into_bytes()
}

/// Parsed view of a [`ClientResponse`]. Not the full power of a real
/// HTTP parser — good enough to print and to JSON-serialise.
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    /// Numeric status code, e.g. `200`.
    pub status: u16,
    /// Full raw status line, e.g. `HTTP/1.1 200 OK`.
    pub status_line: String,
    /// Ordered `(name, value)` pairs in their response order.
    pub headers: Vec<(String, String)>,
    /// Body bytes (may be empty).
    pub body: Bytes,
}

/// Parse a [`ClientResponse`]'s raw HTTP/1.1 head into a
/// [`ParsedResponse`]. Returns an error if the head is not valid
/// UTF-8 or the status line is malformed.
pub fn parse_response(resp: &ClientResponse) -> Result<ParsedResponse> {
    let head_str =
        std::str::from_utf8(&resp.head_bytes).context("response head is not valid UTF-8")?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("empty response head"))?
        .to_string();
    let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(anyhow!("invalid status line: {status_line:?}"));
    }
    let status: u16 = parts[1]
        .parse()
        .with_context(|| format!("invalid status code in {status_line:?}"))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim_start().to_string()));
        }
    }
    Ok(ParsedResponse {
        status,
        status_line,
        headers,
        body: resp.body.clone(),
    })
}

/// JSON shape `--json` emits. Body is `body_utf8` when valid UTF-8,
/// `body_b64` (standard base64 with padding) otherwise. Extracted so
/// the schema can be unit-tested without spawning a subprocess.
pub fn response_to_json(resp: &ParsedResponse) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("status".into(), serde_json::json!(resp.status));
    obj.insert("status_line".into(), serde_json::json!(resp.status_line));
    obj.insert(
        "headers".into(),
        serde_json::json!(resp
            .headers
            .iter()
            .map(|(k, v)| serde_json::json!([k, v]))
            .collect::<Vec<_>>()),
    );
    match std::str::from_utf8(&resp.body) {
        Ok(s) => {
            obj.insert("body_utf8".into(), serde_json::json!(s));
        }
        Err(_) => {
            obj.insert(
                "body_b64".into(),
                serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&resp.body)),
            );
        }
    }
    serde_json::Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_variants() {
        assert_eq!(
            parse_header_arg("X-A: value").unwrap(),
            ("X-A".to_string(), "value".to_string())
        );
        assert_eq!(
            parse_header_arg("X-A:value").unwrap(),
            ("X-A".to_string(), "value".to_string())
        );
        assert_eq!(
            parse_header_arg("X-A:  two spaces").unwrap(),
            ("X-A".to_string(), " two spaces".to_string()),
            "only one leading space is stripped (curl convention)"
        );
        assert!(parse_header_arg("no colon").is_err());
        assert!(parse_header_arg(":value").is_err());
    }

    #[test]
    fn build_request_head_defaults() {
        let head = build_request_head("GET", "/index.html", "openhost", &[], 0);
        let s = std::str::from_utf8(&head).unwrap();
        assert!(s.starts_with("GET /index.html HTTP/1.1\r\n"));
        assert!(s.contains("Host: openhost\r\n"));
        assert!(!s.contains("Content-Length"));
        assert!(s.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_request_head_includes_content_length_when_body_present() {
        let head = build_request_head("POST", "/p", "host", &[], 42);
        let s = std::str::from_utf8(&head).unwrap();
        assert!(s.contains("Content-Length: 42\r\n"));
        assert!(s.contains("Content-Type: application/octet-stream\r\n"));
    }

    #[test]
    fn build_request_head_user_host_overrides_default() {
        let headers = vec![("Host".to_string(), "custom.example".to_string())];
        let head = build_request_head("GET", "/", "default", &headers, 0);
        let s = std::str::from_utf8(&head).unwrap();
        assert!(s.contains("Host: custom.example\r\n"));
        assert!(!s.contains("Host: default\r\n"));
    }

    #[test]
    fn build_request_head_user_content_type_skips_default() {
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];
        let head = build_request_head("POST", "/", "host", &headers, 5);
        let s = std::str::from_utf8(&head).unwrap();
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert_eq!(s.matches("Content-Type").count(), 1);
    }

    #[test]
    fn parse_response_basic() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\n".to_vec();
        let resp = ClientResponse {
            head_bytes: raw,
            body: Bytes::from_static(b"hello"),
        };
        let parsed = parse_response(&resp).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_line, "HTTP/1.1 200 OK");
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(
            parsed.headers[0],
            ("Content-Type".into(), "text/plain".into())
        );
        assert_eq!(parsed.body.as_ref(), b"hello");
    }

    #[test]
    fn parse_response_rejects_malformed_status() {
        let resp = ClientResponse {
            head_bytes: b"HTTP/1.1\r\n\r\n".to_vec(),
            body: Bytes::new(),
        };
        assert!(parse_response(&resp).is_err());
    }

    #[test]
    fn response_to_json_prefers_utf8_body() {
        let parsed = ParsedResponse {
            status: 200,
            status_line: "HTTP/1.1 200 OK".into(),
            headers: vec![],
            body: Bytes::from_static(b"hello"),
        };
        let v = response_to_json(&parsed);
        let obj = v.as_object().unwrap();
        assert_eq!(obj["status"], 200);
        assert!(obj.contains_key("body_utf8"));
        assert!(!obj.contains_key("body_b64"));
        assert_eq!(obj["body_utf8"], "hello");
    }

    #[test]
    fn response_to_json_falls_back_to_b64_for_invalid_utf8() {
        let parsed = ParsedResponse {
            status: 200,
            status_line: "HTTP/1.1 200 OK".into(),
            headers: vec![],
            body: Bytes::from_static(&[0xFF, 0xFE, 0xFD]),
        };
        let v = response_to_json(&parsed);
        let obj = v.as_object().unwrap();
        assert!(obj.contains_key("body_b64"));
        assert!(!obj.contains_key("body_utf8"));
    }

    #[test]
    fn read_body_arg_literal() {
        let bytes = read_body_arg("hello").unwrap();
        assert_eq!(bytes.as_ref(), b"hello");
    }

    #[test]
    fn read_body_arg_reads_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"file-contents").unwrap();
        let arg = format!("@{}", tmp.path().display());
        let bytes = read_body_arg(&arg).unwrap();
        assert_eq!(bytes.as_ref(), b"file-contents");
    }

    #[test]
    fn load_identity_rejects_wrong_size() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"too-short").unwrap();
        let err = load_identity_from_file(tmp.path()).unwrap_err();
        assert!(format!("{err}").contains("32 bytes"));
    }

    #[test]
    fn load_identity_loads_raw_32_byte_seed() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let seed = [0x42u8; 32];
        std::fs::write(tmp.path(), seed).unwrap();
        let sk = load_identity_from_file(tmp.path()).unwrap();
        assert_eq!(sk.to_bytes(), seed);
    }

    #[test]
    fn is_usage_error_detects_identity_usage_variant() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"too-short").unwrap();
        let err = load_identity_from_file(tmp.path()).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn is_usage_error_is_false_for_plain_runtime_errors() {
        let err = anyhow!("network went away");
        assert!(!is_usage_error(&err));
    }
}
