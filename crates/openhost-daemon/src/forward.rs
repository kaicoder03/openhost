//! Localhost HTTP forwarder (PR #6).
//!
//! Accepts a framed `REQUEST_HEAD` + buffered body from the data-channel
//! listener, reconstructs an HTTP/1.1 request, applies spec §4.1 + §7.12
//! SSRF defences, dispatches to the configured upstream, and returns the
//! head + body bytes the listener encodes as `RESPONSE_HEAD` +
//! `RESPONSE_BODY` + `RESPONSE_END`.
//!
//! **SSRF defences applied on every forwarded request:**
//! - Hop-by-hop headers (RFC 7230 §6.1) stripped: `Connection`,
//!   `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`,
//!   `Trailer`, `Transfer-Encoding`, `Upgrade`.
//! - Provenance headers blocked: `X-Forwarded-For`, `X-Forwarded-Host`,
//!   `X-Forwarded-Proto`, `Forwarded`, `X-Real-IP`.
//! - `Host` header pinned to the configured target authority.
//! - `Upgrade: websocket` rejected — the spec gates websockets behind
//!   explicit per-path config (future PR).
//!
//! The response head is similarly sanitised on the way back: hop-by-hop
//! headers removed (a misbehaving upstream sending
//! `Transfer-Encoding: chunked` would otherwise leak through our
//! binary framing), and `Content-Length` rewritten to match the
//! buffered body length.

use crate::config::ForwardConfig;
use crate::error::ForwardError;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use std::time::Duration;

/// Default connect timeout when reaching the upstream. Localhost should
/// complete in microseconds; 2 seconds is comfortably above the worst
/// case and still bounds a misconfigured target from wedging a request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Hop-by-hop header names per RFC 7230 §6.1. Must be stripped from
/// both inbound requests (before dispatch to upstream) and outbound
/// responses (before re-framing to the openhost client).
///
/// Stored lowercase for `HeaderName::from_static`-style comparisons —
/// `HeaderMap::remove` is case-insensitive.
const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Provenance headers the openhost client MUST NOT be able to inject into
/// upstream requests. Stripped on the way in.
const PROVENANCE_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
    "x-real-ip",
];

type HyperClient = LegacyClient<HttpConnector, Full<Bytes>>;

/// One buffered HTTP response, ready for the listener to re-frame onto
/// the data channel.
pub struct ForwardResponse {
    /// HTTP/1.1 response head — status line + sanitised headers,
    /// terminated by `\r\n\r\n`.
    pub head_bytes: Vec<u8>,
    /// Response body. May be empty for 204 / 304 etc.
    pub body: Bytes,
}

/// The daemon's localhost forwarder.
pub struct Forwarder {
    /// Upstream origin; scheme is guaranteed `http`.
    target: Uri,
    /// Value the outbound `Host` header is pinned to.
    host_override: String,
    /// Shared hyper client. Cloneable; we never hold it across requests
    /// so the internal connection pool is the only piece of state that
    /// lives between calls.
    client: HyperClient,
    /// Per-request body-size cap. Exceeding it errors with
    /// [`ForwardError::BodyTooLarge`] before any upstream bytes are
    /// sent.
    max_body_bytes: usize,
}

impl Forwarder {
    /// Build a forwarder from a validated [`ForwardConfig`]. Returns
    /// `None` if `cfg.target` isn't set (daemon falls back to the
    /// PR #5 502-stub path).
    pub fn from_config(cfg: &ForwardConfig) -> Result<Option<Self>, ForwardError> {
        let Some(target_str) = cfg.target.as_deref() else {
            return Ok(None);
        };
        let target: Uri = target_str
            .parse()
            .map_err(|e: http::uri::InvalidUri| ForwardError::TargetParse(e.to_string()))?;
        if target.scheme_str() != Some("http") {
            return Err(ForwardError::TargetParse(
                "only http:// upstreams are supported".to_string(),
            ));
        }
        let authority = target
            .authority()
            .ok_or_else(|| ForwardError::TargetParse("target is missing an authority".into()))?
            .to_string();

        let host_override = cfg
            .host_override
            .clone()
            .unwrap_or_else(|| authority.clone());

        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(CONNECT_TIMEOUT));

        let client: HyperClient =
            LegacyClient::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(connector);

        Ok(Some(Self {
            target,
            host_override,
            client,
            max_body_bytes: cfg.max_body_bytes,
        }))
    }

    /// The request-body size cap. Exposed so the listener can reject
    /// oversized requests before the full body accumulates in memory.
    pub fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    /// Forward one request. `head_payload` is the `REQUEST_HEAD` frame
    /// payload verbatim (HTTP/1.1 request line + headers, terminated by
    /// `\r\n\r\n`); `body` is the concatenation of any `REQUEST_BODY`
    /// frames between HEAD and END.
    pub async fn forward(
        &self,
        head_payload: &[u8],
        body: Bytes,
    ) -> Result<ForwardResponse, ForwardError> {
        if body.len() > self.max_body_bytes {
            return Err(ForwardError::BodyTooLarge {
                cap: self.max_body_bytes,
            });
        }

        let (method, path, mut headers) = parse_request_head(head_payload)?;
        sanitize_request_headers(&mut headers, &self.host_override)?;

        // Build the outbound URI by combining the target origin with the
        // request path. The path comes from the client verbatim; no
        // rewriting this PR.
        let target_uri = combine_target_and_path(&self.target, &path)?;

        let mut req_builder = Request::builder().method(method).uri(target_uri);
        // Replace the HeaderMap wholesale — simpler than iterating and
        // inserting one-by-one, and guaranteed to honour sanitisation.
        if let Some(req_headers) = req_builder.headers_mut() {
            *req_headers = headers;
        }

        // Tell hyper not to pool this connection. The data-channel
        // session may never make another request; reusing the TCP
        // handle risks leaking state if the upstream had side effects
        // tied to the connection.
        if let Some(req_headers) = req_builder.headers_mut() {
            req_headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }

        let req = req_builder
            .body(Full::new(body))
            .map_err(|e| ForwardError::HeadParse(header_error_reason(&e)))?;

        let response = self
            .client
            .request(req)
            .await
            .map_err(|e| ForwardError::UpstreamUnreachable(e.to_string()))?;

        if response.status() == StatusCode::SWITCHING_PROTOCOLS {
            return Err(ForwardError::UpstreamResponse(
                "upstream returned 101 Switching Protocols; upgrades unsupported",
            ));
        }

        let (parts, body) = response.into_parts();
        let collected = body
            .collect()
            .await
            .map_err(|e| ForwardError::UpstreamUnreachable(e.to_string()))?
            .to_bytes();

        let head_bytes = encode_response_head(parts.status, parts.headers, collected.len())?;
        Ok(ForwardResponse {
            head_bytes,
            body: collected,
        })
    }
}

/// Hand-rolled strict HTTP/1.1 request head parser. Accepts:
///
/// ```text
/// <METHOD> <PATH> HTTP/1.1\r\n
/// Header-Name: value\r\n
/// ...\r\n
/// \r\n
/// ```
///
/// Rejects HTTP/0.9, HTTP/1.0, HTTP/2+, missing blank line, and any
/// obvious line-ending confusion (bare `\n` inside headers).
fn parse_request_head(bytes: &[u8]) -> Result<(Method, String, HeaderMap), ForwardError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ForwardError::HeadParse("request head is not valid UTF-8"))?;

    // Find the header terminator. Must be exactly `\r\n\r\n`.
    let end = text
        .find("\r\n\r\n")
        .ok_or(ForwardError::HeadParse("missing blank line after headers"))?;
    let head = &text[..end];

    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or(ForwardError::HeadParse("empty request head"))?;

    let mut parts = request_line.split(' ');
    let method_str = parts
        .next()
        .ok_or(ForwardError::HeadParse("request line missing method"))?;
    let path = parts
        .next()
        .ok_or(ForwardError::HeadParse("request line missing path"))?
        .to_string();
    let version = parts
        .next()
        .ok_or(ForwardError::HeadParse("request line missing HTTP version"))?;
    if parts.next().is_some() {
        return Err(ForwardError::HeadParse("request line has trailing tokens"));
    }
    if version != "HTTP/1.1" {
        return Err(ForwardError::HeadParse(
            "only HTTP/1.1 request lines are supported",
        ));
    }

    let method = Method::from_bytes(method_str.as_bytes())
        .map_err(|_| ForwardError::HeadParse("invalid HTTP method"))?;

    let mut headers = HeaderMap::new();
    for line in lines {
        let colon = line
            .find(':')
            .ok_or(ForwardError::HeadParse("header line missing ':'"))?;
        let name = line[..colon].trim();
        let value = line[colon + 1..].trim_start_matches(' ');
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| ForwardError::HeadParse("invalid header name"))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| ForwardError::HeadParse("invalid header value"))?;
        headers.append(header_name, header_value);
    }

    Ok((method, path, headers))
}

/// Strip hop-by-hop + provenance headers, reject websocket upgrades,
/// and pin `Host` to the configured override.
fn sanitize_request_headers(
    headers: &mut HeaderMap,
    host_override: &str,
) -> Result<(), ForwardError> {
    // Reject websocket upgrades BEFORE stripping `Upgrade`.
    if let Some(upgrade) = headers.get(http::header::UPGRADE) {
        let v = upgrade.to_str().unwrap_or("").trim();
        if v.eq_ignore_ascii_case("websocket") {
            return Err(ForwardError::WebSocketUnsupported);
        }
    }

    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    for name in PROVENANCE_HEADERS {
        headers.remove(*name);
    }

    let host_value = HeaderValue::from_str(host_override).map_err(|_| {
        ForwardError::HeadParse("configured host_override is not a valid header value")
    })?;
    headers.insert(http::header::HOST, host_value);

    Ok(())
}

/// Build `http://<target-authority><path>` for the outbound request.
fn combine_target_and_path(target: &Uri, path: &str) -> Result<Uri, ForwardError> {
    let authority = target
        .authority()
        .ok_or(ForwardError::HeadParse("target URI is missing authority"))?;

    // Tolerate clients that send a relative-form path (`/foo`) or an
    // absolute-form URI (`http://host/foo`). Spec §4 implies relative;
    // accept both for resilience.
    let path_str = if let Some(stripped) = path.strip_prefix("http://") {
        match stripped.find('/') {
            Some(i) => &stripped[i..],
            None => "/",
        }
    } else {
        path
    };

    let path_and_query = if path_str.is_empty() || !path_str.starts_with('/') {
        format!("/{path_str}")
    } else {
        path_str.to_string()
    };

    let uri_str = format!("http://{authority}{path_and_query}");
    uri_str
        .parse()
        .map_err(|_| ForwardError::HeadParse("could not combine target + path into a URI"))
}

/// Encode the upstream response's status + headers into the wire form the
/// openhost client expects inside the `RESPONSE_HEAD` frame.
fn encode_response_head(
    status: StatusCode,
    mut headers: HeaderMap,
    body_len: usize,
) -> Result<Vec<u8>, ForwardError> {
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(*name);
    }
    // Rewrite Content-Length to match the buffered body. The upstream
    // might have sent `Transfer-Encoding: chunked` (now stripped);
    // without an accurate Content-Length the openhost client can't
    // frame-split the response stream.
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_len.to_string()).expect("body_len is ASCII digits"),
    );

    let reason = status.canonical_reason().unwrap_or("Unknown");
    let mut out = Vec::with_capacity(128 + headers.len() * 64);
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason).as_bytes());
    for (name, value) in &headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// Best-effort conversion from an `http::Error` into a stable
/// `&'static str` for `ForwardError::HeadParse`. The error's `Display`
/// varies across versions; we match on a few known-stable substrings.
fn header_error_reason(err: &http::Error) -> &'static str {
    let msg = err.to_string().to_ascii_lowercase();
    if msg.contains("invalid uri") {
        "invalid uri in outbound request"
    } else if msg.contains("header") {
        "invalid header in outbound request"
    } else {
        "failed to build outbound request"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Header sanitiser -------------------------------------------

    fn fresh_headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::HOST, HeaderValue::from_static("evil.example"));
        h.insert(
            http::header::CONNECTION,
            HeaderValue::from_static("keep-alive"),
        );
        h.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        h.insert(http::header::TE, HeaderValue::from_static("trailers"));
        h.insert(
            http::header::TRAILER,
            HeaderValue::from_static("Trailer-Name"),
        );
        h.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        h.insert(http::header::UPGRADE, HeaderValue::from_static("h2c"));
        h.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_static("1.2.3.4"),
        );
        h.insert(
            HeaderName::from_static("x-real-ip"),
            HeaderValue::from_static("5.6.7.8"),
        );
        h.insert(
            HeaderName::from_static("forwarded"),
            HeaderValue::from_static("by=evil"),
        );
        h.insert(
            HeaderName::from_static("x-forwarded-proto"),
            HeaderValue::from_static("https"),
        );
        h.insert(
            HeaderName::from_static("x-custom"),
            HeaderValue::from_static("keep-me"),
        );
        h
    }

    #[test]
    fn sanitize_strips_all_hop_by_hop_headers() {
        let mut h = fresh_headers();
        sanitize_request_headers(&mut h, "127.0.0.1:8080").unwrap();
        for name in HOP_BY_HOP_HEADERS {
            assert!(
                !h.contains_key(*name),
                "hop-by-hop header {name:?} survived sanitisation"
            );
        }
    }

    #[test]
    fn sanitize_strips_all_provenance_headers() {
        let mut h = fresh_headers();
        sanitize_request_headers(&mut h, "127.0.0.1:8080").unwrap();
        for name in PROVENANCE_HEADERS {
            assert!(
                !h.contains_key(*name),
                "provenance header {name:?} survived sanitisation"
            );
        }
    }

    #[test]
    fn sanitize_preserves_benign_headers() {
        let mut h = fresh_headers();
        sanitize_request_headers(&mut h, "127.0.0.1:8080").unwrap();
        assert_eq!(
            h.get("x-custom").map(|v| v.to_str().unwrap()),
            Some("keep-me")
        );
    }

    #[test]
    fn sanitize_pins_host() {
        let mut h = fresh_headers();
        sanitize_request_headers(&mut h, "127.0.0.1:8080").unwrap();
        assert_eq!(
            h.get(http::header::HOST).map(|v| v.to_str().unwrap()),
            Some("127.0.0.1:8080"),
            "Host header MUST be overwritten; saw: {:?}",
            h.get(http::header::HOST),
        );
    }

    #[test]
    fn sanitize_rejects_websocket_upgrade() {
        let mut h = HeaderMap::new();
        h.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
        let err = sanitize_request_headers(&mut h, "x").unwrap_err();
        assert!(matches!(err, ForwardError::WebSocketUnsupported));
    }

    #[test]
    fn sanitize_allows_non_websocket_upgrades_but_still_strips_upgrade_header() {
        // `Upgrade: h2c` is a legitimate HTTP/1.1 upgrade header that
        // upstream proxies might see. We don't support the upgrade
        // either, but don't treat it as a websocket-specific rejection —
        // just strip it as hop-by-hop so the upstream never sees it.
        let mut h = HeaderMap::new();
        h.insert(http::header::UPGRADE, HeaderValue::from_static("h2c"));
        sanitize_request_headers(&mut h, "x").unwrap();
        assert!(!h.contains_key(http::header::UPGRADE));
    }

    // --- Request head parser ----------------------------------------

    #[test]
    fn parse_request_head_happy_path() {
        let raw = b"GET /foo/bar?x=1 HTTP/1.1\r\nHost: example\r\nX-Custom: yes\r\n\r\n";
        let (method, path, headers) = parse_request_head(raw).unwrap();
        assert_eq!(method, Method::GET);
        assert_eq!(path, "/foo/bar?x=1");
        assert_eq!(headers.get("host").unwrap(), "example");
        assert_eq!(headers.get("x-custom").unwrap(), "yes");
    }

    #[test]
    fn parse_request_head_rejects_wrong_version() {
        let raw = b"GET / HTTP/1.0\r\n\r\n";
        let err = parse_request_head(raw).unwrap_err();
        assert!(matches!(err, ForwardError::HeadParse(_)));
    }

    #[test]
    fn parse_request_head_rejects_missing_blank_line() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n";
        let err = parse_request_head(raw).unwrap_err();
        assert!(matches!(err, ForwardError::HeadParse(_)));
    }

    #[test]
    fn parse_request_head_rejects_bad_method() {
        let raw = b"G\xFFT / HTTP/1.1\r\n\r\n";
        let err = parse_request_head(raw).unwrap_err();
        assert!(matches!(err, ForwardError::HeadParse(_)));
    }

    #[test]
    fn parse_request_head_rejects_header_without_colon() {
        let raw = b"GET / HTTP/1.1\r\nNoColonHere\r\n\r\n";
        let err = parse_request_head(raw).unwrap_err();
        assert!(matches!(err, ForwardError::HeadParse(_)));
    }

    // --- Response head encoder --------------------------------------

    #[test]
    fn encode_response_head_rewrites_content_length_and_strips_hop_by_hop() {
        let mut upstream = HeaderMap::new();
        upstream.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain"),
        );
        upstream.insert(
            http::header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        upstream.insert(http::header::CONNECTION, HeaderValue::from_static("close"));

        let bytes = encode_response_head(StatusCode::OK, upstream, 5).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("content-length: 5\r\n"));
        assert!(!text.to_lowercase().contains("transfer-encoding"));
        assert!(!text.to_lowercase().contains("connection: close"));
        assert!(text.contains("content-type: text/plain"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    // --- Forwarder::from_config -------------------------------------

    #[test]
    fn from_config_none_when_target_absent() {
        let cfg = ForwardConfig {
            target: None,
            host_override: None,
            max_body_bytes: 1024,
        };
        assert!(Forwarder::from_config(&cfg).unwrap().is_none());
    }

    #[test]
    fn from_config_rejects_https_target() {
        let cfg = ForwardConfig {
            target: Some("https://example.com".into()),
            host_override: None,
            max_body_bytes: 1024,
        };
        // `Forwarder` isn't `Debug`, so `unwrap_err()` won't compile —
        // pattern-match the `Result` instead.
        let result = Forwarder::from_config(&cfg);
        assert!(matches!(result, Err(ForwardError::TargetParse(_))));
    }

    #[test]
    fn from_config_rejects_non_url_target() {
        let cfg = ForwardConfig {
            target: Some("not a url".into()),
            host_override: None,
            max_body_bytes: 1024,
        };
        let result = Forwarder::from_config(&cfg);
        assert!(matches!(result, Err(ForwardError::TargetParse(_))));
    }

    #[test]
    fn from_config_derives_host_override_from_target() {
        let cfg = ForwardConfig {
            target: Some("http://127.0.0.1:8080".into()),
            host_override: None,
            max_body_bytes: 1024,
        };
        let fwd = Forwarder::from_config(&cfg).unwrap().unwrap();
        assert_eq!(fwd.host_override, "127.0.0.1:8080");
    }

    #[test]
    fn from_config_respects_explicit_host_override() {
        let cfg = ForwardConfig {
            target: Some("http://127.0.0.1:8080".into()),
            host_override: Some("my-service.local".into()),
            max_body_bytes: 1024,
        };
        let fwd = Forwarder::from_config(&cfg).unwrap().unwrap();
        assert_eq!(fwd.host_override, "my-service.local");
    }

    // --- combine_target_and_path ------------------------------------

    #[test]
    fn combine_target_and_path_builds_http_uri() {
        let target: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let uri = combine_target_and_path(&target, "/foo?bar=1").unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:8080/foo?bar=1");
    }

    #[test]
    fn combine_target_and_path_handles_missing_leading_slash() {
        let target: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let uri = combine_target_and_path(&target, "foo").unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:8080/foo");
    }

    #[test]
    fn combine_target_and_path_handles_absolute_form_request() {
        // Some clients send `GET http://host/path HTTP/1.1` (absolute-form
        // per RFC 7230 §5.3.2). The forwarder substitutes the configured
        // target but keeps the path — the client can't pick a different
        // upstream by smuggling one into the request line.
        let target: Uri = "http://127.0.0.1:8080".parse().unwrap();
        let uri = combine_target_and_path(&target, "http://evil.example/foo").unwrap();
        assert_eq!(uri.to_string(), "http://127.0.0.1:8080/foo");
    }
}
