## 2026-07-15 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP request smuggling or response splitting.
**Learning:** `http::HeaderValue::from_str` does not automatically trim whitespace from the provided string. Additionally, many hand-rolled parsers (including the one in this daemon's forwarder) may be overly permissive with whitespace before the colon in header lines. RFC 7230 §3.2.4 explicitly prohibits whitespace between the header name and the colon and requires trimming OWS from the value.
**Prevention:** Explicitly reject header names ending in whitespace before the colon and use `.trim_matches([' ', '\t'])` to handle OWS at both ends of the header value in all custom HTTP parsers.
