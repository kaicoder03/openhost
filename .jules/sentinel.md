## 2025-06-29 - [Vulnerability] Header Whitespace Lenience in HTTP Parser
**Vulnerability:** The HTTP/1.1 request head parser in `crates/openhost-daemon/src/forward.rs` used `.trim()` on header field names, allowing whitespace between the field name and the colon (e.g., `Host : example`).
**Learning:** This violation of RFC 7230 §3.2.4 ("No whitespace is allowed between the header field-name and colon") is a classic precursor to HTTP Request Smuggling and Response Splitting. If a proxy and an upstream disagree on how to handle malformed headers, an attacker can "hide" a request or header.
**Prevention:** Remove `.trim()` from header names before validation. Rely on strict parser primitives like `HeaderName::from_bytes` which correctly reject tokens containing whitespace.
