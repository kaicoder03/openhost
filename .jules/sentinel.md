## 2025-05-15 - Strict HTTP Header Parsing
**Vulnerability:** HTTP Request Smuggling via header whitespace.
**Learning:** The hand-rolled HTTP/1.1 parser in `forward.rs` was using `.trim()` on header field names. RFC 7230 §3.2.4 explicitly forbids whitespace between the field name and the colon (`field-name ":" OWS field-value BWS`). Allowing whitespace could lead to request smuggling if a frontend proxy and this backend daemon interpret the header name differently.
**Prevention:** Avoid `.trim()` on protocol-sensitive tokens. Use exact slicing and rely on strict validation libraries (like `http::HeaderName::from_bytes` on the raw slice) which correctly reject invalid characters including interior or trailing spaces.
