## 2025-05-15 - HTTP Header Smuggling via Whitespace Lenience
**Vulnerability:** The HTTP/1.1 request head parser incorrectly accepted whitespace before the colon in header fields (e.g., `Host : example.com`).
**Learning:** Using `.trim()` on header names before validation can bypass RFC-mandated strictness. In `openhost-daemon`, this was being done before passing the name to `http::HeaderName::from_bytes`.
**Prevention:** Avoid manual trimming of protocol-critical identifiers. Delegate validation to established libraries (like the `http` crate) using the raw, untrimmed bytes from the wire.
