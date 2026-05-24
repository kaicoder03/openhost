## 2025-05-15 - [Strict HTTP Header Parsing & Size Limits]
**Vulnerability:** Memory-exhaustion DoS via unbounded HTTP request headers and potential Request Smuggling via non-compliant header parsing (whitespace before colon, OBS-fold).
**Learning:** Even internal protocol bridges (DataChannel to localhost HTTP) must enforce strict RFC 7230 compliance and resource limits, as they represent the application's attack surface. Relying on `.trim()` during parsing can inadvertently normalize invalid/dangerous inputs.
**Prevention:** Always enforce a `MAX_HEAD_BYTES` limit before allocating/cloning header buffers and use strict parsing that rejects any deviation from the expected RFC format (no whitespace between field-name and colon, no line folding).
