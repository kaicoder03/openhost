## 2026-07-09 - Strict RFC 7230 header parsing to prevent request smuggling
**Vulnerability:** The hand-rolled HTTP parser was trimming whitespace from header names and only trimming leading whitespace from values.
**Learning:** RFC 7230 §3.2.4 strictly forbids whitespace between the header name and the colon. Trimming it masks invalid requests that could be used in request smuggling attacks if the upstream is more strict. Additionally, OWS (Optional WhiteSpace) in header values includes both leading and trailing whitespace.
**Prevention:** Always validate header names without trimming. Use `HeaderName::from_bytes` on the raw name part. Trim both leading and trailing SP/HTAB from header values using `.trim_matches([' ', '\t'])`.
