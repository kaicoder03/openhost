## 2026-07-06 - Strict RFC 7230 Header Parsing
**Vulnerability:** Trimming whitespace from HTTP header names before validation in hand-rolled parsers violates RFC 7230 §3.2.4 and can mask request smuggling vulnerabilities.
**Learning:** Hand-rolled HTTP parsers must be extremely strict with OWS (Optional WhiteSpace). In this codebase, \`.trim()\` on header names was hiding illegal whitespace that \`HeaderName::from_bytes\` would have otherwise caught.
**Prevention:** Rely on established parser libraries when possible, or ensure hand-rolled parsers exactly match RFC specifications. For header values, RFC 7230 allows OWS but requires it be trimmed before processing.
