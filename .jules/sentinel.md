## 2026-07-08 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling (HRS).
**Learning:** Hand-rolled HTTP parsers that allow whitespace between a header name and colon (e.g., via `.trim()` on the name) deviate from RFC 7230 §3.2.4 and can be exploited for request smuggling when layered with stricter proxies.
**Prevention:** Always use `name.ends_with([' ', '\t'])` to explicitly reject OWS before the colon, and use `value.trim_matches([' ', '\t'])` to ensure trailing OWS is stripped from values as required by the spec.
