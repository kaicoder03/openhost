## 2026-07-08 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling via whitespace in header names.
**Learning:** Trimming whitespace from header names before validation in hand-rolled parsers violates RFC 7230 §3.2.4 and can mask request smuggling vulnerabilities where intermediaries and upstreams disagree on header identity.
**Prevention:** Rely on the `http` crate's `HeaderName::from_bytes` for strict validation and use `.trim_matches([' ', '\t'])` on values to correctly implement OWS (Optional WhiteSpace) requirements.
