## 2026-07-08 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling risk via loose header parsing.
**Learning:** Trimming whitespace from header names and only trimming leading whitespace from values allows malformed headers that can be exploited for request smuggling. RFC 7230 §3.2.4 strictly forbids whitespace before the colon and requires OWS (SP/HTAB) trimming for values.
**Prevention:** Always use strict parsers that follow RFC specifications for HTTP. For hand-rolled parsers, ensure they explicitly reject forbidden whitespace and correctly handle optional whitespace according to the spec.
