## 2026-07-06 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling via whitespace before the colon in header fields.
**Learning:** Hand-rolled HTTP parsers that `trim()` header names before validation can be tricked by proxies that pass through `Host : example` while the server sees it as `Host: example`, leading to request desynchronization.
**Prevention:** Always use strict byte-for-byte validation for header names and ensure optional whitespace (OWS) is only trimmed from header values.
