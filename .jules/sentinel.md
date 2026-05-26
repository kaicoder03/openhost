## 2025-05-14 - HTTP Header Parsing Hardening
**Vulnerability:** HTTP Request Smuggling and Denial-of-Service via unbounded headers.
**Learning:** Hand-rolled HTTP parsers often default to permissive whitespace handling (e.g., Unicode-aware `.trim()`) which can diverge from strict RFC 7230 §3.2.4 requirements (OWS is only Space and HTAB). This divergence, along with support for Obsolete Line Folding (OBS-fold), creates opportunities for request smuggling.
**Prevention:** Always enforce a hard size limit on the request head *before* full parsing/storage. Strictly validate OWS per RFC 7230 and explicitly reject OBS-fold and whitespace before the header colon.
