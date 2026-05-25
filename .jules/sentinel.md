## 2025-05-22 - Strict HTTP Header Parsing and Size Limits
**Vulnerability:** HTTP request smuggling and memory exhaustion DoS via lenient header parsing (whitespace before colon, OBS-fold) and unbounded header sizes.
**Learning:** Hand-rolled HTTP parsers must explicitly implement modern RFC 7230 constraints (e.g., §3.2.4) to prevent smuggling; global frame limits are insufficient for request-level security.
**Prevention:** Enforce strict header name/colon separation, reject line folding, and apply per-transaction size caps before fully buffering headers in memory.
