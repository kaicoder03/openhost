## 2025-05-14 - Strict HTTP Header Parsing and Size Limits
**Vulnerability:** Resource exhaustion DoS via oversized HTTP request heads and potential request smuggling via loose header parsing (whitespace trimming, OBS-fold).
**Learning:** Defaulting to `.trim()` on header names in a proxy is dangerous as it can lead to differential interpretation between the proxy and upstream. Enforcing strict RFC 7230 compliance (no whitespace before colon, no OBS-fold) is a critical defense-in-depth measure.
**Prevention:** Always enforce explicit length caps on untrusted buffers before processing, and use strict parsers for protocol-sensitive fields like HTTP headers.
