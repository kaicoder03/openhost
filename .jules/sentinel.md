## 2026-07-28 - Strict Compliance with RFC 7230 §3.2.4 Header Name Parsing
**Vulnerability:** Header field names containing whitespace (e.g. space before colon `Host : example` or leading space ` Host: example`) were silently trimmed during request parsing. This tolerance could allow HTTP Request Smuggling or Header Injection when proxying requests upstream.
**Learning:** Silently trimming header field names instead of strictly rejecting whitespace before or around header names creates a desynchronization gap between front-end and back-end parsers.
**Prevention:** Strictly reject any HTTP request header field name that contains space or tab characters before parsing or forwarding.
