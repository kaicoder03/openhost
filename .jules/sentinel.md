## 2025-05-14 - Hardening Hand-rolled HTTP Parser against Smuggling
**Vulnerability:** HTTP Request Smuggling (Desync) via malformed headers.
**Learning:** Hand-rolled HTTP parsers often overlook RFC 7230 edge cases like whitespace before colons and obsolete line folding (obs-fold). Malicious clients can use these to desync a proxy from its upstream, potentially smuggling a second request.
**Prevention:** Always enforce strict RFC 7230 compliance in manual parsers: reject any header line starting with whitespace and reject whitespace between the header name and the colon.
