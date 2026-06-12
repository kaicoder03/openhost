## 2025-05-14 - HTTP Header Parsing Hardening
**Vulnerability:** Potential memory exhaustion (DoS) via oversized request heads and protocol-level vulnerabilities like Request Smuggling due to non-strict header parsing.
**Learning:** Even if the underlying HTTP library (hyper) might handle these, the daemon's own framing and parsing layer must enforce security limits and spec compliance before forwarding. RFC 7230 §3.2.4 explicitly prohibits whitespace between the header name and colon to prevent smuggling.
**Prevention:** Always enforce standard security limits (e.g., 32KiB for headers) and implement strict, spec-compliant parsing for protocol-level inputs.
