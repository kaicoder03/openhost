## 2025-05-14 - HTTP Request Head Size Limit
**Vulnerability:** Denial of Service (DoS) via memory exhaustion. The daemon was accumulating and parsing HTTP request heads of unbounded size, allowing an attacker to exhaust RAM by sending extremely large headers.
**Learning:** Even when using a framed protocol (like openhost's data channel frames), application-layer payloads (like HTTP headers) must be explicitly capped before they are fully buffered or parsed. Framed length prefixes (up to 16MB in this repo) are often much larger than what is safe for specific sub-protocols like HTTP/1.1 headers.
**Prevention:** Enforce strict size limits at the earliest possible entry point (the frame dispatcher) and provide defense-in-depth by re-verifying limits in the parsing logic.
