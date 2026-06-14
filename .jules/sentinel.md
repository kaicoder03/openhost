## 2025-05-15 - Enforce Request Head Limits and Strict Parsing
**Vulnerability:** Potential memory exhaustion (DoS) from unbounded HTTP request headers and potential HTTP Request Smuggling due to lenient header parsing (whitespace before colon, header folding).
**Learning:** Even if the underlying transport is secure (WebRTC/DTLS), the application-layer protocol (HTTP) must still be hardened. Lenient parsers can be exploited to bypass security controls or crash the process.
**Prevention:** Always enforce a reasonable limit on the request "head" (line + headers) and use a strict parser that rejects RFC-violating constructs like `obs-fold` or malformed header names.
