## 2025-05-14 - Request Head Security Limits and RFC 7230 Hardening
**Vulnerability:** Lack of size limits on REQUEST_HEAD frames and non-strict parsing of header name/colon whitespace.
**Learning:** Without explicit bounds on the `head_payload` before parsing, a malicious client can exhaust memory or cause a DoS. Additionally, lenient header parsing (allowing whitespace before the colon) can lead to HTTP Request Smuggling.
**Prevention:** Always enforce a maximum size for headers (e.g., 32KB) at the earliest possible entry point and strictly reject RFC 7230 violations in the parser.
