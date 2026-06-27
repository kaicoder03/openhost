## 2025-05-15 - RFC 7230 §3.2.4 Violation in HTTP Header Parsing
**Vulnerability:** The HTTP/1.1 request head parser in `openhost-daemon` was using `.trim()` on header names, which allowed whitespace between the header field name and the colon (e.g., `Host : example`).
**Learning:** Over-aggressive trimming during manual HTTP parsing can inadvertently accept malformed headers that are prohibited by RFC 7230 §3.2.4. This creates a risk of HTTP request smuggling if an upstream server interprets the same headers differently.
**Prevention:** Avoid `.trim()` on header names. Let the underlying header library (like `http::header::HeaderName`) validate the raw bytes from the colon-split to ensure no illegal whitespace is present.
