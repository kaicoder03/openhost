## 2026-07-01 - [RFC 7230 §3.2.4 Header Parsing Vulnerability]
**Vulnerability:** The HTTP/1.1 request head parser incorrectly allowed whitespace between the header field name and the colon by calling `.trim()` on the name.
**Learning:** RFC 7230 §3.2.4 strictly forbids such whitespace because inconsistent handling by different proxies/servers can lead to request smuggling or response splitting.
**Prevention:** Always use strict parsing for HTTP headers. Avoid blanket `.trim()` on header components; instead, follow the RFC's specific whitespace rules (e.g., OWS allowed between colon and value, but none before the colon).
