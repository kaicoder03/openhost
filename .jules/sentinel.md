## 2025-05-14 - HTTP Request Smuggling via Header Name Whitespace
**Vulnerability:** The HTTP parser allowed whitespace between the header name and the colon (e.g., `Host : example.com`), which violates RFC 7230 §3.2.4 and can lead to request smuggling or cache poisoning if upstream/downstream parsers handle it differently.
**Learning:** Using `.trim()` on the extracted header name is a common but dangerous pattern that can hide invalid protocol framing.
**Prevention:** Enforce strict RFC 7230 §3.2.4 compliance by ensuring no whitespace exists between the field name and the colon.
