## 2025-05-15 - RFC 7230 Header Parsing and DoS Protection

**Vulnerability:** HTTP request smuggling due to permissive header name parsing (whitespace before colon) and potential memory exhaustion (DoS) from unbounded request heads.

**Learning:** The `parse_request_head` implementation used `.trim()` on header names, which incorrectly accepted whitespace before the colon (§3.2.4). Additionally, while request bodies were capped, the request head (line + headers) was not, allowing a malicious client to consume excessive memory.

**Prevention:** Always parse header names verbatim and rely on strict validation libraries (or traits like `HeaderName::from_bytes`) to reject invalid characters, including whitespace. Enforce a generous but firm limit (e.g., 32 KiB) on the entire request head before attempting to parse it.
