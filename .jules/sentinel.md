## 2025-05-15 - Strict HTTP Header Parsing and Request Head Limits
**Vulnerability:** HTTP Smuggling via whitespace before colons and Denial of Service via unbounded request heads.
**Learning:** The hand-rolled HTTP parser in `forward.rs` used `.trim()` on header names, which allowed "Host :" instead of "Host:". RFC 7230 §3.2.4 requires rejecting such requests. Additionally, the `REQUEST_HEAD` frame lacked a size limit, allowing potential memory exhaustion.
**Prevention:** Always follow RFC strictness for header field names (no whitespace before colon) and enforce reasonable application-layer limits (e.g., 32KB) on all variable-length control structures before parsing.
