## 2026-07-15 - Strict RFC 7230 Header Parsing
**Vulnerability:** Request Smuggling
**Learning:** `http::HeaderValue::from_str` and the manual `parse_request_head` parser were previously lenient with whitespace around the colon and within header values. Specifically, allowing whitespace between the field name and colon, and failing to trim trailing OWS from field values, can lead to request smuggling or splitting when the daemon is used in conjunction with other HTTP intermediaries.
**Prevention:** Enforce RFC 7230 §3.2.4 strictly. Reject any header field name that ends with whitespace before the colon. Use `.trim_matches([' ', '\t'])` on header values to ensure all Optional WhiteSpace (OWS) is removed from both ends before parsing as a `HeaderValue`.

## 2026-07-16 - Strict RFC 7230 Compliance Verification
**Vulnerability:** Request Smuggling / RFC 7230 non-compliance
**Learning:** Proactive verification of RFC compliance in manual parsers is essential. Unit tests should explicitly cover edge cases in the specification (like OWS and whitespace-before-colon) that libraries like `http` or `hyper` might handle differently if they are passed pre-split strings.
**Prevention:** Always add negative tests for specification violations (e.g., rejecting whitespace before colons) and positive tests for required normalization (e.g., trimming trailing OWS) when implementing or maintaining manual protocol parsers.
