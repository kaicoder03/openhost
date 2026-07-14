## 2026-07-09 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling via permissive whitespace handling in header names and values.
**Learning:** The daemon's hand-rolled HTTP parser was using `.trim()` on header names, which allowed whitespace between the field-name and the colon. This violates RFC 7230 §3.2.4 and is a known vector for request smuggling. Additionally, only leading whitespace was being trimmed from header values, leaving trailing OWS intact.
**Prevention:** Explicitly check for and reject whitespace at the end of header names before the colon. Use `.trim_matches([' ', '\t'])` on header values to correctly strip both leading and trailing OWS as mandated by the spec.
