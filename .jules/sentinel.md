## 2025-05-14 - Strict HTTP Header Parsing and Provenance Sanitization
**Vulnerability:** HTTP Request Smuggling and IP Spoofing.
**Learning:** The HTTP/1.1 parser in `crates/openhost-daemon/src/forward.rs` was overly permissive, allowing whitespace before the colon in header fields (violating RFC 7230 §3.2.4). Additionally, several common proxy headers (`true-client-ip`, `cf-connecting-ip`, `x-forwarded-port`) were not being stripped, allowing clients to potentially spoof provenance information.
**Prevention:** Enforce strict RFC compliance by rejecting any whitespace between the header field-name and the colon. Maintain a comprehensive list of known provenance headers for stripping in proxy/forwarding logic.
