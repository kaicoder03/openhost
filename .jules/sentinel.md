## 2025-05-14 - Strict HTTP Parsing in Localhost Forwarder
**Vulnerability:** Manual HTTP/1.1 parsing in `forward.rs` was susceptible to memory-exhaustion DoS and Request Smuggling.
**Learning:** Hand-rolled parsers often miss RFC 7230 edge cases like bare line terminators (LF/CR), obsolete line folding, and whitespace before colons. Additionally, missing bounds on header size allows untrusted clients to consume excessive memory.
**Prevention:** Always enforce a `MAX_HEAD_BYTES` limit (e.g., 64KB) and explicitly reject non-CRLF line terminators, folded headers, and invalid whitespace in the header block. Use `HeaderValue::from(u64)` for numeric headers to avoid allocation-heavy string formatting.
