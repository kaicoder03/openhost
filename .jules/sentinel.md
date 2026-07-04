## 2025-05-14 - HTTP Header Name Smuggling in Hand-Rolled Parser
**Vulnerability:** Hand-rolled HTTP parser trimmed whitespace from header names before validation, allowing `Host :` to be accepted as `Host`.
**Learning:** RFC 7230 §3.2.4 strictly forbids whitespace before the colon. Trimming names before passing them to a validator (like `http::HeaderName::from_bytes`) masks this violation.
**Prevention:** Never trim header names in HTTP parsers; let the validator handle the raw bytes to ensure strict compliance.
