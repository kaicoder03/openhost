## 2025-05-15 - Hardened HTTP parsing and resource limits in openhost-daemon
**Vulnerability:** Memory exhaustion DoS via oversized HTTP request heads and request smuggling/splitting via non-compliant header parsing.
**Learning:** The hand-rolled HTTP parser in `forward.rs` was too permissive, accepting bare CR/LF, obsolete line folding, and whitespace before colons, which are known vectors for request smuggling. It also lacked a dedicated size limit for the header block, separate from the body cap.
**Prevention:** Always enforce a explicit size limit (`MAX_HEAD_BYTES`) on HTTP heads before re-framing. Use a strict parser that rejects RFC 7230 violations (bare CR/LF, folding, leading/trailing whitespace around field names).
