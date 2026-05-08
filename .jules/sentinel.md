## 2025-05-15 - Hardening HTTP Request Parsing

**Vulnerability:** HTTP Request Smuggling and Denial of Service (DoS) via memory exhaustion.
**Learning:** The initial HTTP forwarder was overly permissive, allowing whitespace before colons and obsolete line folding (RFC 7230 violations) which can be used for request smuggling. It also lacked a size limit on the request head, making the daemon vulnerable to memory-exhaustion DoS.
**Prevention:** Enforce strict RFC 7230 compliance in hand-rolled parsers (reject bare CR/LF, obsolete folding, and OWS before colons). Always apply resource bounds (like `MAX_HEAD_BYTES`) at the earliest possible ingestion point.
