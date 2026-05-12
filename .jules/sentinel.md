# Sentinel's Security Journal

## 2025-05-14 - Harden HTTP forwarder against DoS and smuggling
**Vulnerability:** The HTTP parser was too permissive, allowing bare CR/LF, obsolete line folding, and whitespace before colons, which can be exploited for request smuggling. Additionally, there was no limit on the size of the HTTP request head, leading to memory-exhaustion DoS risks.
**Learning:** Custom HTTP parsers must strictly adhere to RFC 7230 to prevent smuggling. Furthermore, application-level limits (like `MAX_HEAD_BYTES`) must be coordinated with transport-level limits (like SCTP's MTU/chunk size) to avoid transmission failures for large payloads.
**Prevention:** Always enforce strict RFC compliance in parsers and set explicit size limits on all buffered inputs.
