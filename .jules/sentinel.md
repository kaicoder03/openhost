## 2025-03-05 - Strict HTTP Parsing and Head Size Limits
**Vulnerability:** Hand-rolled HTTP parser allowed whitespace between header names and colons (RFC 7230 §3.2.4 violation), accepted OBS-fold, and lacked head size limits, risking request smuggling and memory exhaustion (DoS).
**Learning:** Hand-rolled parsers often miss subtle RFC requirements that have significant security implications. Defense-in-depth is necessary even when using robust libraries like Hyper, as the initial framing layer (data channel listener) might still be vulnerable.
**Prevention:** Always enforce strict RFC compliance in parsers, implement explicit resource limits at the earliest possible entry point, and add regression tests for known smuggling vectors.
