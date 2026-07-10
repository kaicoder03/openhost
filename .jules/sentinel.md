## 2026-07-08 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling via lenient header parsing.
**Learning:** Hand-rolled HTTP parsers must strictly follow RFC 7230 §3.2.4. Leniently trimming whitespace from header names can allow an attacker to bypass security filters that expect exact header names. Additionally, only trimming leading whitespace from values (OWS) can leave trailing whitespace that different proxies may interpret inconsistently (e.g., in Content-Length).
**Prevention:** Remove any `.trim()` calls on header names before validation. Use `.trim_matches([' ', '\t'])` on header values to ensure both leading and trailing Optional WhiteSpace is removed.
