# Sentinel Security Journal

## 2026-07-28 - Strict Compliance with RFC 7230 §3.2.4 to Prevent HTTP Request Smuggling
**Vulnerability:** HTTP Request Smuggling due to lenient parsing of header names containing surrounding whitespace.
**Learning:** Standard parser tolerance was trimming surrounding whitespace of header names (e.g., space or tab before the colon), allowing malformed requests that could bypass security gateways or cause downstream desynchronization.
**Prevention:** Explicitly reject any HTTP request containing spaces or tabs leading, trailing, or before the colon in a header name, enforcing strict token validation before processing.
