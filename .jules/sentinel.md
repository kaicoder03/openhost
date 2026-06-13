## 2025-05-14 - Strict HTTP Header Parsing and Head Size Limits
**Vulnerability:** HTTP Request Smuggling via whitespace before colon in headers, and Potential DoS via unbounded header accumulation.
**Learning:** Hand-rolled HTTP parsers often miss subtle RFC requirements like RFC 7230 §3.2.4 which forbids whitespace between header name and colon. Additionally, protocol security limits (like 32KB for headers) must be enforced at the entry point (listener) and ideally again at the processing layer (forwarder) for defense in depth.
**Prevention:** Always validate header formatting against RFC 7230 strictly. Enforce explicit size limits on all inbound buffers and protocol-level objects.
