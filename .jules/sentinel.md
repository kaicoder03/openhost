## 2026-06-11 - Strict HTTP Header Validation
**Vulnerability:** HTTP Request Smuggling / Ambiguity via illegal whitespace in header names.
**Learning:** RFC 7230 §3.2.4 explicitly forbids whitespace between the header name and the colon. Parsers that are too lenient (e.g., by trimming the name) can be exploited if an upstream proxy has a different interpretation of the malformed header.
**Prevention:** Always validate that the substring before the colon in an HTTP header line does not end with whitespace before performing any trimming or further processing.
