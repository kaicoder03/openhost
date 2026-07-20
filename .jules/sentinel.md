# Sentinel Security Journal

## 2026-07-15 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling via whitespace injection in headers.
**Learning:** Legacy parsers that allowed leading/trailing whitespace or whitespace before the colon in header fields could be exploited for request smuggling. Trim and reject rules must strictly conform to RFC 7230 §3.2.4.
**Prevention:** Reject headers containing whitespace before the colon and explicitly trim OWS from header values.

## 2026-07-25 - File Creation Permission Race Condition
**Vulnerability:** Local information disclosure of sensitive private keys and certificates.
**Learning:** Creating sensitive files using default write/create functions, followed by a secondary `chmod` or `set_permissions` call, creates a timing window where the file is readable by other local users.
**Prevention:** Always use `OpenOptions` with Unix-specific `mode(0o600)` at file creation time to ensure permissions are locked down before any bytes are written.
