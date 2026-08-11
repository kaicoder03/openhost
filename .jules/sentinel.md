## 2026-07-28 - Preventing Unix File Creation Permission Race Condition
**Vulnerability:** Creating sensitive files (such as identities, seeds, certs, or allowlists) and then tightening permissions (e.g. via chmod) creates a brief Time-of-Check to Time-of-Use (TOCTOU) timing window during which other local users could potentially read or write to the file.
**Learning:** This existed because file permissions were set post-creation via chmod.
**Prevention:** Ensure highly sensitive files are atomically created with strict permissions using `OpenOptionsExt::mode(0o600)` on Unix platforms at creation time.

## 2026-07-28 - Strict Compliance with RFC 7230 §3.2.4 to Prevent HTTP Request Smuggling
**Vulnerability:** Accepting requests where leading or trailing whitespace surrounds a header name violates RFC 7230 §3.2.4 and can lead to HTTP Request Smuggling or Header Injection attacks when requests are forwarded upstream.
**Learning:** This existed because header parsers or forwarders may trim whitespace around header names, allowing malicious clients to craft requests that are parsed differently by our forwarder and the upstream proxy.
**Prevention:** Explicitly reject any request containing whitespace (space or horizontal tab) surrounding a header name, and strictly trim optional whitespace (OWS) at both ends of header values.
