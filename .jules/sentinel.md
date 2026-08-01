# Sentinel's Security Journal

## 2026-07-28 - HTTP Request Smuggling Prevention (RFC 7230 §3.2.4)
**Vulnerability:** HTTP Request Smuggling could occur if whitespace (space or tab) surrounding a header name was not rejected.
**Learning:** Strict compliance with RFC 7230 §3.2.4 is required to prevent parsing deviations between the openhost daemon forwarder and upstream servers.
**Prevention:** Explicitly reject any request header containing leading or trailing whitespace around its name in `parse_request_head` and trim OWS from values.

## 2026-07-28 - Unix File Creation Permission Race Condition
**Vulnerability:** Creating sensitive files (e.g., Ed25519 seeds, DTLS certs, allowlists) with default permissions and subsequently changing their mode using `set_permissions` opens a TOCTOU (Time of Check, Time of Use) timing window. During this window, other unprivileged local users could read the sensitive data.
**Learning:** File permissions must be set atomically at the exact moment of file creation rather than as a post-creation adjustment.
**Prevention:** Use `OpenOptions` (either `std::fs` or `tokio::fs`) with `OpenOptionsExt::mode(0o600)` on Unix platforms to ensure atomic 0o600 permissions at creation time.
