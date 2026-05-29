## 2025-05-14 - Strict RFC 7230 compliance in custom HTTP forwarders
**Vulnerability:** Permissive HTTP header parsing and missing size limits on request heads in `openhost-daemon`.
**Learning:** Even when HTTP is carried over a custom transport (like WebRTC data channels), the application-layer parser must strictly enforce RFC 7230 to prevent request smuggling and memory-exhaustion DoS. Custom hand-rolled parsers often miss edge cases like OBS-fold and OWS rules that mature libraries handle automatically.
**Prevention:** Always enforce a hard cap on HTTP head frames before parsing. Reject OBS-fold and any whitespace between header names and colons. Strip both leading and trailing optional whitespace from values.
