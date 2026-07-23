## 2026-07-25 - Unix File Creation Permission Race Condition Prevention
**Vulnerability:** A TOCTOU (Time-of-Check to Time-of-Use) race condition existed when highly sensitive files (such as Ed25519 seed files, DTLS certificates, and pairing allowlists) were created with default permissions and subsequently restricted using `chmod` or equivalent functions, temporarily exposing secrets to other local users.
**Learning:** File permissions must be established atomically at the exact moment of creation rather than modified afterwards. On Unix-like systems, this is securely achieved using `OpenOptionsExt::mode(0o600)` during file creation.
**Prevention:** Use `tokio::fs::OpenOptions` or `std::fs::OpenOptions` with `.mode(0o600)` on Unix platforms when initializing sensitive local stores.

## 2026-07-28 - HTTP Header Whitespace Parsing Vulnerability
**Vulnerability:** The HTTP request parser permissively trimmed whitespace (spaces/tabs) surrounding header field names (e.g. `Host : value` or ` Host: value`) before colon separation. This violates RFC 7230 §3.2.4 and can lead to HTTP Request Smuggling or header spoofing when requests are processed by intermediate proxies.
**Learning:** Hand-rolled HTTP parsers must strictly enforce the HTTP specification. Permissive parsing allows malformed messages to pass downstream, where different proxy parsers may interpret them differently.
**Prevention:** Explicitly check for and reject any leading or trailing whitespace around header field names before parsing. Trim OWS from both ends of the header value.
