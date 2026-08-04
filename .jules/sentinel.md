# Sentinel Security Journal

## 2026-07-28 - Strict Compliance with RFC 7230 §3.2.4 to Prevent HTTP Request Smuggling
**Vulnerability:** HTTP Request Smuggling caused by parsing HTTP headers with whitespace surrounding header names (e.g. `Host : example.com`), which allowed desynchronization between front-end proxies and the back-end daemon.
**Learning:** Permissive parsing of header names (e.g. using `.trim()`) can allow attackers to inject headers that are interpreted differently by an upstream proxy and downstream daemon, potentially leading to cache poisoning, request hijacking, or credential leakage.
**Prevention:** Always explicitly reject any header lines with whitespace (spaces or tabs) preceding or succeeding the header name or surrounding the colon separator, as mandated by RFC 7230 §3.2.4.

## 2026-07-28 - Atomic Mode Selection to Avoid File Permission Race Conditions on Unix
**Vulnerability:** File permission race conditions (TOCTOU) where highly sensitive files (such as identities, seeds, and certificate private keys) were created with default permissions and then subsequently secured via `chmod`-like operations.
**Learning:** A small window of time exists between file creation and file permission modification where other local users on a shared Unix system could read the newly created sensitive files.
**Prevention:** Always set highly restrictive file permissions atomically at creation time using platform-specific APIs (e.g. `std::os::unix::fs::OpenOptionsExt::mode` with `0o600`) to guarantee that the files are never readable by other users even for a fraction of a millisecond.
