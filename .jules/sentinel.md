# Sentinel Security Journal

## 2026-07-28 - Preventing HTTP Request Smuggling via Header Name Whitespace Check (RFC 7230 §3.2.4)
**Vulnerability:** HTTP Request Smuggling (HRS) is possible if upstreams and downstreams parse or handle header names with surrounding whitespace differently. RFC 7230 §3.2.4 explicitly mandates rejecting any request that contains whitespace (space or tab) surrounding a header name.
**Learning:** Simply trimming whitespace from parsed header names is unsafe because an upstream proxy may interpret or route the request differently than the local forwarder, leading to security bypasses or cache poisoning.
**Prevention:** Reject requests with an error (e.g., `ForwardError::HeadParse`) if whitespace is detected before the colon separator in a header line.

## 2026-07-28 - Preventing Local File Permission Race Conditions via OpenOptions Atomic Creation
**Vulnerability:** Local privilege escalation or sensitive data leakage (TOCTOU race condition) can occur if sensitive files (such as private keys, DTLS certificates, seeds, or pairing databases) are created with default permissive permissions and then subsequently restricted using `chmod` / `set_permissions`.
**Learning:** During the tiny window between file creation and permission restriction, other local users could read the sensitive file.
**Prevention:** Always use `OpenOptions` (`std::fs` or `tokio::fs`) with `.mode(0o600)` at creation time on Unix platforms so that the file is atomic and never exposed with permissive defaults.
