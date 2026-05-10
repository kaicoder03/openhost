## 2025-05-14 - [Memory Exhaustion via Unbounded HTTP Request Head]
**Vulnerability:** The daemon accumulated `REQUEST_HEAD` frame payloads into memory without an explicit size limit. A malicious client could send a multi-megabyte `REQUEST_HEAD` frame (up to `MAX_PAYLOAD_LEN` = 16MiB) or multiple large heads to exhaust daemon memory.
**Learning:** While higher-level protocols like HTTP often have these limits, the daemon's framing layer must also enforce them to prevent resource exhaustion before the payload is even handed to the parser.
**Prevention:** Always enforce strict size limits on unauthenticated or untrusted input buffers, especially those that are accumulated per-session.
