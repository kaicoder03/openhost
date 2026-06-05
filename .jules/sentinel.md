## 2025-05-15 - Strict HTTP Header Parsing and Size Limits

**Vulnerability:** HTTP header smuggling and Denial of Service (DoS). The daemon was trimming whitespace from header names, which could lead to parsing ambiguities (RFC 7230 §3.2.4). It also lacked a dedicated limit for the total size of the HTTP request head, potentially allowing memory exhaustion.

**Learning:** Trimming header names (e.g., `Host : example`) instead of rejecting them strictly can cause "split-view" attacks if an upstream proxy handles the whitespace differently. Additionally, while individual data-channel frames are capped, the accumulated request head needs its own security boundary (set here to 32KB) to protect both the daemon and the upstream service.

**Prevention:** Always use strict byte-level validation for protocol-critical fields like HTTP header names. Implement multi-layered size limits (early rejection in the listener + defense-in-depth in the forwarder) to protect against resource exhaustion.
