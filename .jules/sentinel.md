## 2025-05-15 - [DoS: Missing Size Limit on Request Heads]
**Vulnerability:** The daemon's HTTP forwarder and WebRTC listener lacked a size limit on `REQUEST_HEAD` frames, allowing a malicious client to exhaust memory by sending extremely large header payloads.
**Learning:** While request bodies were capped, the "head" (request line + headers) was implicitly trusted to be small. In a framed protocol, every buffer that accumulates peer data must have an explicit cap before allocation or cloning.
**Prevention:** Enforce a `MAX_HEAD_BYTES` (32KB) limit at the entry point of frame dispatch and again in the application-level forwarder.
