## 2025-05-14 - HTTP Header Parsing and Frame Size Limits
**Vulnerability:** Memory exhaustion DoS via oversized REQUEST_HEAD frames and potential HTTP Request Smuggling via ambiguous header whitespace.
**Learning:** Hand-rolled HTTP parsers in the forwarder path must strictly enforce RFC 7230 §3.2.4 (no whitespace before colons, no OBS-folds) to prevent smuggling when talking to upstream backends. Additionally, application-layer framing requires explicit per-frame-type size limits (like MAX_HEAD_BYTES) even if the transport has its own chunk limits, to prevent unbounded buffering of request metadata.
**Prevention:** Always apply strict white-list parsing for HTTP headers and enforce early size rejections in the frame dispatcher before payload processing.
