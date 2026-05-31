## 2026-05-31 - [Strict HTTP Parsing and Head Size Limits]
**Vulnerability:** Hand-rolled HTTP parser was lenient with header name whitespace (e.g., "Host :") and obsolete line folding, which can lead to HTTP request smuggling. Additionally, there was no size limit on the `RequestHead` frame, leading to potential memory exhaustion DoS.
**Learning:** Hand-rolled parsers often miss RFC edge cases that established libraries handle. Security limits must be enforced as early as possible in the pipeline (at the listener level) to prevent resource exhaustion before parsing.
**Prevention:** Always use strict parsing rules for protocol-sensitive text. Enforce explicit size limits on all inbound buffers and frames.
