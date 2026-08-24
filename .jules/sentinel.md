## 2026-07-28 - Strict Compliance with RFC 7230 §3.2.4 Header Whitespace
**Vulnerability:** Accepting HTTP requests with whitespace surrounding header names (e.g. `Host : example`) can lead to HTTP Request Smuggling or header smuggling if proxy and upstream parsers handle whitespace differently.
**Learning:** Hand-rolled HTTP request line/header parsers must explicitly validate that no whitespace exists before the header name or between the header name and colon, as `trim()` silently accepts non-compliant whitespace.
**Prevention:** Reject any header line where the slice before the colon contains whitespace, and trim only OWS (`[' ', '\t']`) from the header value.
