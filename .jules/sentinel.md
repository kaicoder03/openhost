## 2025-05-15 - HTTP Request Smuggling in Hand-rolled Parser
**Vulnerability:** Loose HTTP/1.1 header parsing in `forward.rs` allowed bare LFs, obsolete line folding, and whitespace before colons.
**Learning:** Hand-rolled HTTP parsers often overlook RFC 7230 edge cases. Using `.trim()` on header lines can inadvertently hide illegal whitespace before a colon, which some backend servers might treat differently than the proxy, leading to smuggling.
**Prevention:** Explicitly validate RFC 7230 constraints: reject bare line terminators (`\r` or `\n`), reject `obs-fold` (lines starting with SP/HTAB), and ensure no whitespace exists between the header name and the colon.
