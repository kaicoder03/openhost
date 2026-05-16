## 2025-05-14 - HTTP Header Name Whitespace Vulnerability
**Vulnerability:** The hand-rolled HTTP/1.1 request head parser in `openhost-daemon` incorrectly accepted whitespace between header names and the colon, as well as leading whitespace before header names (obs-fold).
**Learning:** The parser used `.trim()` on the header name portion of the string, which silently normalized malformed input. This can lead to HTTP Request Smuggling if an upstream proxy and the daemon interpret the malformed header differently.
**Prevention:** Always use strict, RFC-compliant parsing for protocol headers. Explicitly check for and reject forbidden whitespace instead of automatically trimming it.
