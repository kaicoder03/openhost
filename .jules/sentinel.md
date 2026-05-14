## 2025-05-14 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling (HRS) risk due to lax header parsing. Specifically, whitespace before the colon and leading whitespace (OBS-fold) were accepted and trimmed.
**Learning:** Hand-rolled HTTP parsers often default to liberal `trim()` calls, which can introduce ambiguity when the same request is processed by multiple proxies with different parsing rules.
**Prevention:** Always enforce strict RFC compliance for protocol delimiters. Reject `OWS` where it is forbidden (e.g., between field-name and colon) rather than silently sanitizing it.
