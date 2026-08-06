## 2026-07-28 - HTTP Request Smuggling RFC 7230 Compliance
**Vulnerability:** HTTP Request Smuggling due to permissive parsing of spaces/tabs preceding the colon in HTTP header names, or around the header values.
**Learning:** Permitting whitespace before a header name's colon violates RFC 7230 §3.2.4 and can lead to severe request smuggling or caching issues when chained with strict downstream or upstream proxies that process the whitespace differently.
**Prevention:** Explicitly reject any HTTP request headers containing whitespace between the header name and the colon, and trim both leading and trailing optional whitespace (OWS) on the header value to ensure parsing consistency.
