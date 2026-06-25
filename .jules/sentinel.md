## 2025-05-15 - HTTP Request Smuggling via Header Whitespace
**Vulnerability:** potential HTTP Request Smuggling (HRS) due to permissive header parsing that allowed whitespace between the field name and the colon.
**Learning:** RFC 7230 §3.2.4 explicitly forbids whitespace before the colon in a header field. Allowing it can lead to interpretation differences between the openhost proxy and its upstream servers, which is a classic HRS vector.
**Prevention:** Header names must be extracted exactly as they appear in the request head without trimming; rely on `http::HeaderName::from_bytes` to enforce RFC compliance on the raw name.
