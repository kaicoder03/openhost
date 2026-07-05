## 2025-03-04 - Strict RFC 7230 Compliance in HTTP Forwarder
**Vulnerability:** HTTP Request Smuggling risk due to lenient header parsing. Trimming whitespace from header names before validation allowed whitespace between the name and colon, which is forbidden by RFC 7230 §3.2.4.
**Learning:** Hand-rolled HTTP parsers must be extremely strict about whitespace. Lenience in parsing (like ignoring OWS before a colon) can lead to different interpretations of the same request by different proxies/servers.
**Prevention:** Never trim header names manually before passing them to a strict validator like `http::HeaderName`. Ensure both ends of header values are trimmed of OWS (SP and HTAB) per RFC 7230 §3.2.
