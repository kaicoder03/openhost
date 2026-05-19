## 2025-05-15 - Strict HTTP Header Parsing in Daemon Forwarder
**Vulnerability:** Lenient HTTP/1.1 header parsing in `openhost-daemon` allowed whitespace between header names and colons, and accepted OBS-fold (header lines starting with whitespace).
**Learning:** Hand-rolled HTTP parsers often miss RFC 7230 §3.2.4 constraints, which can be exploited for HTTP request smuggling if the upstream server has different parsing leniency.
**Prevention:** Always validate header names strictly: they must not end with whitespace, and header lines must not start with whitespace (unless explicitly handling OBS-fold by normalization).
