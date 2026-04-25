## 2026-04-25 - HTTP Smuggling and Header Injection
**Vulnerability:** The daemon's HTTP forwarder was susceptible to request smuggling and header injection because it didn't dynamically strip headers listed in the 'Connection' field (RFC 7230 §6.1), allowed whitespace in header names, and didn't trim trailing OWS from header values.
**Learning:** Custom HTTP parsers and sanitizers must strictly follow RFC 7230, especially regarding hop-by-hop header management and whitespace handling, to avoid inconsistent interpretation by upstream servers.
**Prevention:** Always use established HTTP libraries for parsing when possible, or implement a "deny-by-default" approach for hop-by-hop headers that includes dynamic stripping based on the 'Connection' header.
