
## 2025-05-22 - Strict HTTP/1.1 Header Parsing (RFC 7230)
**Vulnerability:** HTTP Request Smuggling/Splitting risk due to loose header parsing (accepting whitespace before colons and obsolete line folding).
**Learning:** Hand-rolled HTTP parsers in `openhost-daemon` were vulnerable to classic smuggling patterns by being too permissive with Optional White Space (OWS) and OBS-fold.
**Prevention:** Strictly enforce RFC 7230 §3.2.4: reject whitespace between header name and colon, reject lines starting with whitespace (OBS-fold), and trim both leading and trailing OWS from values.
