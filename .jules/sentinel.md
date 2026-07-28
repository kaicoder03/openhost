## 2026-07-28 - [HTTP Request Smuggling Vulnerability via Lenient Header Parsing]
**Vulnerability:** HTTP Request Smuggling due to lenient parsing of header names containing whitespace (space or tab) preceding or surrounding the colon separator, in violation of RFC 7230 §3.2.4.
**Learning:** Leniently trimming whitespace before/around header names allows proxy/server differences in parsing, which enables attackers to smuggle requests through intermediate HTTP hops. Strictly rejecting requests with whitespace surrounding the header name prevents parsing discrepancies.
**Prevention:** Always validate that there is no whitespace before the colon separator on any HTTP header line, and strictly reject any malformed lines immediately.
