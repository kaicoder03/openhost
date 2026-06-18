## 2025-05-22 - HTTP Request Smuggling Prevention
**Vulnerability:** HTTP Request Smuggling due to lax RFC 7230 compliance in hand-rolled parser.
**Learning:** Hand-rolled HTTP parsers often miss security-critical edge cases like whitespace before colons or obsolete line folding (obs-fold) that standard libraries handle. These can be exploited for request smuggling.
**Prevention:** Strictly implement RFC constraints in custom parsers and include negative tests for forbidden whitespace and line-folding patterns.
