## 2025-09-19 - Strict HTTP Header Parsing
**Vulnerability:** HTTP Request Smuggling / Response Splitting via permissive header parsing (accepting obs-fold and whitespace before colons).
**Learning:** Hand-rolled HTTP parsers often miss RFC 7230 edge cases like `obs-fold` (obsolete line folding) and "whitespace before colon" which are common vectors for request smuggling.
**Prevention:** Always follow RFC 7230 §3.2.4 strictly: reject any header line starting with whitespace and ensure no whitespace exists between the field name and the colon.
