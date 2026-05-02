## 2025-05-15 - Strict HTTP Header Parsing for Security
**Vulnerability:** HTTP Request Smuggling and DoS via oversized/malformed headers.
**Learning:** Standard HTTP parsers that use `.lines()` or lenient whitespace handling can be vulnerable to request smuggling if they don't strictly follow RFC 7230's requirements for line endings and whitespace around colons.
**Prevention:** Implement hand-rolled or strictly-configured parsers that reject bare CR/LF, obsolete line folding, and whitespace before colons, while also bounding the total size of the header block.
