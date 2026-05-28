## 2025-05-14 - Harden HTTP Header Parsing
**Vulnerability:** Memory Exhaustion DoS and HTTP Request Smuggling.
**Learning:** Hand-rolled HTTP parsers must strictly follow RFC 7230 §3.2.4 (reject OBS-fold and whitespace before colon) to prevent smuggling, and enforce explicit size limits on headers before buffering to prevent DoS.
**Prevention:** Always bound inbound frame sizes and use strict byte-level checks for protocol grammar.
