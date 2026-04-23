## 2025-03-24 - HTTP Request Smuggling and Header Injection Hardening
**Vulnerability:** The HTTP/1.1 request parser was overly permissive, accepting headers with whitespace before the colon and obsolete line folding, and failing to dynamically strip headers listed in the `Connection` field.
**Learning:** Hand-rolled HTTP parsers often miss RFC 7230 edge cases that proxies are strictly required to reject to prevent smuggling. SSRF defenses must also account for dynamic hop-by-hop headers to be robust.
**Prevention:** Always validate header syntax against RFC 7230 §3.2.4 (no whitespace before colon, no line folding) and implement dynamic header stripping via `Connection` as a standard proxy defense.
