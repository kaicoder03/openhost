## 2026-06-15 - [HTTP Header Hardening]
**Vulnerability:** HTTP Request Smuggling and Spoofing via provenance headers.
**Learning:** Legacy HTTP parsers often allow whitespace before colons or obsolete line folding, which can be exploited for smuggling. Additionally, many upstream services trust non-standard provenance headers like 'true-client-ip'.
**Prevention:** Strictly adhere to RFC 7230 §3.2.4 by rejecting malformed headers early and maintain a comprehensive blocklist of provenance headers.
