## 2025-05-15 - Strict HTTP Forwarding Sanatization
**Vulnerability:** Potential HTTP Request Smuggling and IP Spoofing in the localhost forwarder.
**Learning:** The initial `parse_request_head` implementation was too permissive, allowing whitespace before colons and obsolete line folding (`obs-fold`), both of which are exploited in smuggling attacks. Additionally, common CDN provenance headers like `true-client-ip` and `cf-connecting-ip` were not being stripped, allowing clients to potentially spoof their origin IP to upstream services.
**Prevention:** Always use strict RFC 7230 parsing for manual HTTP reconstruction. In Rust, ensure `HeaderMap` insertions from untrusted sources are preceded by explicit validation against `obs-fold` and whitespace-prefixed/suffixed header names.
