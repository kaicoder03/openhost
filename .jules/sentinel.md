## 2025-05-15 - HTTP Header Parsing Strictness (RFC 7230)
**Vulnerability:** HTTP Request Smuggling / IP Spoofing
**Learning:** Proxies must strictly enforce RFC 7230 §3.2.4 by rejecting whitespace before colons and obsolete line folding (obs-fold) to prevent desynchronization with upstreams. Additionally, provenance headers like `true-client-ip` and `cf-connecting-ip` must be explicitly stripped to prevent IP spoofing when behind CDNs.
**Prevention:** Implement strict header validation in the initial parsing stage and maintain a comprehensive allowlist/denylist for provenance headers.
