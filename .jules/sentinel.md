## 2025-05-15 - Strict HTTP Header Parsing
**Vulnerability:** HTTP Request Smuggling / Header Injection via lenient parsing.
**Learning:** Leniently trimming whitespace before colons and allowing obsolete line folding (OBS-fold) can lead to desynchronization between proxies, potentially allowing an attacker to smuggle a second request or inject headers.
**Prevention:** Strictly adhere to RFC 7230 §3.2.4: reject headers with whitespace between field-name and colon, and reject lines starting with whitespace (OBS-fold).
