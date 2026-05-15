## 2025-01-24 - Strict RFC 7230 Header Parsing
**Vulnerability:** HTTP Request Smuggling and Cache Poisoning via lenient header parsing.
**Learning:** The previous hand-rolled parser accepted OBS-fold (line folding) and whitespace between the header name and colon. These ambiguities allow an attacker to craft requests that are interpreted differently by the openhost daemon and the upstream HTTP service, leading to request smuggling.
**Prevention:** Strictly enforce RFC 7230 §3.2.4 by rejecting any request containing OBS-fold or whitespace before the header colon. Ensure header values are fully trimmed of OWS (SP/HTAB) to maintain consistent normalization.
