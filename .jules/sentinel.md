# Sentinel Security Journal

This is a record of critical security learnings for the openhost codebase.

## 2026-07-28 - HTTP Request Smuggling via Lenient Header Parsing (RFC 7230 §3.2.4)
**Vulnerability:** The localhost HTTP request forwarder parsed header field names leniently using `.trim()`, which allowed request headers to have trailing or leading whitespace around field names (e.g., `Host : example.com`). This violates RFC 7230 §3.2.4 and can lead to HTTP Request Smuggling where a downstream/upstream proxy parses headers differently.
**Learning:** Permissive string-trimming during parsing hides malformed input and introduces parsing inconsistencies between hops, which is the root cause of request smuggling.
**Prevention:** Never use a generic `.trim()` on header names during HTTP parsing. Explicitly validate that header names contain absolutely no leading or trailing whitespace (SP/HTAB) surrounding the name or before the colon, and reject invalid requests immediately.
