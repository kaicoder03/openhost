## 2025-09-18 - Optimized HTTP Forwarder Hot Path

**Learning:** Manual string construction and HeaderValue pre-parsing in high-frequency request paths yield significant performance gains by avoiding redundant formatting, validation, and intermediate allocations.

**Action:** Prefer `String::with_capacity` and `push_str` over `format!` for URI/status-line construction, and store frequently reused headers as `HeaderValue` instead of `String`.
