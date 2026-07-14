## 2026-07-09 - Optimized HTTP Forwarding Path
**Learning:** Pre-parsing frequent header values (like `Host` overrides) into `http::HeaderValue` and using `HeaderValue::from(u64)` for `Content-Length` significantly reduces per-request allocations. Using `write!` directly on `Vec<u8>` buffers for status lines further eliminates intermediate `String` allocations.
**Action:** Always check if constant or configuration-driven header values can be pre-parsed during initialization, and prefer `write!` over `format!` for buffer construction in performance-critical paths.
