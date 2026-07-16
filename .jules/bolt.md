## 2026-07-20 - [Optimizing HTTP Forwarder Allocations]
**Learning:** In performance-critical paths like an HTTP forwarder, repeated string-to-HeaderValue parsing and intermediate String allocations (e.g., via `format!`) add measurable latency. Pre-parsing configuration into `HeaderValue` and using `write!` macro on `Vec<u8>` buffers can significantly reduce this overhead. Specifically, `HeaderValue::from(u64)` avoids the string conversion/parsing path entirely for `Content-Length`.

**Action:** Always check for repeated parsing of static/config values in request hot-paths and move them to initialization. Prefer `std::io::Write` on existing buffers over `format!` for line-oriented protocols like HTTP.
