
## 2026-06-26 - [Optimizing HTTP Response Head Encoding]
**Learning:** The `format!` macro and `usize::to_string()` are convenient but cause unnecessary `String` allocations. In high-frequency paths like HTTP response head encoding, these allocations add up. `http::HeaderValue` provides an optimized `From<u64>` implementation that avoids intermediate strings.
**Action:** Prefer manual `extend_from_slice` with pre-existing byte slices (like `status.as_str().as_bytes()`) and optimized type conversions over `format!` for hot-path buffer construction.
