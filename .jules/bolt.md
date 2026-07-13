## 2026-07-09 - Optimize HTTP forwarder hot paths

**Learning:** HTTP header parsing and string formatting in the request/response hot path can be optimized by pre-parsing static values and using the `write!` macro for direct buffer manipulation. Specifically, storing a `HeaderValue` instead of a `String` avoids validation overhead per request, and `HeaderValue::from(u64)` is faster than `from_str(&len.to_string())`.

**Action:** Always check if dynamic strings used in headers can be pre-parsed into `HeaderValue` during initialization, and prefer `write!` over `format!` when building byte buffers.
