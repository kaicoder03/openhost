## 2025-05-15 - Optimize response head encoding
**Learning:** Using `format!` to build HTTP status lines in hot paths like the forwarder creates unnecessary intermediate `String` allocations. Since we already use a pre-allocated `Vec<u8>` with `with_capacity`, writing directly to it via the `write!` macro from `std::io::Write` is more efficient.
**Action:** Prefer `write!` over `format!` when encoding protocol headers or status lines into an existing buffer.
