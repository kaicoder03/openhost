## 2026-04-18 - [Optimization of HTTP Header Encoding]
**Learning:** Using `format!` to construct strings that are immediately converted to bytes and appended to a buffer causes an unnecessary heap allocation and a copy.
**Action:** Use the `write!` macro directly on types that implement `std::io::Write` (like `Vec<u8>`) to avoid intermediate allocations in hot paths.
