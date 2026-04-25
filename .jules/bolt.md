# Bolt's Journal - Critical Performance Learnings

## 2025-03-24 - Initializing Journal
**Learning:** Starting the mission to optimize openhost.
**Action:** Follow the profiling and optimization process.

## 2025-03-24 - [Optimizing Inbound Buffering & Header Encoding]
**Learning:** Using `Vec::drain(..n)` on inbound buffers is $O(N)$ and can become a bottleneck as the buffer grows. Switching to `BytesMut` and `advance(n)` provides $O(1)$ complexity. Additionally, using `HeaderValue::from(u64)` and `write!` macro for HTTP encoding avoids redundant string allocations.
**Action:** Always prefer `BytesMut` for stream/frame buffering and use allocation-free header constructors where possible.

## 2025-03-24 - [Broken Test: real_pkarr.rs]
**Learning:** The `real_pkarr.rs` integration test is gated by a feature and easily falls out of sync when core configuration structs (like `DtlsConfig`) are updated.
**Action:** If a workspace member's tests fail after a structural change, check gated integration tests like `real_pkarr.rs` for missing fields.
