## 2025-05-22 - [Buffer Management Optimization]
**Learning:** In Rust networking code, using `Vec<u8>` with `drain(..n)` for prefix consumption is an O(N) operation, which can become a bottleneck as buffer sizes grow or frame frequency increases. Switching to `bytes::BytesMut` with `advance(n)` reduces this to O(1).
**Action:** Always prefer `BytesMut` and the `Buf` trait for inbound stream buffering and frame decoding loops.
