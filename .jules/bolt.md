## 2026-04-19 - [Framing and Buffer Optimizations]
**Learning:** Found O(N) performance bottlenecks in inbound buffer handling using `Vec::drain` and redundant memory allocations in outbound framing. HTTP header encoding was also using inefficient `format!` calls.
**Action:** Use `BytesMut::advance` for O(1) buffer consumption, refactor framing to use `&[u8]` slices instead of owned `Frame` objects to eliminate redundant copies, and use `write!` directly to pre-allocated buffers for header encoding.
