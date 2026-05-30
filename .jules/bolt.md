## 2025-05-14 - [O(N) to O(1) buffer consumption with BytesMut]
**Learning:** Using `Vec::drain(..n)` for inbound network buffers is a hidden performance killer in high-throughput data channels. In Rust, `Vec::drain` is $O(N)$ because it shifts all remaining elements.
**Action:** Always prefer `bytes::BytesMut` for inbound buffers. Use `advance(n)` for $O(1)$ consumption and `split_to(n).freeze()` for zero-copy payload extraction.
