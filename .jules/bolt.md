## 2025-05-14 - Transition to Bytes/BytesMut for Frame Processing
**Learning:** Using `Vec<u8>` with `drain(..n)` for network buffers results in O(N) performance due to byte shifting. Moving to `bytes::BytesMut` and `advance(n)` provides O(1) consumption. Furthermore, using `bytes::Bytes` for frame payloads enables zero-copy slicing from the inbound buffer, significantly reducing allocations in high-throughput data channels.
**Action:** Use `BytesMut` for all inbound protocol buffers and `Bytes` for immutable data chunks passed between layers.
