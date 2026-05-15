## 2026-05-15 - O(1) Buffer Consumption with BytesMut
**Learning:** Using `Vec::drain(..n)` for inbound frame buffering in `openhost-daemon` and `openhost-client` resulted in (N)$ data shifting on every decoded frame.
**Action:** Transitioned inbound buffers to `bytes::BytesMut`. By using `buf.advance(n)` (via the `Buf` trait), consumption is now (1)$, which is significantly more efficient for high-throughput data channels.
