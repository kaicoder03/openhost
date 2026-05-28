## 2026-05-28 - O(1) buffer consumption with BytesMut
**Learning:** Using `BytesMut` for inbound network buffers allows $O(1)$ consumption via `advance(n)` instead of $O(N)$ via `Vec::drain(..n)`. This reduces memory copies during frame decoding in high-throughput data channels.
**Action:** Always prefer `BytesMut` over `Vec<u8>` for streaming decoders where partial consumption is common.
