## 2026-04-26 - [O(1) Frame Decoding with BytesMut]
**Learning:** Using `Vec<u8>` with `drain(..n)` for stream decoding is an O(N) operation that causes redundant memory shifts. In high-frequency framing paths like WebRTC data channels, this becomes a measurable bottleneck.
**Action:** Always prefer `bytes::BytesMut` for inbound buffers. Use `advance(n)` for O(1) consumption and initialize with a capacity hint (e.g., 64 KiB) to avoid early reallocations during HTTP head accumulation.
