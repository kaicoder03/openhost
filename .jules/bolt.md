## 2026-06-15 - O(1) Buffer Consumption with BytesMut
**Learning:** Using `Vec<u8>` with `drain(..consumed)` for inbound network buffers introduces an O(N) penalty on every frame decode, as remaining bytes must be shifted to the front of the allocation. While negligible for tiny pings, this becomes a bottleneck for large HTTP bodies or high-throughput streams.
**Action:** Use `BytesMut` from the `bytes` crate for all stream-based inbound buffers. Use `.put_slice()` for appending and `.advance()` for O(1) consumption.
