## 2025-05-14 - [Bolt: optimize frame buffering and HTTP encoding]
**Learning:** Replacing O(N) `Vec::drain` with O(1) `BytesMut::advance` significantly improves performance in data channel frame processing. Direct `write!` to pre-allocated vectors and `HeaderValue::from(u64)` eliminate unnecessary string allocations in the localhost forwarder. Using `FRAME_V2_HEADER_LEN` constant ensures consistent pre-allocation for v2 frames.
**Action:** Always prefer `BytesMut` for inbound buffering and direct `write!` for byte-oriented header construction in high-frequency networking paths.
