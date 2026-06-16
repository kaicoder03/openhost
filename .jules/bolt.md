# Bolt's Journal - Critical Learnings Only

## 2025-05-15 - Initializing Journal
**Learning:** Initialized journal for the openhost project.
**Action:** Keep hunting for performance bottlenecks.

## 2025-05-15 - O(1) Inbound Buffer Management
**Learning:** Inbound network buffers using `Vec<u8>::drain(..n)` perform in $O(N)$ due to memory shifting, which becomes a bottleneck in high-throughput data channels. Replacing them with `bytes::BytesMut` and using `.advance(n)` provides $O(1)$ consumption.
**Action:** Always prefer `BytesMut` for protocol decoders and stream-processing buffers in performance-critical paths.
