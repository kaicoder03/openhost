## 2026-04-23 - [O(1) Frame Buffering]
**Learning:** Using `Vec::drain(..consumed)` for inbound frame buffering in `openhost-daemon` and `openhost-client` was an O(N) operation, shifting the entire remaining buffer on every frame.
**Action:** Use `bytes::BytesMut` and `buf.advance(consumed)` for O(1) buffer management in all streaming/framing code.
