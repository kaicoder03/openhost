## 2025-05-15 - BytesMut Panic Risk with put_slice
**Learning:** Switching from `Vec<u8>` to `bytes::BytesMut` for performance (replacing $O(N)$ `drain` with $O(1)$ `advance`) introduces a panic risk if using `put_slice` without explicit `reserve`. `Vec::extend_from_slice` automatically grows, but `BytesMut::put_slice` panics if capacity is insufficient.
**Action:** Use `BytesMut::extend_from_slice` (which handles reservation automatically) instead of `put_slice` when the input size is not strictly bounded, or call `reserve` manually.
