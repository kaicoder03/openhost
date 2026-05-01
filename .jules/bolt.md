## 2025-05-14 - BytesMut optimization for inbound buffers
**Learning:** Replacing `Vec<u8>::drain(..n)` with `BytesMut::advance(n)` shifts complexity from O(N) to O(1) by using pointer manipulation instead of shifting memory. `BytesMut::extend_from_slice` is an inherent method and doesn't require importing the `BufMut` trait, while `advance` requires the `Buf` trait.
**Action:** Use `BytesMut` for all stream-like inbound buffers. Always import `bytes::Buf` when using `advance`.
