## 2025-05-15 - [O(1) Inbound Frame Buffer Consumption]
**Learning:** Using `Vec::drain(..n)` for buffer consumption in a network loop is $O(N)$ per operation, leading to $O(N^2)$ overall complexity as bytes are shifted forward. `bytes::BytesMut` with the `Buf` trait's `advance(n)` method provides an $O(1)$ alternative that avoids these redundant copies.
**Action:** Always prefer `BytesMut` and `advance()` for inbound stream buffering in Rust networking code.
