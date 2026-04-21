## 2025-05-14 - [O(N) to O(1) buffer advancement]
**Learning:** Using `Vec::drain(..n)` for inbound stream buffering is an $O(N)$ operation because it shifts all remaining bytes to the front of the vector. For high-frequency message loops like WebRTC data channels, this creates unnecessary CPU pressure.
**Action:** Use `bytes::BytesMut` and `buf.advance(n)$ which is $O(1)$ by adjusting the internal view of the buffer.

## 2025-05-14 - [Avoiding temporary String allocations in HTTP headers]
**Learning:** Using `format!(...).as_bytes()` to build HTTP header lines creates a temporary `String` allocation on every call.
**Action:** Use the `write!` macro directly into a pre-allocated `Vec<u8>$ buffer (which implements `std::io::Write`) to avoid the intermediate allocation.
