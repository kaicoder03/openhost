# Bolt's Journal

## 2026-07-20 - O(N) single-pass bucket-sort fragment reassembly optimization
**Learning:** Found that walking the packet's RR list chunk_total times is fine for 1-3 fragments but O(N^2) in pathological cases with MAX_FRAGMENT_TOTAL=255.
**Action:** Decoded answer fragments from packets can be reassembled in a single O(N) pass.

## 2026-07-28 - Forwarding URL and string optimization
**Learning:** Avoided intermediate `String` allocations by using `http::Uri::builder()`, zero-allocation `&str` request-path borrowing, and `std::borrow::Cow` path normalization.
**Action:** Use pre-parsed `HeaderValue` for host_override and write macro on a buffer directly.
