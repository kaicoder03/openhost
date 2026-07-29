# Bolt's Journal

## 2026-07-28 - Forwarding URL & string optimization
**Learning:** Reconstructing the request Uri on every forwarded HTTP/WebSocket request can be optimized by using `http::Uri::builder()` with a zero-allocation path/query construct (`std::borrow::Cow` to avoid slash prepends). Also, passing the parsed request path around as a borrowed `&str` instead of a heap-allocated `String` avoids a per-request heap allocation.
**Action:** Always prefer `Uri::builder` over whole-string formatting/parsing and use lifetimes/borrowing to avoid intermediate string allocations.
