## 2026-07-20 - [O(N) Single-Pass Bucket-Sort Fragment Reassembly]
**Learning:** Avoided multiple O(N) passes of resource records when reassembling fragmented DNS packets. Instead of iterating up to `chunk_total` times, we can perform a single pass over all resource records in the packet, matching and bucket-sorting fragments by their numeric `-<idx>` suffix into a stack-allocated array of size 256. This converts an O(N^2) path into O(N).
**Action:** Use a stack-allocated array `[Option<DecodedFragment>; 256]` initialized via `const NONE` to avoid heap allocations and trait bounds. Extract the first label of resource record names using `.get_labels().first()` to handle zone suffixes robustly.

## 2026-07-28 - [Forwarding URL and String Optimizations]
**Learning:** Found unnecessary string allocations and formatting macro overhead in HTTP response path.
**Action:** Optimize forwarding URL construction using `http::Uri::builder()`, zero-allocation `&str` request-path borrowing, and `std::borrow::Cow` path normalization.
