## 2026-07-20 - O(N) single-pass bucket-sort fragment reassembly optimization
**Learning:** Initial list was sorting fragment records which resulted in O(N log N) complexity, optimized with stack-allocated array for bucket-sorting fragments.
**Action:** Use stack-allocated/fixed-size array buckets when range of indices is small and known.

## 2026-07-28 - Forwarding URL and string optimization
**Learning:** Rebuilding URI or string manipulation per-request is slow. Pre-parsing HeaderValue and using Cow reduces allocation.
**Action:** Use Cow and pre-parsed http headers when possible.
