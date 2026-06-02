## 2025-05-15 - Answer Fragment Reassembly Optimization
**Learning:** O(N*M) lookups for fragmented DNS records in Pkarr packets (where N is fragment count and M is total records) can be optimized to O(M + N log N) using a single pass over all resource records combined with bucket-sorting/sorting. String allocations during TXT joining can be significant if not pre-allocated.
**Action:** Use `packet.all_resource_records()` for single-pass scanning when reassembling fragmented records. Pre-calculate buffer capacities for String and Vec operations in hot paths.
