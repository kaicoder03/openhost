## 2026-07-20 - O(N) single-pass bucket-sort fragment reassembly optimization
**Learning:** Fragmented Pkarr packet records can cause O(N^2) CPU overhead if we probe each index sequentially with a full linear scan over all resource records in the packet. We can optimize this by doing a single pass over `all_resource_records()` and bucket-sorting the extracted indexes.
**Action:** Use single-pass loops over resource records with index-based array lookups to avoid sequential DNS record probes.
