## 2025-05-22 - [Optimizing Pkarr Fragment Reassembly]
**Learning:** Fragmented Pkarr answer records were previously reassembled using repeated linear scans over the DNS packet for each expected index. This resulted in (N \cdot M)$ complexity.
**Action:** Use `packet.all_resource_records()` to scan the packet once, collect matching fragments, and then sort/validate. This reduces complexity to (N + M \log M)$ and eliminates redundant string allocations by pre-calculating capacity.
