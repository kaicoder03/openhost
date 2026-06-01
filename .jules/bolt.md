## 2025-05-15 - [Efficient DNS Fragment Reassembly]
**Learning:** Reassembling fragmented DNS records using repeated probes with `resource_records(name)` leads to $O(N \cdot M)$ complexity. Using `all_resource_records()` in a single pass reduces this to $O(M + N \log N)$. Additionally, inspecting labels via `Label::as_ref()` avoids expensive string allocations in hot loops.
**Action:** Always prefer a single pass over all packet records for multi-fragment reassembly tasks. Use byte-level label checks to filter records before performing high-level decoding.
