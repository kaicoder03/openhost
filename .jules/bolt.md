## 2026-07-20 - [O(N) single-pass bucket-sort fragment reassembly optimization]
**Learning:** The fragment reassembly originally performed nested loop lookups, walking the entire DNS record list `chunk_total` times (O(N^2)). By switching to a single-pass bucket sort, reassembly complexity drops to O(N).
**Action:** Use single-pass iterations and array/slice buckets for parsing numbered/fragmented records.
