## 2026-06-04 - Optimize DNS answer fragment reassembly
**Learning:** Reassembling fragmented DNS TXT records using multiple passes ((N \cdot M)$) is a common bottleneck when dealing with signed packets containing many records. Using a single pass over `all_resource_records()` and sorting matching fragments reduces complexity to (M + N \log N)$.
**Action:** Always prefer a single pass over resource records for reassembly tasks. Pre-calculate capacity when joining character-strings to minimize allocations.
