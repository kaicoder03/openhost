## 2026-07-20 - [O(N) single-pass bucket-sort fragment reassembly optimization]
**Learning:** Sequential probing on packet resource records using `collect_single_txt` scales quadratically O(N * T) and wastes CPU cycles.
**Action:** Consolidate fragment gathering into a single O(N) pass over all records, and sort them into a stack-allocated bucket array `[Option<T>; 256]` to bypass extra heap allocations and bound checks.
