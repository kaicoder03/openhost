# Bolt's Journal

## 2026-07-20 - O(N) single-pass bucket-sort fragment reassembly optimization
**Learning:** Walking the packet's resource records list `chunk_total` times yields an O(N^2) complexity in the worst case (with 255 fragments), which can be optimized to O(N) via a single-pass scan with bucket sorting.
**Action:** Always prefer single-pass filtering and sorting for packet-record processing over multi-pass lookups.
