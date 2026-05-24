## 2025-05-14 - Optimized DNS Fragment Reassembly
**Learning:** Reassembling fragmented records (like openhost answers) by probing each index with `packet.resource_records(name)` leads to O(N*M) complexity. Each probe triggers full DNS label serialization and string comparisons. Using `packet.all_resource_records()` allows for a single-pass O(N) scan.
**Action:** Use `all_resource_records()` for any task requiring multiple lookups in the same DNS packet. Combine with byte-level `starts_with(b"_")` and `eq_ignore_ascii_case` on `Label` bytes for zero-allocation filtering.
