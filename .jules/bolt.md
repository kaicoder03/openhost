## 2025-05-14 - [Optimize answer fragment reassembly]
**Learning:** Fragment reassembly via repeated `packet.resource_records(name)` calls leads to $O(N \times M)$ complexity, which becomes pathological as the number of answers and fragments per answer grows. `packet.all_resource_records()` allows for a single-pass $O(N)$ reassembly using bucket sorting.
**Action:** Always prefer a single pass over `all_resource_records()` when reassembling multi-fragment records or scanning for multiple client hashes in one packet.
