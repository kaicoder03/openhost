## 2026-06-24 - [Optimize answer fragment reassembly]
**Learning:** Reassembling fragmented DNS TXT records by repeatedly probing for specific names using `packet.resource_records(name)` leads to (N \cdot M)$ complexity, where $ is the number of records and $ is the number of fragments.
**Action:** Use a single pass over all resource records with `packet.all_resource_records()` and a bucket sort to achieve (N)$ complexity for reassembly.
