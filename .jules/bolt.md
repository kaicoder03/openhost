## 2025-05-14 - Optimized Answer Fragment Reassembly
**Learning:** `SignedPacket::resource_records(name)` performs a linear scan of all records. Repeatedly calling it for $M$ fragments results in $O(N \times M)$ complexity. Using `all_resource_records()` allows for a single-pass $O(N)$ collection.
**Action:** Use `all_resource_records()` and a single pass when reassembling fragmented records from a Pkarr packet. Inspect the first label of the record name to match local names, as the iterator returns fully-qualified names including the zone.
