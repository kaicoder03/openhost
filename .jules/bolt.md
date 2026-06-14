## 2026-06-14 - Answer Fragment Reassembly Complexity
**Learning:** Reassembling fragmented Pkarr records using per-index probes resulted in O(N*M) complexity, which becomes significant as the number of fragments (M) and total records in the packet (N) grows. The `pkarr` crate's `SignedPacket::all_resource_records()` allows for a single O(N) pass to collect all fragments into a bucket-sorted vector.
**Action:** Always prefer single-pass collection over multiple name-based lookups when processing multiple related records in a DNS packet.
