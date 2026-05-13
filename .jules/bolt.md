## 2025-05-14 - Answer Fragment Reassembly O(N*M) Bottleneck
**Learning:** Reassembling fragmented DNS records by calling `resource_records(name)` in a loop results in O(N*M) complexity, where N is the total records in the packet and M is the number of fragments. The `pkarr` crate's `SignedPacket` provides `all_resource_records()` which allows for a single-pass O(N) reassembly using bucket-sorting.
**Action:** Always prefer single-pass iteration over `all_resource_records()` when reassembling multi-record items from a `SignedPacket`.
