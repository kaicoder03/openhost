## 2026-05-31 - [Optimized DNS Fragment Reassembly]
**Learning:** Reassembling DNS fragments by repeated probes with `packet.resource_records(name)` is O(N*M). A single pass over `all_resource_records()` with a `BTreeMap` is much more efficient for fragmented records.
**Action:** Always prefer a single pass over packet records when reassembling multiple related labels.
