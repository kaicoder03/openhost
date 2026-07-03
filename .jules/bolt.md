## 2026-07-03 - [Optimize PKARR answer fragment reassembly]
**Learning:** PKARR answer fragmentation reassembly was previously O(N²) because it performed a full resource record scan for each expected fragment index. By switching to a single-pass scan over all records and using a bucket sort (array of 256 Options), complexity is reduced to O(N).
**Action:** Always prefer single-pass scans with bucket-sorting or hash-maps when reassembling indexed protocol fragments from an unordered set of records.
