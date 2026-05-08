## 2025-05-14 - Optimized Answer Fragment Reassembly
**Learning:** Reassembling fragmented answers by probing for each index resulted in O(N*M) complexity. A single pass over all resource records reduces this to O(M). DNS names in `simple-dns` (used by `pkarr`) can be absolute and are case-insensitive, so name matching must be robust against trailing dots and casing.
**Action:** Use a single pass and bucket-sorting for protocol reassembly tasks involving multiple resource records. Ensure name matching handles absolute names and casing correctly.
