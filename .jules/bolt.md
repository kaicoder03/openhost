# Bolt's Journal

## 2026-07-28 - O(N) single-pass bucket-sort fragment reassembly optimization
**Learning:** In `decode_answer_fragments_from_packet`, probing each fragment index by performing `collect_single_txt` (which iterates over all records and does string conversion on names) repeatedly is $O(total \times N)$ and causes multiple string allocations per resource record.
**Action:** Optimize fragment reassembly to perform a single pass over the records, parse indexes into a stack-allocated bucket array, and validate/concatenate fragments sequentially in $O(N)$ time.
