## 2026-07-20 - O(N) single-pass bucket-sort fragment reassembly optimization
**Learning:** Using an O(N) single-pass bucket sort for fragment reassembly avoids the O(N log N) overhead of sorting or allocating dynamic maps.
**Action:** Always consider array/slice indexing for fixed-bound sort/reassembly before sorting vectors.
