## 2026-05-17 - Optimize DNS fragment reassembly
**Learning:** Replacing multi-pass probes with a single O(M) pass over resource records significantly improves reassembly performance, especially when using zero-allocation checks on DNS labels and bucket-sorting into pre-allocated vectors.
**Action:** Use single-pass iterations and bucket-sorting for fragmented resource reassembly to avoid $O(N \times M)$ overhead.
