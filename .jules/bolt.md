## 2026-07-08 - [Optimized PKARR fragment reassembly]
**Learning:** (N^2)$ reassembly in PKARR answer decoding was caused by repeated linear probes for each fragment index. Using a single pass with bucket sorting reduces this to (N)$.
**Action:** Always look for "TODO(perf)" markers in hand-rolled reassembly or parsing logic; they often highlight (N^2)$ bottlenecks that can be solved with single-pass bucket sorting or hash lookups.
