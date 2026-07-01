
## 2026-07-01 - [O(N) Answer Reassembly]
**Learning:** Pkarr answer reassembly was O(N^2) due to repeated resource record scanning. A single-pass bucket sort using the numeric label suffix significantly improves efficiency, especially for large numbers of fragments.
**Action:** Use single-pass iterations and zero-allocation label matching (`get_labels().first()`) for reassembly patterns.
