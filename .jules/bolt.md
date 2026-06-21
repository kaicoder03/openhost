## 2025-05-15 - [Optimize answer fragment reassembly]
**Learning:** The previous (N \cdot M)$ implementation of answer fragment reassembly was walking the entire resource record list for every expected fragment. By switching to a single-pass bucket sort, we achieved (M)$ complexity. Fixed-length z-base-32 hashes in DNS labels allow for reliable prefix stripping and index parsing.
**Action:** Always look for (N^2)$ patterns in packet/record scanning and consider single-pass collection with indexing or bucket-sorting.
