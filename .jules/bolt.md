## 2026-05-12 - O(M) Answer Reassembly
**Learning:** In Pkarr/simple-dns packets, resource record names are case-insensitive and may be absolute (containing trailing dots). Robust label parsing (e.g., `name.strip_prefix(base).split('.').next()`) is required to reliably extract numeric indices from labels.
**Action:** Always pre-calculate comparison strings outside loops and use fast-path prefix checks (`starts_with`) to avoid expensive string allocations for irrelevant records. Use pre-calculated capacities for `Vec::with_capacity` when the final size is known.
