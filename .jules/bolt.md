## 2025-05-15 - [Optimization] Answer fragment reassembly complexity reduction

**Learning:** `SignedPacket::all_resource_records()` in `pkarr` v5 returns absolute names (including the origin). When matching records that are supposed to be "under" the zone (like `_answer-*`), simple prefix matching on the whole name is insufficient if the origin is unknown or variable. The robust pattern is to iterate over labels and check the first label's prefix while verifying the total label count (e.g., `labels.count() == 2` for a single-label record plus the origin).

**Action:** Use label-level iteration and zero-allocation byte checks (`Label::as_ref()`) instead of `Name::to_string()` in hot loops to avoid redundant allocations and correctly handle absolute name matching.
