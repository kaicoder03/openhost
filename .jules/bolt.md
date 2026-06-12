## 2026-06-12 - Optimize DNS Answer Fragment Reassembly
**Learning:** DNS packet reassembly from fragments can be O(N*M) if each fragment is probed individually. Using `all_resource_records()` for a single-pass bucket-sort reduces this to O(M). Byte-level matching on `Label` objects avoids `to_string()` overhead in hot loops.
**Action:** Always prefer single-pass iteration over resource records when multiple related records (like fragments) need to be collected. Use `reserve()` on `String`/`Vec` when total capacity can be pre-calculated from record metadata.
