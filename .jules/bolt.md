## 2026-06-29 - [Efficient Array Initialization in Rust 1.85]
**Learning:** Initializing large arrays of non-Copy types (like Option<DecodedFragment>) efficiently in the project's Rust 1.85 environment can be done using inline const blocks: const { [const { None }; 256] }. This avoids the need for macros or runtime initialization loops.
**Action:** Use nested inline const blocks for large fixed-size array initialization of non-Copy types.

## 2026-06-29 - [Zero-Allocation DNS Label Prefix Matching]
**Learning:** Matching DNS labels in the `pkarr` crate can be done without string allocations by using `rr.name.get_labels().first().map(|l| l.as_ref())`. This provides a byte slice view of the first label, which can then be checked for prefixes.
**Action:** Prefer `Label::as_ref()` over `Label::to_string()` for name filtering in performance-critical paths.
