## 2025-05-15 - [DNS Label Optimization]
**Learning:** `pkarr::simple_dns::Name::get_labels()` returns a slice of `Label` objects. The first label (the leftmost part of the DNS name) can be accessed via `.first()`, and its raw bytes can be accessed via `.as_ref()`. This allows checking prefixes and parsing numeric suffixes without calling `.to_string()`, avoiding unnecessary heap allocations during packet scans.

**Action:** Prefer `get_labels().first()` for zero-allocation DNS name inspections in performance-critical paths like Pkarr packet processing.

## 2025-05-15 - [Rust 1.85+ Array Initialization]
**Learning:** Initializing large arrays of non-`Copy` types (like `[Option<String>; 256]`) requires the use of nested inline `const` blocks to satisfy compile-time evaluation: `const { [const { None }; 256] }`.

**Action:** Use this pattern for large fixed-size buckets or caches when targeting Rust 1.85+.
