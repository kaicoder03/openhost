## 2025-05-15 - Array initialization of non-Copy types in Rust 1.85+
**Learning:** Initializing large arrays of non-Copy types (like `Option<String>`) requires nested inline `const` blocks: `const { [const { None }; 256] }`. The outer block allows non-Copy elements, and the inner block is needed for `None` even though it is a constant.
**Action:** Use nested `const` blocks for fixed-size array buffers of non-Copy types to avoid trait bound errors.
