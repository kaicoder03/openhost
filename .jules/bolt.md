## 2025-05-14 - [Optimize HTTP response head encoding]
**Learning:** High-level string formatting (`format!`) and intermediate string allocations (`to_string()`) in the core request/response path add measurable latency. `HeaderValue::from(u64)` and manual byte-slice extension are significantly faster.
**Action:** Prefer direct byte-level operations and efficient library constructors over high-level formatting macros in performance-critical serialization paths.
