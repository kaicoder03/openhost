## 2025-05-14 - HTTP Head Parsing and Encoding Optimizations
**Learning:** `format!` into `Vec::extend_from_slice` is an easy-to-spot allocation bottleneck in request/response hot paths; replacing with `write!` (requiring `std::io::Write`) is a zero-cost fix. Returning `&str` from parsers instead of `String` eliminates per-request heap churn.
**Action:** Always check HTTP header parsing and encoding logic for `format!` or `to_string()` calls on data that is already available in the buffer or could be written directly.
