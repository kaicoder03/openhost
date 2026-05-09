## 2025-05-15 - Reduce heap allocations in HTTP forwarder
**Learning:** Returning `&str` from a parser instead of `String` significantly reduces heap churn in the request hot path. Additionally, using `write!` into a pre-allocated `Vec<u8>` is more efficient than `format!` as it avoids intermediate `String` allocations.
**Action:** Always look for opportunities to return references to input buffers when parsing, and prioritize direct buffer encoding over string formatting.
