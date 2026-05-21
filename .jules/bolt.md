## 2025-05-14 - [Optimize HTTP forwarder allocations]
**Learning:** Manual string construction with `String::with_capacity` and `push_str` is significantly more efficient than `format!` in hot paths as it avoids runtime format string parsing and multiple intermediate allocations.
**Action:** Prefer `write!` into a pre-allocated `Vec<u8>` or manual `String` building in high-frequency paths like HTTP header parsing and response encoding.
