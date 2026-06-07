## 2025-05-14 - Zero-allocation DNS label prefix checks
**Learning:** In hot loops walking pkarr/simple-dns resource records, calling `rr.name.to_string()` to check for prefixes is a significant allocation bottleneck. The `Name` type can be iterated to get `Label` objects, which implement `AsRef<[u8]>`, allowing direct byte-level prefix/suffix checks without string allocation.
**Action:** Use `rr.name.iter().next().map(|l| l.as_ref().starts_with(b"_answer-"))` instead of string-based matching for early record filtering.
