## 2026-07-08 - String optimization in URI construction
**Learning:** `http::uri::Authority` does not implement `len()`, requiring a call to `as_str()` before measuring length or pushing to a `String`. Consolidating multiple `format!` calls into a single `String::with_capacity` block significantly reduces allocation churn in request hot-paths.
**Action:** When building URIs or headers, pre-calculate capacity and use `push_str` to avoid `format!` overhead. Always check for `.as_str()` on `http` crate types.
