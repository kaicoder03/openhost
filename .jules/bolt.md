
## 2025-05-22 - [Optimizing HTTP head encoding]
**Learning:** Using 'format!' to generate HTTP status lines and header values in a loop introduces unnecessary intermediate 'String' allocations. These can be avoided by writing directly into a pre-allocated 'Vec<u8>' using the 'write!' macro. Similarly, 'HeaderValue::from(u64)' is more efficient than 'HeaderValue::from_str(&len.to_string())'.
**Action:** Always prefer 'write!(buf, ...)' over 'buf.extend_from_slice(format!(...).as_bytes())' when working with byte buffers in hot paths.
