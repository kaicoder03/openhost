## 2026-07-09 - Strict RFC 7230 Header Parsing
**Vulnerability:** Hand-rolled HTTP/1.1 parser in `forward.rs` was trimming whitespace from header names before validation and failing to trim trailing whitespace from values.
**Learning:** Trimming header names can mask request smuggling vulnerabilities where intermediaries (like proxies) have different parsing tolerances. RFC 7230 §3.2.4 explicitly forbids whitespace between the field name and the colon.
**Prevention:** Rely on strict validation libraries (like the `http` crate's `HeaderName::from_bytes`) without pre-processing the input strings. Always trim both leading and trailing Optional WhiteSpace (OWS) from header values using `.trim_matches([' ', '\t'])` to align with the spec.
