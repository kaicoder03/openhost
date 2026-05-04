## 2025-05-15 - Hardening HTTP Parser against DoS and Smuggling
**Vulnerability:** The HTTP forwarder accepted request heads up to 16 MiB (frame cap) and used a permissive hand-rolled parser that ignored RFC 7230's prohibitions on whitespace before colons and bare line terminators.
**Learning:** Permissive custom parsers are a primary vector for Request Smuggling and DoS. Bounding memory allocation early and strictly enforcing RFC-mandated delimiters is essential for proxies.
**Prevention:** Always bound the size of unparsed buffers before processing. Use strict matching for line delimiters (rejecting bare CR/LF) and enforce field-name hygiene (no OWS before colon) as required by RFC 7230 §3.2.4.
