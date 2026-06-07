## 2025-05-15 - Strict HTTP Header Parsing and Sanitization
**Vulnerability:** HTTP request smuggling and DoS risks via malformed or oversized headers in the custom forwarder.
**Learning:** Custom HTTP forwarders must strictly adhere to RFC 7230. Static hop-by-hop header lists are insufficient; the `Connection` header must be parsed to identify dynamic hop-by-hop headers. Additionally, allowing whitespace between a header name and colon can lead to interpretation differences between the daemon and upstream services.
**Prevention:** Centralize header sanitization logic. Use a dedicated helper like `strip_hop_by_hop_headers` that handles both static and dynamic lists. Enforce explicit security limits (e.g., `MAX_HEAD_BYTES`) at the earliest possible entry point.
