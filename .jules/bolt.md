## 2025-01-24 - [Optimizing DNS Fragment Reassembly]
**Learning:** `pkarr::SignedPacket::all_resource_records()` is significantly more efficient than multiple `.resource_records(name)` probes for fragmented records. However, DNS names in the underlying `simple-dns` types are fully qualified and include the packet origin.
**Action:** When scanning all resource records for specific prefixes/suffixes, always use `strip_prefix` and robustly parse components (e.g., using `.split('.').next()`) to handle the FQDN structure correctly.
