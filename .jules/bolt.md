## 2025-05-14 - Optimized Pkarr Answer Reassembly and DNS TXT Codec

**Learning:** The previous implementation of Pkarr answer reassembly used O(N*M) complexity by performing repeated probes for each fragment index. By switching to a single pass over all resource records in the SignedPacket and using zero-allocation label checks, we can achieve O(M + N log N) complexity. Additionally, pre-calculating string capacity for TXT character-string joining and avoiding intermediate Vec<String> allocations in TXT construction significantly reduces heap churn.

**Action:** Use `packet.all_resource_records()` for single-pass scanning of Pkarr packets. Prefer zero-allocation byte-level checks on DNS labels via `rr.name.iter().next().as_ref()` before performing full string normalization or parsing. Always pre-allocate collection buffers when the total size can be derived from the input.
