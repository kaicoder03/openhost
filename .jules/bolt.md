## 2025-05-15 - Optimizing Pkarr Fragment Reassembly
**Learning:** Reassembling fragmented DNS records by repeated probes using `packet.resource_records(name)` is $O(N \times M)$ and creates significant overhead in polling loops. Using `packet.all_resource_records()` reduces this to $O(N)$ and allows for zero-allocation label filtering.
**Action:** Always prefer single-pass iteration over resource records when processing multiple fragmented or related DNS records in a Pkarr packet.

## 2025-05-15 - DNS TXT Character-String Encoding
**Learning:** The `simple_dns::TXT` builder can be called iteratively with `with_string`. Pre-collecting chunks into a `Vec<String>` is an unnecessary $O(N)$ allocation.
**Action:** Stream chunks directly into the TXT builder using `with_string` to avoid intermediate heap churn.
