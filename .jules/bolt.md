## 2026-07-20 - Single-Pass O(N) DNS Fragment Reassembly Bucket Sort
**Learning:** Iterating over `SignedPacket::resource_records()` multiple times per fragment index results in O(N²) packet scans during DNS answer reassembly. Using a single pass over `packet.resource_records()` with a stack-allocated array `[Option<DecodedFragment>; 256]` initialized via `const NONE: Option<DecodedFragment> = None; [NONE; 256]` avoids heap allocations and converts fragment reassembly to O(N). Resource record names must have trailing dots trimmed (`.strip_suffix('.')`) or first label extracted (`rr.name.get_labels().first()`) to handle absolute domain names.
**Action:** Use a single-pass stack-allocated bucket array when reassembling packet fragments by index.

## 2026-07-28 - Zero-Allocation Path and URI Construction
**Learning:** In HTTP request forwarding, string allocations and repeated parsing of `Uri` can be eliminated by borrowing request path slices (`&str`), using `std::borrow::Cow` for path normalization, pre-parsing `HeaderValue` for static host overrides, and building URIs via `http::Uri::builder()`.
**Action:** Use zero-allocation borrowing and pre-parsed header values in high-throughput HTTP forwarders.
