## 2025-05-22 - DNS Fragment Matching in Single-Pass Iteration
**Learning:** When refactoring from `SignedPacket::resource_records(name)` to a single-pass `all_resource_records()` loop, matching against local fragment names requires inspecting only the first label (`rr.name.iter().next()`). This is because the iterator returns fully-qualified names including the zone/origin, which will not match a simple local name string.
**Action:** Always use `.name.iter().next()` for zero-allocation local label matching when iterating over all records in a Pkarr packet.
