## 2025-05-14 - HTTP Header Size Bounding for DoS Prevention
**Vulnerability:** Memory-exhaustion Denial-of-Service (DoS).
**Learning:** In protocol implementations where user-supplied frames are accumulated in memory (like HTTP request heads or bodies), a lack of explicit size limits allows an attacker to exhaust server RAM by sending arbitrarily large frames.
**Prevention:** Enforce strict size limits at the earliest possible entry point (e.g., in the protocol listener's frame dispatch) and use defensive caps for all buffered data structures.
