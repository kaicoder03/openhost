## 2025-05-14 - [DoS Mitigation & Secret Zeroization]
**Vulnerability:** Memory-exhaustion DoS via unbounded HTTP request heads and residual secrets in memory.
**Learning:** Even if individual frames are capped by the wire codec (16MB), higher-level protocol units like HTTP heads need tighter limits (64KB) to prevent per-connection memory inflation. Sensitive key material (seeds, exporter secrets) must be zeroized even in error paths to prevent leakage.
**Prevention:** Always enforce size limits on accumulated buffers and use the `zeroize` crate for all intermediate buffers holding cryptographic secrets.
