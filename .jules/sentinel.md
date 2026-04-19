## 2025-05-14 - Intermediate key material zeroization
**Vulnerability:** Intermediate buffers (Vec<u8> or [u8; 32]) holding sensitive Ed25519 seeds were not explicitly zeroized after use, potentially leaving key material in memory.
**Learning:** While the primary SigningKey struct implements ZeroizeOnDrop, temporary copies created via to_bytes() for serialization or derivation are plain byte arrays/vectors that persist until reclaimed by the allocator.
**Prevention:** Always wrap intermediate buffers containing raw seeds or private keys in zeroize::Zeroizing or manually zeroize them immediately after the required operation (e.g., writing to disk or passing to a KDF).
