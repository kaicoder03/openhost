# Sentinel Security Journal

This is a record of critical security learnings for the openhost codebase.

## 2026-07-28 - Preventing Unix File Permission Race Conditions
**Vulnerability:** Weak default file-creation permissions allowed sensitive files (e.g., Ed25519 seeds) to be temporarily readable by other local users before explicit `chmod` was called, creating a TOCTOU (time-of-check to time-of-use) race condition window.
**Learning:** Operating system file creation defaults (umask) can be overly permissive, and setting permissions post-creation leaves a race window open.
**Prevention:** Use platform-specific `OpenOptionsExt::mode(0o600)` at the exact moment of file creation so the file is never readable by other users.

## 2026-07-28 - Zeroizing Sensitive Handshake Keying Material
**Vulnerability:** The DTLS exporter secret (sensitive keying material used for channel binding) was returned as a raw heap-allocated `Vec<u8>` on both client and daemon sides. When deallocated at the end of the handshake, the plaintext bytes lingered in heap memory.
**Learning:** Raw vectors do not automatically zeroize their contents on drop.
**Prevention:** Wrap raw sensitive buffers in `zeroize::Zeroizing` to ensure the memory is cleared immediately when it goes out of scope.
