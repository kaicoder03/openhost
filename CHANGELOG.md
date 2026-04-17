# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches a tagged release.

## [Unreleased]

### Added

- Initial project scaffolding: Rust workspace, empty crates, public website skeleton, protocol specification drafts, CI workflows.
- Protocol spec (`spec/00-overview.md`, `spec/01-wire-format.md`, `spec/03-pkarr-records.md`, `spec/04-security.md`).
- Public website with landing page and comparison against ngrok, Tailscale Funnel, Cloudflare Tunnel, and port forwarding.
- `openhost-core` M1 implementation:
  - `identity` module: Ed25519 keypairs with zeroize-on-drop, z-base-32 encoding, and `oh://` URL parsing.
  - `crypto` module: libsodium-compatible sealed boxes (X25519 + XSalsa20-Poly1305), HMAC-SHA256 allowlist hashing, HKDF-SHA256 channel binding, and Ed25519→X25519 conversion.
  - `wire` module: HTTP-over-DataChannel framing with streaming decode.
  - `pkarr_record` module: `OpenhostRecord` schema, canonical deterministic signing bytes, and `SignedRecord::sign`/`verify` with 2-hour freshness window.
  - Reference JSON test vectors under `spec/test-vectors/` for every primitive, consumed by the crate's integration tests so the spec and implementation cannot drift.
  - End-to-end protocol exercise that walks spec §8 across all four modules.

### Changed

- Rust toolchain pinned to 1.90 (edition2024 dependencies require 1.85+).
- Spec clarifications: public-key z-base-32 length is 52 characters (not 56); sealed-box construction is X25519 + XSalsa20-Poly1305 (libsodium-compatible), not XChaCha20-Poly1305.

[Unreleased]: https://github.com/kaicoder03/openhost/commits/main
