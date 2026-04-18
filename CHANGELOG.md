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
- `openhost-daemon` M3.1 bootstrap:
  - Library + `openhostd` binary: `run`, `identity show`, `identity rotate` subcommands.
  - `config` module: TOML schema for identity, Pkarr, DTLS, logging; `deny_unknown_fields`; HTTPS-only relay URL validation. `directories` backs the platform default path.
  - `identity_store` module: `KeyStore` trait with filesystem-backed `FsKeyStore`. 32-byte Ed25519 seed on disk, mode 0600 on Unix via atomic write-then-rename. Keychain impls plug behind the trait in a later PR.
  - `dtls_cert` module: self-signed ECDSA P-256 certificate via `rcgen` 0.13, persisted as a combined PEM bundle (private key + cert). SHA-256 fingerprint pinned into the published record. Rotation policy keyed on file mtime; `force_rotate` invoked by the `identity rotate` subcommand.
  - `publish` module: `SharedState` holds the live fingerprint / allowlist / ICE blobs; `PublishService` wraps `openhost_pkarr::PublisherHandle` and feeds a `RecordSource` closure that snapshots `SharedState` on every tick. `start_with_transport` lets tests inject a fake `Transport` without opening sockets.
  - `app` / `signal` / `main`: `App::build` wires identity → DTLS cert → state → publisher; `App::run` blocks on SIGINT / SIGTERM (Ctrl-C on Windows) and shuts the publisher down cleanly.
  - Integration test (`tests/bootstrap.rs`) drives `App::build_with_transport` against a tempdir and a fake transport; asserts file permissions, fingerprint propagation, and trigger behaviour.
  - Opt-in real-network smoke test (`tests/real_pkarr.rs`, feature `real-network`, `#[ignore]`d by default) round-trips a record through `pkarr.pubky.app` to catch publisher regressions before merge.
- `openhost-pkarr` M2 implementation:
  - `codec` module: bidirectional translation between `SignedRecord` and `pkarr::SignedPacket`; a single `_openhost` TXT record carries `base64url(sig || canonical_signing_bytes)` and the outer BEP44 signature is produced by the same Ed25519 identity key.
  - `publisher` module: 30-minute republish loop with an on-demand trigger channel, CAS-threaded seq handoff, and a `Transport` trait abstracting over `pkarr::Client` for testability.
  - `resolver` module: wraps `pkarr::Client::resolve_most_recent` with openhost-layer validation (decode, ±1s timestamp-drift check, `SignedRecord::verify` for the 2-hour freshness window, and caller-supplied `cached_seq` monotonicity).
  - `relays` module: bundled default Pkarr HTTP relay list (`pkarr.pubky.app`, `relay.iroh.network`).
  - `nostr` module (feature-gated): pure envelope builder for the NIP-78 kind-30078 tertiary substrate. Publish path deferred to M3.
  - Reference test vector `spec/test-vectors/pkarr_packet.json` pinning the full signed-packet bytes for the reference `SignedRecord`, with matching Rust round-trip integration test.

### Changed

- Rust toolchain pinned to 1.90 (edition2024 dependencies require 1.85+).
- Spec clarifications: public-key z-base-32 length is 52 characters (not 56); sealed-box construction is X25519 + XSalsa20-Poly1305 (libsodium-compatible), not XChaCha20-Poly1305.
- `spec/01-wire-format.md §2`: the four-row textual Pkarr record table is replaced with a single opaque TXT record at `_openhost` carrying `base64url(signature || canonical_signing_bytes)`. Semantic fields are carried inside `canonical_signing_bytes` as defined by `openhost-core::pkarr_record`.
- Workspace dependencies bumped to match the adapter: `pkarr = "5"` (was `"3"`), `mainline = "6"` (was `"4"`).

[Unreleased]: https://github.com/kaicoder03/openhost/commits/main
