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
- `openhost-daemon` M5.1 WebRTC passive listener + frame routing:
  - New `openhost_daemon::listener::PassivePeer`: loads the persisted `RTCCertificate`, pins `DTLSRole::Server` via `SettingEngine::set_answering_dtls_role`, and exposes `handle_offer(sdp) -> Result<sdp>` as the library API an offer-record poller (PR #7) will eventually call. Inbound data channels run bytes through `openhost_core::wire::Frame::try_decode`; every `REQUEST_HEAD` frame gets a stub `HTTP/1.1 502 Bad Gateway` `RESPONSE_HEAD` + empty `RESPONSE_END`. The real localhost forwarder lands in PR #6.
  - `dtls_cert` pivoted to store an `RTCCertificate` directly. Persistence format switched from standard two-block PEM to webrtc-rs's EXPIRES-tagged PEM (`RTCCertificate::serialize_pem` / `from_pem`) so the SHA-256 fingerprint is stable across reloads — a plain-PEM reload would have webrtc-rs regenerate the cert from the keypair, picking a new random CN and serial and invalidating every published record.
  - `App::build` now builds a `PassivePeer` alongside the publisher; `App::handle_offer` is the library entry point. `App::run` awaits `PublishService::await_initial_publish` with a 10 s budget before logging "openhostd: up" so the daemon's visible readiness signal is tied to the first publish's terminal outcome (resolves the M3.2 TODO around publish.rs:186). The cert-rotation vs active-connections TODO(M3.2) at app.rs:111 is replaced with a documented policy: the per-daemon-restart `API` binds the current cert; rotation requires a republish (`publisher.trigger()`) so clients resolving after the rotation see the new `fp`.
  - `SettingEngine::set_answering_dtls_role(DTLSRole::Server)` + a pre-flight `a=setup:` scan on the inbound offer reject any SDP whose DTLS role would flip spec §3.1's passive/active split. `actpass` is accepted (standard WebRTC offerer default per RFC 5763 §5); the daemon's answer still asserts `passive`, preserving the invariant.
  - `rustls = "0.23"` added as a direct dep with the `ring` crypto provider; the daemon installs it once at `PassivePeer::new` so webrtc-dtls + reqwest (transitive via pkarr) have a CryptoProvider to consume.
  - Workspace dep: `webrtc = "0.17"` enables the `pem` feature.
  - `tests/listener.rs` drives a full in-process two-peer round-trip: DTLS handshake completes under 5 s, answer SDP carries the expected fingerprint, a `REQUEST_HEAD` frame produces a `502 Bad Gateway` `RESPONSE_HEAD` + `RESPONSE_END`, and `setup:passive` / missing `a=setup:` offers are rejected before any `RTCPeerConnection` is allocated. Plus 5 listener unit tests.
  - **Channel binding (spec §7.1 / RFC 8844 mitigation) is NOT implemented this PR** — `webrtc` v0.17.x does not publicly expose RFC 5705 exporter keying material (`RTCDtlsTransport::conn` is `pub(crate)`). A `TODO(spec §7.1 / PR #5.5)` marker at the `Connected` state callback documents the gap; the attack surface is currently empty because no offerer client exists (that's PR #8). PR #5.5 will vendor a patched `webrtc` fork exposing `export_keying_material` and wire the signature handshake.
- `openhost-client` M4.1 read-only resolver + debug CLI:
  - `Client` + `ClientBuilder`: wraps `openhost_pkarr::Resolver` behind an `oh://…`-URL surface. `.relays(…)` overrides the relay list (empty falls back to `DEFAULT_RELAYS`). `.grace_window(Duration)` overrides the spec §3 rule-5 grace (`Duration::ZERO` skips the second race entirely). `Client::resolve_url` parses the URL and resolves in one call; `Client::resolve` accepts a pre-parsed `OpenhostUrl`. `ClientBuilder::build_with_resolve` takes any `openhost_pkarr::Resolve` trait object so downstream tests drive the full validator flow without touching the network.
  - `openhost-resolve` binary (behind the `cli` feature so WASM / FFI consumers don't pull `clap` / `tracing-subscriber` / `serde_json` / `hex` transitively): `openhost-resolve <oh-url> [--relay URL]... [--fast] [--json]`. Pretty-prints or JSON-serialises the decoded record; exit codes `0` success, `2` URL parse error, `1` any resolve error. Installs a tracing subscriber on stderr when not in `--json` mode so the subscriber never corrupts machine-readable output.
  - `tests/resolve.rs` drives the full `Client::resolve_url` path against the canonical `spec/test-vectors/pkarr_packet.json` fixture (re-signed with a fresh `ts` so the 2-hour freshness window passes regardless of wall-clock) and asserts the decoded record round-trips. Malformed-URL rejection is covered too.
- `openhost-pkarr` M3.2 resolver + publisher hardening:
  - `resolver::resolve` now implements the 1.5-second grace window from `spec/01-wire-format.md §3` rule 5. After the first validated record is accepted, the resolver sleeps `openhost_pkarr::GRACE_WINDOW` and issues a second substrate race; any higher-`seq` record that validates during the window is preferred. A factored `validate_packet` helper applies identical drift / verify / seq-regression checks to both races. `NotFound` on the first race fast-fails without waiting.
  - `Resolver::with_grace_window(Duration)` lets latency-sensitive callers (browser extension, CLI one-shots) opt down or out; `Duration::ZERO` skips the second race entirely. The second `resolve_most_recent` is bounded by `tokio::time::timeout(grace, …)` so total `resolve()` latency is capped at `grace + first-race latency + validation` regardless of pkarr's internal per-substrate timeout. Second-race validation failures `tracing::warn!` the error and keep the first validated record, making a malicious substrate observable for debugging.
  - `publisher::spawn` wraps the initial publish in an exponential-backoff retry: `INITIAL_PUBLISH_ATTEMPTS = 3`, backoffs `INITIAL_PUBLISH_BACKOFF * 2^(n-1)` = 500 ms / 1 s between attempts. On success: `info!`. On intermediate failure: `warn!` with the next retry delay. On all-fail: `error!` and a fall-through to the normal 30-minute ticker so the task stays alive.
  - `PublisherHandle::await_initial_publish()` — new out-of-band signal backed by `tokio::sync::watch<Option<InitialPublishOutcome>>`. Resolves when the initial retry loop produces a terminal outcome: `Succeeded(ts)` or `Exhausted`. Unblocks the daemon's `App::build` startup-gating TODO(M3.2) without log scraping.
  - New tests (+11): `resolver` — grace-window higher-seq straggler prefers, keeps first on lower-seq / absent / validation-failing second, no straggler race on NotFound, zero-grace skips second race, second-race timeout falls back to first. `publisher` — retry succeeds after two transport failures, gives up cleanly after `INITIAL_PUBLISH_ATTEMPTS`, `await_initial_publish` returns `Succeeded` on first-try success, returns `Exhausted` after all-fail. Virtual-time tests use `#[tokio::test(start_paused = true)]` via the `test-util` tokio feature.
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
