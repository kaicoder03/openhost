# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches a tagged release.

## [Unreleased]

### Added (PR #23, distributable binaries)

- **New `.github/workflows/release.yml`** — fires on `v*` tag push (or `workflow_dispatch` for backfills). Builds `openhostd`, `openhost-dial`, `openhost-resolve` on native GitHub runners for Linux x86_64, macOS aarch64, macOS x86_64, and Windows x86_64; strips, packs (`.tar.gz` / `.zip`), and uploads to the matching GitHub release via `softprops/action-gh-release`. Release body is sliced out of the matching `## [X.Y.Z]` section of `CHANGELOG.md` by a small awk filter; `fail_on_unmatched_files: true` guards against a silent no-op on a misconfigured glob.
- **New `distribution/`** tree with operator-ready service-manager files:
  - `distribution/systemd/openhostd.service` — Linux systemd unit with resource ceilings (`MemoryMax=256M`, `TasksMax=64`), sandboxing (`ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, `MemoryDenyWriteExecute=true`, and friends), and backoff that caps crashloops before they hammer public Pkarr relays.
  - `distribution/launchd/com.openhost.openhostd.plist` — macOS launchd plist with user-agent and system-daemon install modes; documented in comments, including the `UserName` block to uncomment for the system install.
  - `distribution/README.md` — install commands + uninstall commands for both platforms, plus a security-posture note (the daemon runs unprivileged by default; don't grant more).
- **Site install guide reshuffle** — `guides/install.md` now leads with a "Pre-built binaries" section and a platform-archive table; "Build from source" moves to a fallback section. README's "Building from source" gains a one-line pointer at the releases page.

### Out of scope for PR #23

- Homebrew tap — requires a separate `homebrew-openhost` repo + formula with pinned SHA256s against a real release artifact. Easier to land once the workflow has run once and produced verifiable checksums.
- macOS notarization / Windows code signing — requires paid developer certs; follow-up.
- ARM Linux (aarch64-unknown-linux-gnu) — cross-compile requires extra toolchain setup, and native ARM GitHub runners are paid. Start with x86_64 Linux; revisit if users ask.
- musl builds for Alpine Linux — follow-up once there's demand.

### Changed (PR #22, shrink main `_openhost` record)

- **Wire-format break**: `PROTOCOL_VERSION` bumped `1` → `2`. v2 records drop the `allow` and `ice` fields from `OpenhostRecord::canonical_signing_bytes`. v1 and v2 records are mutually unreadable; the `version` byte is the discriminator (decoders **MUST** reject a mismatched version).
- `IceBlob` struct deleted entirely. The daemon had no writer for it in production; the exploration confirmed it was always `Vec::new()`. Per-client ICE ciphertext will live in separate TXT records when that feature lands (see updated `spec/01-wire-format.md §2`).
- The host's allowlist stays in `SharedState::allow` (consulted by `is_client_allowed` on every inbound offer) but is **no longer published**. Operators that scraped the published `allow` list for diagnostic purposes should instead inspect the daemon's pairing TOML directly (`~/.config/openhost/allow.toml` by default).
- `openhost-resolve --json` schema drops the `allow_hex` and `ice` keys. Any script that consumed them needs updating; the remaining keys (`version`, `ts`, `dtls_fp_hex`, `roles`, `salt_hex`, `disc`, `signature_hex`) are unchanged.
- Reference test vectors regenerated: `spec/test-vectors/pkarr_record.json` carries a new canonical length (118 bytes, was 230) + new signature; `spec/test-vectors/pkarr_packet.json` carries a new BEP44 outer signature + packet bytes (packet shrank from 584 to 434 bytes on the wire — a 26% reduction before fragment fanout).

### Added (PR #22)

- New `pkarr_record::tests::v2_main_record_base64_fits_under_ceiling` pins the base64url length of a realistic v2 main record below 260 chars. The v2 shape measures ~243 chars; any future field addition that quietly regrows the record can't silently recreate the pre-PR-22 BEP44 overflow.
- `spec/01-wire-format.md §2` rewritten: v2 canonical bytes listed, v1 migration path described, allowlist-is-private-state constraint added, ICE-ciphertext-as-separate-records planned path documented.

### Known limitations (carries into 0.3)

- **Residual BEP44 gap on real webrtc-rs answers remains open.** PR #22 freed ~112 bytes from the main record, but the `daemon_produces_sealed_answer_for_dialer_offer` end-to-end test still asserts `PollAnswerTimeout` because real webrtc-rs answer SDPs (~450 bytes sealed → 3 fragments at 180 bytes each) still exceed the residual BEP44 budget after fragmentation overhead. Further fixes — likely either larger `MAX_FRAGMENT_PAYLOAD_BYTES` with DNS multi-string handling, or shrinking the answer SDP itself — are separate follow-ups.

## [0.2.0] - 2026-04-18

Phase 1 + Phase 2 of the post-v0.1 roadmap, shipped as seven focused PRs (#14 – #20). Closes all three v0.1 known limitations (answer-record overflow, missing client CLI, SIGHUP-only pairing reload) and lands the operator-facing docs needed to actually test the release: install + quickstart + troubleshoot guides on the site, worked `examples/` for static sites + Jellyfin + Home Assistant, a README Quickstart, and a root-level `CONTRIBUTING.md`. Also a breaking wire-format change in `_answer-<client-hash>` records — see `### Changed` below.

### Added (PR #20, CONTRIBUTING.md)

- **New root-level `CONTRIBUTING.md`.** Covers: what contributions are welcome and what needs discussion first; dev setup (Rust 1.90 toolchain, pnpm for site); the three test commands we gate on (`cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all --check`) plus the opt-in `--features real-network` suite; the five-step plan → implement → self-review → fix-all → merge PR cadence; how to propose a spec change (issue first for non-trivial changes, `spec/**` is markdown-linted); a concrete "filing good bug reports" checklist (`openhost-resolve --json`, debug-level daemon log, client stderr) linking the bug-report issue template; and a security-report pointer at GitHub Private Security Advisories.
- `README.md` gains a `Contributing` section immediately above `License` linking the new doc.

### Verification (PR #20)

- `cargo check --workspace` clean (no code changes).
- Every referenced path exists: `PULL_REQUEST_TEMPLATE.md`, both issue templates, `SECURITY.md`, `ROADMAP.md`, `CHANGELOG.md`, `spec/04-security.md`, `rust-toolchain.toml`.
- GitHub Discussions is **not** silently claimed to exist; document notes honestly that it's not enabled and directs readers at issues with the `question` label instead.

### Added (PR #19, README Quickstart + worked examples)

- `README.md` gains a **Quickstart** section — four copy-paste commands that clone, build, run, and dial — plus a link to the fuller [site Quickstart guide](https://kaicoder03.github.io/openhost/guides/quickstart/). The Repository-layout table now names the three worked examples we actually ship.
- **`examples/README.md`** — index of the service walkthroughs with a compatibility note (REST works today; WebSocket-dependent UIs don't, pending the Phase 3+ per-path WebSocket allowlist).
- **`examples/personal-site/`** — `README.md` + complete `daemon.toml`. End-to-end working example against a `caddy file-server`-hosted static site on `127.0.0.1:8080`. Smallest viable walkthrough; no caveats.
- **`examples/jellyfin/`** — `README.md` + `daemon.toml`. Exposes Jellyfin's REST API on `127.0.0.1:8096` and demonstrates authenticated requests via `X-Emby-Token`. Documents that the web UI loads but doesn't function fully (WebSocket progress reporting), and that direct-play streaming is partial-only at `v0.1.0`. `max_body_bytes = 32 MiB` to accommodate library listings and posters.
- **`examples/home-assistant/`** — `README.md` + `daemon.toml`. Exposes Home Assistant's `/api/` on `127.0.0.1:8123` with `host_override = "127.0.0.1:8123"` so `http.trusted_proxies` is a non-issue. Concrete examples cover state reads and service calls (turn on a light from a second machine). Explicitly flags that Lovelace UI and Companion apps do not work at `v0.1.0` because they require WebSockets.

### Verification (PR #19)

- `cargo check --workspace` clean (no code changes).
- Every `daemon.toml` parses against the `Config` schema at `crates/openhost-daemon/src/config.rs` (identity store tag `kind = "fs"`, `pkarr.offer_poll` subsection, `pairing` defaults).
- Every `openhost-dial` / `openhostd` / `openhost-resolve` invocation in the walkthroughs uses flags that exist post-PR-16 / PR-17.
- WebSocket incompatibility explicitly called out in both Jellyfin and Home Assistant walkthroughs so early testers don't waste time debugging a known limitation.

### Added (PR #18, site operator guides)

- New **Guides** section under `site/src/content/docs/guides/` with three pages:
  - **`install.md`** — Rust 1.90 prerequisites, `cargo build --release` commands for the daemon + `--features cli` client crate, binary destinations, install hints (`~/.local/bin`), per-platform notes (macOS / Linux / Windows), and a pointer at Phase 3+ distributable-binary work in `ROADMAP.md`.
  - **`quickstart.md`** — six-step walkthrough: upstream HTTP service on the host (`python3 -m http.server`), minimal `~/.config/openhost/daemon.toml` (identity, pkarr, dtls, forward sections), `openhostd run` + `openhostd identity show`, `openhost-dial oh://<pubkey>/` from the client, switching to `enforce_allowlist = true` + `openhostd pair add`, and `openhost-resolve --json` as a diagnostic. Includes an inline caveat on the residual BEP44 answer-size gap (tracked in `ROADMAP.md` post-Phase-2).
  - **`troubleshoot.md`** — failure-mode playbook structured by symptom: DHT/relay miss, relay 5xx, `PollAnswerTimeout` (three common causes including the residual size gap and pair-watcher unreliability on network filesystems), DTLS handshake failure, and pair-DB changes not propagating. Each section carries 2–4 verification steps with concrete commands.
- Starlight sidebar now carries a **Guides** section between **Get started** and **Specification**. `site/astro.config.mjs` extended with three explicit slugs so ordering is deterministic.

### Verification (PR #18)

- `cd site && pnpm install && pnpm build` — 10 pages generated (was 7), including the three new `/guides/*/index.html` routes.
- No code changes; `cargo check --workspace` unaffected.

### Added (PR #17, pair-DB file watcher)

- **Automatic pair-DB reload on every platform.** New `openhost_daemon::pair_watcher` module wraps `notify-debouncer-mini` in a tokio-friendly handle: the watcher targets the pair-DB file's parent directory in non-recursive mode, filters events by filename inside a dedicated bridge thread, and forwards debounced reload triggers into the daemon's event loop via a tokio `mpsc`. The `App::run` event loop grows a third `tokio::select!` arm parallel to `shutdown_signal` and `reload_signal`; the SIGHUP path is retained as a secondary trigger on Unix so the existing SIGHUP integration test (`pairing_enforcement.rs`) continues to exercise the same reload code.
- New `PairWatcherError` variant on `DaemonError` (`BadPath`, `Io`, `Backend`, `ThreadSpawn`). Spawn failures degrade gracefully — the watcher logs a `warn!` and returns `None`, the daemon keeps running, and pairing changes fall back to the SIGHUP path.
- New config field `pairing.watch_debounce_ms: u64` (default 250). Operators can tune the coalesce window per deployment; the default swallows `pairing::save_atomic`'s write-then-rename burst and still feels interactive.
- New integration test `crates/openhost-daemon/tests/pair_watcher.rs::watcher_reloads_allowlist_without_sighup`: boots `App`, modifies the pair DB on disk via `pairing::add`, and asserts `SharedState::is_client_allowed` becomes true within 3 s — without sending SIGHUP. Runs on both Unix and Windows (modulo notify-backend timing) under a multi-threaded tokio flavor so the watcher-driven reload arm of `App::run` can actually fire.
- 3 new unit tests in `pair_watcher.rs`: fires on write, fires on initial-create (pair DB does not exist at daemon start), ignores sibling files in the same directory.

### Changed (PR #17)

- `openhostd pair add/remove` drops the "Send SIGHUP to the running daemon" reminder and instead prints a one-line note that a running daemon picks the change up automatically via the file watcher. SIGHUP remains documented as a fallback on Unix.
- `App::run` factored the common post-reload logic into a new `reload_and_trigger(path, state, publisher, source)` helper. Both the SIGHUP and file-watcher arms now route through it; log lines carry a `source` field so operators can distinguish which trigger fired.
- New dependency: `notify-debouncer-mini = "0.6"` (workspace-level; transitively pulls in `notify`, `inotify` on Linux, `fsevent-sys` on macOS, `notify-types`).

### Added (PR #16, `openhost-dial` CLI)

- **New binary: `openhost-dial`**. Sends one HTTP request over openhost and prints the response. Behind the existing `cli` feature, so WASM / FFI consumers of `openhost-client` don't pull clap / tracing-subscriber / serde_json / hex transitively. Usage: `openhost-dial oh://<zbase32-pubkey>[/path] [-X METHOD] [-H 'Key: Value']... [-d BODY] [--relay URL]... [--timeout SECS] [--identity PATH] [--json]`. `-d` accepts `@path` (file), `-` (stdin), or a literal string — curl-style. `--identity <PATH>` loads a 32-byte raw Ed25519 seed (matches the daemon's `FsKeyStore` format); when omitted the binary generates an ephemeral key (useful against unauthenticated daemons, not useful against hosts with `enforce_allowlist = true` since the pubkey changes per invocation).
- New public module `openhost_client::cli`. Shared CLI helpers the binary uses: `load_identity_from_file`, `read_body_arg`, `parse_header_arg`, `build_request_head`, `parse_response`, `response_to_json`, and the `ParsedResponse` struct. Also gated behind the `cli` feature.
- 11 new unit tests covering the cli helpers: header-parsing variants (`Key: Value`, `Key:Value`, multiple-space values, empty-name error, colon-missing error), request-head defaults and user-override precedence (Host / Content-Length / Content-Type skipped when user supplied), response parsing (happy path + malformed status), JSON body encoding (UTF-8 vs base64 fallback), file and literal body loading, and identity-seed size validation. Plus 2 binary-level tests for relay-URL validation.
- Exit-code contract documented: `0` for any successful round-trip (regardless of HTTP status, matching curl), `1` for openhost / network / protocol errors, `2` for usage errors (clap parse failures, URL parse errors, identity file missing / wrong size, non-HTTPS relays).
- Non-`--json` output routes the status line + response headers to stderr and the body to stdout, so `openhost-dial … | jq` works out of the box; `--json` emits a single pretty-printed object to stdout instead.

### Changed (PR #16)

- `crates/openhost-client/src/lib.rs` adds `#[cfg(feature = "cli")] pub mod cli;` and documents the new binary alongside `openhost-resolve` in the crate header.
- `crates/openhost-client/Cargo.toml` adds a second `[[bin]]` entry for `openhost-dial` with `required-features = ["cli"]`.

### Added (PR #15, answer-record splitting)

- `openhost-pkarr` fragmented answer records. Each `AnswerEntry`'s sealed ciphertext is now split into one or more `_answer-<client-hash>-<idx>` TXT records before being folded into the daemon's `_openhost` pkarr packet. Each fragment carries a 5-byte envelope (`version=0x01`, `chunk_idx: u8`, `chunk_total: u8`, `payload_len: u16 BE`) followed by up to `MAX_FRAGMENT_PAYLOAD_BYTES = 180` bytes of sealed ciphertext. Public API adds `decode_answer_fragments_from_packet`, `answer_txt_chunk_name`, `MAX_FRAGMENT_PAYLOAD_BYTES`, and `MAX_FRAGMENT_TOTAL = 255`.
- Dialer reassembly: `openhost-client::Dialer::poll_answer` now calls `decode_answer_fragments_from_packet`, which probes fragment zero first (so a missing zero cheaply means "no answer yet"), reads `chunk_total`, fetches the remaining `1..chunk_total - 1` fragments, validates that every fragment's label suffix agrees with its envelope `chunk_idx` and that `chunk_total` is consistent across the set, and concatenates the payloads before running sealed-box open. Malformed sets (gaps, oversize payloads, inconsistent totals, unknown envelope versions) are rejected before any cryptographic operation runs.
- New tests in `crates/openhost-pkarr/src/offer.rs` covering the fragment codec: `small_answer_fragments_and_reassembles`, `multi_fragment_answer_reassembles`, `fragment_decode_rejects_unknown_version`, `fragment_decode_rejects_idx_ge_total`, `fragment_decode_rejects_zero_total`, `fragment_decode_rejects_length_mismatch`, `fragment_reassembly_detects_chunk_total_disagreement`, `fragment_reassembly_detects_missing_middle`. The existing `encode_evicts_oldest_when_overflow` and `encode_with_one_answer_preserves_openhost_txt` tests continue to pass against the new fragment path.
- New `crates/openhost-client/tests/end_to_end.rs::dialer_reassembles_fragmented_answer_from_wire` exercises the full wire round-trip: a synthetic small sealed answer is pushed into `SharedState`, the publisher re-emits, and the test resolves the packet and asserts `decode_answer_fragments_from_packet` returns byte-identical sealed bytes.

### Changed (PR #15, answer-record splitting)

- **Wire-format break**: v0.2+ daemons emit fragmented `_answer-<client-hash>-<idx>` TXTs; v0.1 clients expecting the legacy unfragmented `_answer-<client-hash>` name will not find an answer on a v0.2 packet, and vice versa. v0.1 answer delivery was already labelled best-effort (the encoder evicted answers that didn't fit the BEP44 cap), and both sides upgrade in lockstep with this PR, so the break is contained.
- `spec/01-wire-format.md §3.3` rewritten: the old "encoder constraint (eviction)" paragraph is replaced with the fragment envelope, DNS naming convention (`-<idx>` suffix), reassembly procedure, and the whole-answer eviction rule (the encoder MUST evict all fragments of an answer together — never a single fragment, which would yield an un-reassemblable partial at the client).
- The encoder's existing oldest-first eviction ordering is preserved but now operates on whole fragment sets; `encode_with_answers` pre-computes per-answer fragment sets and packs them atomically.
- `openhost-client::Dialer::poll_answer` no longer imports or references `decode_answer_from_packet`; callers who depended on the legacy unfragmented decoder should migrate to `decode_answer_fragments_from_packet`.

### Known limitations (carries into 0.2.0 from 0.1.0)

- Real webrtc-rs answer SDPs seal to ≈450 bytes, which — even with fragmentation — still exceeds the residual BEP44 budget after the main `_openhost` record. The daemon's `handle_offer → push_answer` path continues to have its answer evicted in `crates/openhost-client/tests/end_to_end.rs::daemon_produces_sealed_answer_for_dialer_offer`, which still asserts `PollAnswerTimeout` as the expected outcome. Closing that gap (shrinking the answer SDP itself, or moving answers out of the main packet) is the next line item in `ROADMAP.md`.

## [0.1.0] - 2026-04-18

The first tagged release. Daemon + client + pkarr integration + WebRTC + channel binding + HTTP forwarding + allowlist + rate limit all shipped. One known gap remains (see below).

### Added (PR #11, v0.1 freeze)

- `openhost-pkarr` offer/answer sealed-plaintext compression. New 1-byte `compression_tag` discriminator prefixing every sealed inner plaintext: `0x01` = uncompressed (legacy, still accepted), `0x02` = zlib (RFC 1950, default for v0.1+ encoders). Decompression output is hard-capped at 64 KiB to defend against zip bombs. The main `_openhost` canonical bytes, outer sealed-box wrapping, base64url, and DNS TXT packaging are all byte-identical; only the sealed plaintext layer changes. 6 new offer-codec unit tests: v2 roundtrip (offer + answer), v1 back-compat for both codecs, size strictly-smaller sanity on a realistic SDP, DoS cap rejection, empty-SDP edge case, unknown-tag rejection.
- Workspace dep: `flate2 = "1"` (pure-Rust miniz_oxide backend — no C deps).
- `spec/01-wire-format.md` reconciled. Canonical text now matches shipped code: client-first channel-binding order (AUTH_NONCE → AUTH_CLIENT → AUTH_HOST), empty DTLS exporter `context` with `host_pk || client_pk || nonce` in HKDF `info`, `_answer-<client-hash>` TXT format with compression tag. The three `TODO(v0.1 freeze)` blocks are resolved.

### Changed (PR #11, v0.1 freeze)

- Workspace version bumped `0.0.0` → `0.1.0`. A `v0.1.0` git tag follows this merge.
- `crates/openhost-client/tests/end_to_end.rs`: `daemon_produces_sealed_answer_for_dialer_offer` now reflects the post-compression reality. Compression alone doesn't shrink a high-entropy WebRTC SDP enough to fit answer + `_openhost` in the BEP44 1000-byte cap on some configurations, so the test continues to assert against `SharedState::snapshot_answers()` (every server-side layer ran) rather than the wire packet. A full wire-level HTTP round-trip still requires splitting the answer across multiple pkarr records — tracked as post-v0.1.

### Known limitations in 0.1.0

- **Answer delivery over BEP44 is best-effort.** A fully-trickled WebRTC answer SDP can overflow the 1000-byte mutable-item cap when folded alongside the main `_openhost` record. Compression (new in 0.1.0) makes the common case fit; the eviction path remains as a safety valve but means some paired clients may not receive a response on the first poll. Post-v0.1 work splits the answer into separate records.
- **Client allowlist mutation requires SIGHUP on Unix and daemon restart on Windows.** The CLI prints the reminder on every `pair add` / `pair remove`.
- **No bundled client CLI.** `openhost-resolve` still ships for record inspection. A `openhost-dial` bin is planned as a follow-up; the `Dialer` library surface is the supported integration point.

## [Pre-0.1.0 development history]

### Added

- `openhost-client` M8 WebRTC offerer + in-process end-to-end test:
  - New `openhost-client::Dialer` — resolves the host's Pkarr record, generates a WebRTC offer, seals + publishes an `_offer-<host-hash>` record under the client's own zone, polls the host zone for `_answer-<client-hash>`, unseals + applies the answer, and runs the client side of the PR #5.5 channel-binding handshake. Returns an authenticated `OpenhostSession` backed by one WebRTC data channel.
  - New `openhost-client::OpenhostSession::request(head, body) -> ClientResponse { head_bytes, body }` — wire-bytes HTTP/1.1 round-trip over the authenticated data channel. `close().await` for orderly teardown; `Drop` is a safety net.
  - New `openhost-client::ClientBinder` — client-side mirror of the daemon's `ChannelBinder`. Domain-separated against `openhost-daemon::ChannelBinder`; both share wire-level constants through a new `openhost-core::channel_binding_wire` module.
  - Staged public methods on `Dialer` (`resolve_host`, `build_offer`, `publish_offer`, `poll_answer`, `apply_answer`) for fault-injection tests. Production callers go through `dial()`.
  - New `openhost-pkarr::MemoryPkarrNetwork` (feature `test-fakes`) — shared in-memory substrate that lets a daemon + dialer publish/resolve against each other in the same process without touching a real relay. Serialized `SignedPacket` storage keyed on pubkey; `Transport` + `Resolve` adapters.
  - `PassivePeer::set_skip_ice_gather_for_tests(bool)` — test-only knob that skips the daemon's `gathering_complete_promise` wait so the answer SDP stays small enough to probe; DO NOT use in production.
  - Two integration tests in `crates/openhost-client/tests/end_to_end.rs`:
    1. `daemon_produces_sealed_answer_for_dialer_offer` — drives a real `App` + real `Dialer` through a shared `MemoryPkarrNetwork`; asserts the full daemon-side flow (poll offer → handle_offer → seal answer → queue in SharedState) fires. See hazard note below.
    2. `dial_times_out_when_daemon_not_running` — no poller seeing the offer, so `Dialer::dial` hits `ClientError::PollAnswerTimeout`.
  - New `ClientError` variants: `ResolveHost`, `PublishOffer`, `PollAnswerTimeout`, `AnswerDecode`, `AnswerBindingMismatch`, `WebRtcSetup`, `ChannelBinding(ClientBindingError)`, `HttpRoundTrip`.
  - Re-exports from `openhost-client`: `PublicKey`, `SigningKey`, `OpenhostUrl`, `DEFAULT_RELAYS`.
  - **Architectural gap flagged `TODO(v0.1 freeze)`:** a full webrtc-rs answer SDP (even with `set_skip_ice_gather_for_tests`) is ~500 bytes; sealed + base64url + DNS packaging pushes the daemon's pkarr packet past the 1000-byte BEP44 `v` cap, so the encoder evicts the answer and the client's `poll_answer` loop never observes it on the wire. The end-to-end test documents this and asserts against `SharedState::snapshot_answers()`. Splitting ICE trickle into separate pkarr records is the planned v0.1-freeze fix that upgrades the test to a full HTTP round-trip assertion.

### Breaking changes

- **Allowlist enforcement is on by default** (`pkarr.offer_poll.enforce_allowlist = true`). Upgraders running PR #7a configurations will see every inbound offer rejected until they either (a) pair their clients via `openhostd pair add <pubkey>`, or (b) explicitly set `enforce_allowlist = false` in the config. The daemon logs a startup `warn!` when enforcement is on, the pair DB is empty, and `watched_clients` is non-empty — operators see the misconfiguration in the first line of the boot log. The escape-hatch (`false`) preserves PR #7a's permissive behavior unchanged.

### Added

- `openhost-daemon` M7b allowlist enforcement + per-client rate limit:
  - New `openhost-daemon::pairing` module: plaintext TOML pair DB at `~/.config/openhost/allow.toml` (overridable via `pairing.db_path`), atomic write with mode 0600 on Unix, `PairingDb::compute_hashes` projects entries into the `_allow` HMAC hashes already published in the `_openhost` record. Missing file = empty list (first-run ergonomics); malformed file or duplicate entries = hard error.
  - New `openhost-daemon::rate_limit::TokenBucket` — pure synchronous token-bucket keyed per `client_pk`. Caller threads `now: Instant` in, keeping the poller's existing `now_instant` reuse clean and making unit tests deterministic.
  - `SharedState` gets `replace_allow`, `is_client_allowed`, `add_client_hash`, `remove_client_hash` helpers; `allow` now mutates at runtime via SIGHUP.
  - `OfferPoller` gains two new gates, evaluated after unseal + cross-check: (1) `is_client_allowed` when `enforce_allowlist = true` (default); (2) `TokenBucket::try_consume` per `client_pk`. Both failure paths advance the dedup cursor so a bypass flood can't drive the daemon into a decrypt-every-tick workload. Allowlist runs before rate-limit so unauthorised peers can't drain legitimate peers' buckets.
  - `signal::reload_signal()` awaits SIGHUP on Unix (returns `Pending` on Windows — pairing changes require a daemon restart there). `App::run` now drives `tokio::select! { biased; shutdown => break; reload => reload_pair_db + publisher.trigger(); }`, hot-swapping the allow list without tearing down live sessions.
  - New CLI subcommand tree `openhostd pair {add <pubkey> [--nickname <str>], remove <pubkey>, list}`. Each mutation rewrites the TOML atomically and prints a reminder to SIGHUP the running daemon.
  - Config surface: new `[pairing] db_path` top-level section + `pkarr.offer_poll.{enforce_allowlist, rate_limit_burst, rate_limit_refill_secs}`. `Config::validate` rejects zero burst, non-finite / non-positive refill.
  - New `DaemonError::Pairing(PairingError)` variant. `PairingError::{Io, Toml, TomlSer, InvalidPubkey, Duplicate, AlreadyPresent, NotPresent}`.
  - 4 new integration tests in `tests/pairing_enforcement.rs`: authorized client processed, unauthorized client rejected, `enforce_allowlist = false` preserves PR #7a behavior, and `rate_limit_burst = 2` caps a 5-offer burst to exactly 2 `handle_offer` calls. 15 new unit tests across `pairing` + `rate_limit` + `publish` (allowlist helpers).
  - **Out of scope for this PR:** mid-session revocation of an already-authenticated DC (the binding-time cross-check of the allow list is a PR #7c item — today an authenticated session survives until the client naturally disconnects or the daemon shuts down). The offer-poll gate is the primary line of defense.
- `openhost-daemon` M7a offer-record polling + per-client answer publishing:
  - New `openhost-pkarr::offer` module: `OfferRecord`/`OfferPlaintext`/`AnswerEntry`/`AnswerPlaintext` types, domain-separated inner-plaintext codec (`openhost-offer-inner1` / `openhost-answer-inner1`), sealed-box wrappers over libsodium `crypto_box_seal`, `host_hash_label` + `client_hash_label` helpers (z-base-32 of a 16-byte hash), and `encode_with_answers` which emits a single `SignedPacket` carrying the main `_openhost` TXT PLUS one extra `_answer-<client-hash>` TXT per queued answer. The encoder auto-evicts the oldest answers when the packet would exceed BEP44's 1000-byte `v` limit. 15 unit tests covering roundtrip, tamper, encoding invariance (with-empty-answers packets are byte-identical to `encode()`), and eviction.
  - New `openhost-pkarr::AnswerSource` hook on `Publisher` — a `FnMut() -> Vec<AnswerEntry>` the publisher calls each tick, folding the snapshot into the outgoing packet via `encode_with_answers`. Daemons that don't need it pass `None` and the bytes match the plain codec exactly.
  - **BEP44 CAS monotonicity fix in `Publisher::publish_once`.** Under PR #7a's 1 Hz poll cadence, two offers arriving in the same wall-clock second would share a `seq` and the second publish would collide on CAS. The publisher now bumps `record.ts = last_seq + 1` when the source returns a non-monotonic timestamp, with a `warn!` for visibility. Pre-existing latent bug; surfaced by this PR.
  - New `openhost-daemon::offer_poller::OfferPoller` service. Polls each configured watched-client pubkey once per second, resolves its `SignedPacket`, decodes the `_offer-<host-hash>` TXT, unseals via the daemon identity, cross-checks inner/outer `client_pk`, calls `PassivePeer::handle_offer(offer_sdp)`, seals the resulting answer SDP back to the client (`AnswerEntry::seal`), pushes the entry into `SharedState`, and triggers an immediate republish so the client's next poll picks up the answer. In-memory seen-cache (keyed on client pubkey, 10-minute TTL) de-duplicates across cycles. Per-client 5-second throttle drops floods without killing the loop. Single-record failures (decrypt, SDP parse, handshake) `warn!` and skip — the loop never terminates from a per-offer error.
  - `SharedState` grows `answers: RwLock<HashMap<[u8; 16], AnswerEntry>>` plus `push_answer` / `snapshot_answers`. Keyed on `client_hash` so a subsequent answer for the same client overwrites the previous one.
  - `publish::start` now returns `(PublishService, Arc<dyn Resolve>)` and `publish::build_default_client` gives one shared `Arc<pkarr::Client>` to both the `PkarrTransport` side and the `PkarrResolve` side — offer polling and record publishing consult the same relay set.
  - `App` grows a `poller: Option<OfferPoller>` field and a new constructor `App::build_with_transport_and_resolve(cfg, transport, resolver)` for integration tests. Shutdown order: `listener → poller → publisher`.
  - `PkarrConfig::offer_poll: OfferPollConfig` — `poll_secs` (default 1), `watched_clients` (z-base-32 client pubkeys; **pre-pairing stopgap** until PR #7b's allowlist-driven watched list lands), `per_client_throttle_secs` (default 5). `Config::validate` parses each `watched_clients` entry as z-base-32 at load time so typos fail loudly.
  - New `DaemonError::OfferPoll(OfferPollError)` — `Decrypt` / `AnswerBuild` / `Pkarr` / `Handshake` variants.
  - New `tests/offer_poll.rs` + `ScriptedResolve` / `CaptureTransport` helpers in `tests/support`: happy path (scripted sealed offer → answer pushed into `SharedState`), dedup (same offer twice → one `handle_offer` call), wrong-recipient (sealed to a different daemon pubkey → no answer), watched-list filter (offer from an unwatched client → no `handle_offer` call).
  - **BEP44 answer-size hazard documented.** A full webrtc-rs answer SDP with trickled ICE candidates routinely exceeds the 1000-byte BEP44 `v` cap when folded alongside the main `_openhost` record. The encoder evicts the oldest answer; the PR #7a integration test asserts against `SharedState` (the answer is produced + queued) rather than the wire packet (where it may have been evicted). Splitting ICE trickle into separate pkarr records is flagged `TODO(v0.1 freeze)` against `spec/01-wire-format.md §3.3`.
  - **Two deviations from `spec/01-wire-format.md §3` are flagged `TODO(v0.1 freeze)`:** (1) the daemon polls explicitly-configured client pubkeys rather than "its own `_offer.*`" — the spec's wording is inconsistent with BEP44's per-pubkey zone model, so PR #7a interprets "poll the watched clients' zones for an `_offer-<host-hash>` TXT sealed to the daemon"; (2) the answer-publication mechanism (`_answer-<client-hash>` inside the main `_openhost` packet) is a PR #7a extension not in the original spec text — documented inline in spec §3.3 and the crate README.

- `openhost-daemon` M5.5 channel binding via RFC 5705 DTLS exporter:
  - New `openhost_daemon::channel_binding` module. `ChannelBinder::verify_client_sig` validates a 96-byte `AuthClient` payload (32-byte `client_pk` || 64-byte `sig_client`) against the shared exporter-derived `auth_bytes`; `ChannelBinder::sign_host` produces the 64-byte `AuthHost` signature. The binder lives behind an exporter-secret-in / `ChannelBindingError`-out interface that makes it testable without a live WebRTC stack.
  - Three new `FrameType` variants on the wire: `AuthNonce` (0x30, 32 bytes), `AuthClient` (0x31, 96 bytes), `AuthHost` (0x32, 64 bytes). Frame vectors in `spec/test-vectors/wire.json` extended with canonical encodings for each.
  - Per-data-channel state machine in the listener: `Pending` → `AwaitingAuthClient{nonce}` → `Authenticated{client_pk}`. `on_open` generates a fresh 32-byte nonce via OS CSPRNG, sends `AuthNonce`, and arms a 10 s timeout task; the first inbound frame MUST be `AuthClient` or the channel is torn down with an `ERROR` frame. After a valid `AuthClient` the daemon emits `AuthHost`, transitions to `Authenticated`, and only then starts accepting `REQUEST_*` / `PING`. Auth frames that arrive after authentication are rejected as a protocol violation.
  - **Workspace `[patch.crates-io]` entry routes `webrtc` through `github.com/kaicoder03/webrtc` at a pinned SHA.** The fork adds a public `RTCDtlsTransport::export_keying_material(label, length)` passthrough so the daemon can reach the RFC 5705 exporter the binding handshake needs. Upstream webrtc-rs v0.17.x keeps `RTCDtlsTransport::conn` `pub(crate)`; an upstream PR is pending. The SHA is pinned immutably so CI is reproducible and an untrusted push to the fork can't silently change what the daemon compiles against.
  - Shared test helper at `crates/openhost-daemon/tests/support/mod.rs` drives the full client-side binding dance (including `BindingMode::{Honest, SendRequestBeforeBinding, TamperSignature, SwapPubkey, TimeoutByNeverAuthing}`); `tests/listener.rs` and `tests/forward.rs` now authenticate through the binder on every test. New `tests/channel_binding.rs` exercises the five state-machine outcomes end-to-end (happy path, pre-auth REQUEST, tampered sig, pk/sig mismatch, timeout), all on real time because `tokio::time::pause` does not play with webrtc-rs internals.
  - **RFC 8844 unknown-key-share attack surface closes on the daemon side.** A client that cannot produce the correct `sig_client` over the shared exporter-derived bytes is dropped before any forwarded request reaches the upstream.
  - **Two deviations from `spec/01-wire-format.md §3 step 9` are flagged `TODO(v0.1 freeze)` and reconciled at v0.1 cut:** (1) the message order is inverted (daemon sends `AuthNonce`, client signs first with `AuthClient`, daemon replies with `AuthHost`) because PR #5.5 ships before PR #7's offer-record plumbing — without an offer record the daemon has no source of truth for `client_pk` before the client speaks. (2) Binding bytes fold into HKDF `info` instead of the DTLS exporter `context` because `webrtc-dtls` v0.17.x rejects a non-empty exporter `context` (`ContextUnsupported`); cryptographically equivalent (exporter secret is session-unique; HKDF still commits to `host_pk || client_pk || nonce`) but the spec text currently layers it the other way.
  - **Authorization is still TODO (PR #7).** PR #5.5 proves the client holds the private key corresponding to the `client_pk` it presented. It does NOT check whether that pubkey is allowed to connect. Any syntactically valid Ed25519 keypair passes binding. The `_allow` record allowlist check lands with PR #7.
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
- `openhost-daemon` M6.1 localhost HTTP forwarder + SSRF defense:
  - New `openhost_daemon::forward::Forwarder`: wraps a `hyper_util::client::legacy::Client` pointed at the configured upstream; `Forwarder::forward(head_payload, body)` parses the inbound HTTP/1.1 request head, sanitises headers, dispatches via hyper, collects the upstream body, and returns the re-encoded response head + body ready for the listener to re-frame.
  - **Spec §4.1 / §7.12 SSRF defences applied on every request:** hop-by-hop headers (RFC 7230 §6.1) stripped (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`); provenance headers blocked (`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded`, `X-Real-IP`); `Host` pinned to the configured target's authority; `Upgrade: websocket` rejected with a typed `WebSocketUnsupported` error. The upstream's response is similarly sanitised (hop-by-hop stripped) and `Content-Length` is rewritten to match the buffered body so a `Transfer-Encoding: chunked` upstream can't leak through our binary framing.
  - `ForwardConfig` extended with `host_override` (optional, defaults to the target's authority) and `max_body_bytes` (default 16 MiB). `Config::validate` rejects non-`http://` targets and zero-size body caps.
  - Listener now accumulates `REQUEST_HEAD` → `REQUEST_BODY*` → `REQUEST_END` into a per-DC `RequestInProgress` state; on `REQUEST_END` it calls the forwarder and emits `RESPONSE_HEAD` + one-or-more `RESPONSE_BODY` frames (chunked at `MAX_PAYLOAD_LEN` = 16 MiB − 1) + `RESPONSE_END`. If no `[forward]` section is configured the PR #5 stub 502 path remains active — daemons deployed purely as discovery targets stay serviceable. Frame-order violations (REQUEST_BODY before HEAD, REQUEST_END without HEAD, unexpected RESPONSE_* from the client) emit spec §5 `ERROR` frames and tear the channel down.
  - `App::build` / `App::build_with_transport` build a `Forwarder` alongside the listener and thread it into `PassivePeer::new`. `Ping` → `Pong` keepalive responses are now wired (previously ignored).
  - Workspace deps: `hyper` 1, `hyper-util` 0.1 (`client-legacy` + `http1` + `tokio`), `http` 1, `http-body-util` 0.1. All transitively in the tree already; listed explicitly so the daemon compiles against a pinned version. The `hyper` `server` feature is only enabled under `[dev-dependencies]` for the integration-test upstream.
  - Tests (+25 across lib + integration): 20 unit tests covering every sanitiser / parser / encoder branch (hop-by-hop stripping, provenance stripping, Host pinning, websocket rejection, request-head parse failures, Content-Length rewrite, response head hop-by-hop stripping, Forwarder::from_config scheme / URL / host_override validation, target-path composition including absolute-form request lines). 5 integration tests (`tests/forward.rs`) spin up an in-process hyper test server and drive real DTLS handshakes: GET 200 round-trip, POST body verbatim, hop-by-hop + provenance stripping verified at the upstream, Host pinned to target authority, upstream-unreachable → 502 stub response.
  - **First demonstrable end-to-end HTTP round-trip through the openhost protocol.** With `openhostd run` pointed at a local HTTP service, a client-side `RTCPeerConnection` (manual today, PR #8 will ship the client) can send a framed request and receive the upstream's response.
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

[Unreleased]: https://github.com/kaicoder03/openhost/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kaicoder03/openhost/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kaicoder03/openhost/tree/v0.1.0
