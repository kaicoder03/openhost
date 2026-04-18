# Roadmap

Where openhost is going after the `v0.1.0` tag. This document is intent, not a contract — priorities can shift in response to testing feedback, spec changes, or upstream library movement. For historical detail on what already shipped, see [`CHANGELOG.md`](CHANGELOG.md).

## Status

**`v0.1.0` shipped on 2026-04-18.** The daemon, client library, Pkarr adapter, WebRTC listener, channel binding, HTTP forwarder, pairing allowlist, and per-client rate limiter are all merged and tagged. Three known limitations carry over into the post-v0.1 work — see Phase 1 below.

openhost remains **pre-audit software**. Do not expose services you cannot afford to have compromised. See [`SECURITY.md`](SECURITY.md) for threat-model scope and reporting.

## Phase 1 — close v0.1 known limitations

Three items from the `v0.1.0` release notes are user-visible enough to block a meaningful testing round. Each gets its own focused PR.

- **Split the WebRTC answer across multiple Pkarr records.** A full trickled answer SDP, sealed and base64url-wrapped alongside the main `_openhost` record, can exceed BEP44's 1000-byte `v` cap. Today the encoder evicts the oldest queued answer to fit, so a paired client's first poll may miss the response. The fix chunks `_answer-<client-hash>-<n>` across multiple records; the dialer reassembles before unsealing.
- **Ship `openhost-dial` as a first-class client CLI.** `v0.1.0` shipped `openhost-resolve` for record inspection only. A new `openhost-dial oh://<host>[/path]` binary makes the first end-to-end HTTP round-trip achievable from the terminal — no Rust library integration required.
- **Hot-reload the pairing allowlist on every platform.** Today `openhostd pair add/remove` needs SIGHUP on Unix and a full daemon restart on Windows. A file-watcher on the pair-DB path removes the requirement for both, with SIGHUP retained as a secondary trigger.

Each PR lands with tests, documentation, and a short note in `CHANGELOG.md`.

## Phase 2 — docs so testers can actually try it

Protocol specs and per-crate READMEs exist, but there is no operator-facing walkthrough. Phase 2 closes that gap so early testers can go from "I heard about this" to "I have my home service reachable from my phone, and I filed a useful bug report."

- **Quickstart, install, and troubleshoot guides** under `site/src/content/docs/guides/`. Five-minute walkthrough for a local service; common failure-mode playbook (DHT misses, relay 5xx, `PollAnswerTimeout`, DTLS handshake failure).
- **Refreshed repo `README.md` plus worked `examples/`** for Jellyfin, Home Assistant, and a static personal site. Each example: a complete `daemon.toml`, client pairing steps, expected output, and gotchas.
- **`CONTRIBUTING.md` and feedback intake.** Dev setup, test commands, the plan → implement → self-review → fix-all → merge cadence we already use internally, and a "how to file good feedback" section pointing at issue templates.

## Phase 3+ — backlog

These are *intent*, not commitments. They enter the active sequence when the earlier phases land and the project has testers in the loop who can help prioritize.

- **Distributable binaries.** GitHub Releases artifacts, a Homebrew tap, a systemd unit, and a launchd plist so operators don't need a Rust toolchain.
- **Observability.** A `/health` endpoint on the daemon, Prometheus-compatible metrics, and structured-log formatting suitable for `journalctl` / `logdna` / `vector`.
- **Keychain identity backends.** Plug macOS Keychain, iOS Keychain, Linux Secret Service, and Windows Credential Manager behind the existing `openhost-daemon::identity_store::KeyStore` trait. Filesystem remains the default for servers.
- **`webrtc-rs` migration to sans-I/O.** Move to the v0.20+ `rtc` line so openhost stops depending on a forked branch of `webrtc-rs` to reach the DTLS exporter.
- **Browser extension.** Minimum-permission manifest, reproducible builds, strict CSP — per the threat-model requirements in `spec/04-security.md`.
- **iOS / macOS native apps.** BIP39 four-word fingerprint confirmation (spec §7.3), keychain-backed long-lived keys to survive iOS background eviction.
- **TLS upstream forwarding.** Today `[forward]` accepts `http://` targets only. TLS lands once upstream trust configuration is specified.
- **Per-path WebSocket allow-list.** `Upgrade: websocket` is globally rejected today; explicit per-path opt-in is the eventual path.

## How to follow along

- **Watch** the repository on GitHub to see releases as they're tagged.
- **File issues** via the templates in `.github/ISSUE_TEMPLATE/`. Bug reports that include the `openhost-resolve --json` output for your host and the daemon's log at `log.level = "debug"` are dramatically easier to act on.
- **Contribute** once `CONTRIBUTING.md` lands in Phase 2. Until then, open an issue before starting non-trivial work so we can line up direction.

Security-sensitive reports: use GitHub's private Security Advisories (see [`SECURITY.md`](SECURITY.md)), not public issues.
