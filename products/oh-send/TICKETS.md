# oh-send — 90-day ticket scope

Q2 2026. Twelve tickets across three tracks (protocol, product, launch). Each ticket names its dependency on the existing `ROADMAP.md` phases and its acceptance criteria.

Sequencing assumption: the Phase 1 items in `ROADMAP.md` (answer-SDP chunking, `openhost-dial` CLI, pair-DB hot reload) are either landed or near-landed; recent commits (`4814fc8`, `9b8cef1`, `fb82fd4`, `291debd`) suggest the wire-format and daemon work is tracking. This plan picks up from that baseline.

Estimates are calendar weeks assuming a 4-person team (2 Rust/systems, 1 TS/WASM, 1 design — per business plan §10). A `★` marks the critical path.

---

## Track 1 — Protocol work that unblocks the product

### T-01 ★ TURN fallback, geo-routed
**Depends on:** Phase 1 landed.
**Blocks:** T-05, T-07, T-10.
**Estimate:** 3 weeks.

Ship encrypted relay fallback for the 8–12% of sessions where direct connection fails (symmetric NAT, CGNAT, strict corporate firewalls). Run `coturn` in three regions (US-East, EU-Central, AP-Singapore) on Hetzner; geo-route via DNS; authenticate short-lived TURN credentials from a minimal REST API signed by the sender's Ed25519 key so anonymous free-tier use can't be abused.

**Acceptance:**
- Session-level `relayed_byte_ratio` metric exported; weekly review KPI.
- Free-tier hard cap at 5 GB/month relayed, enforced server-side by Ed25519-signed quota tokens.
- Connection success rate ≥ 99% across a test matrix of 20 NAT topologies (document the matrix).
- Ciphertext still opaque to the relay — add a conformance test that asserts the relay sees only ChaCha20-Poly1305 records.
- ~$180/month infra cost documented and paid from the seed round, not personal cards.

### T-02 Streaming transfer (files > RAM)
**Depends on:** Phase 1 landed.
**Blocks:** T-05, credibility of the "unlimited size" claim on landing page.
**Estimate:** 4 weeks.

Today `openhost-client` assumes an in-memory buffer. Move to a chunked/streaming API in the `openhost-client` crate with backpressure, resumable chunk acknowledgment, and integrity framing (per-chunk MAC, not just whole-file). The CLI ships the `oh-send file.mkv` UX on top.

**Acceptance:**
- Public API change documented in `crates/openhost-client/CHANGELOG.md`.
- 100 GB end-to-end transfer test in CI (or nightly, if CI runners can't allocate).
- Memory ceiling ≤ 64 MB at any transfer size.
- Benchmark: ≥ 80% of raw link bandwidth on loopback; ≥ 60% across a 50 ms RTT link.
- Fuzz tests for the chunk framing.

### T-03 WASM build of `openhost-client`
**Depends on:** existing `openhost-pkarr-wasm`.
**Blocks:** T-05.
**Estimate:** 2 weeks.

Compile the transfer client itself to `wasm32-unknown-unknown`, not just the Pkarr resolver. The extension work (`ROADMAP.md` Phase 3) scaffolds some of this; oh-send needs the transfer-specific surface exposed. Reproducible builds from day one — pin the toolchain in `rust-toolchain.toml`, verify binary hash in CI.

**Acceptance:**
- `wasm-pack build` produces a < 450 KB compressed artifact.
- Reproducible build: two independent builds produce byte-identical artifacts.
- Browser support matrix: Chrome ≥ 120, Firefox ≥ 115, Safari ≥ 17. Document any gaps (Safari WebRTC data-channel quirks suspected).
- Audit the WASM sandbox for `spec/04-security.md` threat-model compliance.

### T-04 Pkarr relay cluster (self-operated)
**Depends on:** Phase 1 landed.
**Blocks:** launch reliability.
**Estimate:** 1.5 weeks.

Today we rely on the public Pkarr relay pool and the public Mainline DHT. For launch, run our own Pkarr relay in the same three regions as TURN so we're not single-pointed on upstream operator liveness. Contribute any fixes back upstream to the `pkarr` project.

**Acceptance:**
- 99.5% monthly uptime SLO on our Pkarr relays, monitored with Prometheus.
- Client resolver prefers our relays but retains the public pool as fallback — never hard-dependent on us.
- Upstream PR opened for at least one issue we hit during operation (signal of "we're contributing, not just consuming").

---

## Track 2 — Product surface

### T-05 ★ `oh-send.dev` web client (alpha)
**Depends on:** T-01, T-03.
**Blocks:** T-09, T-11.
**Estimate:** 4 weeks.

Drag-and-drop single-page app at `oh-send.dev`. Renders the copy in `LANDING.md`. Wraps the T-03 WASM client. No server-side component except a static CDN (Cloudflare Pages). Pubkey generated in-page, stored in `indexedDB` with an export-to-file option.

**Acceptance:**
- Lighthouse ≥ 95 on performance, accessibility, best practices.
- First meaningful paint < 1.2 s on a cable connection, < 2.5 s on 3G Slow.
- No third-party JS in the critical path (analytics via self-hosted PostHog, error tracking via Sentry — both lazy-loaded).
- Works on Chrome/Firefox/Safari/mobile Safari/Chrome-Android.
- Keyboard navigable, screen-reader-tested on VoiceOver + NVDA.
- End-to-end test: drop a 1 GB file, copy link, open in another browser on another machine, receive the file, byte-hash matches.

### T-06 `oh-send` CLI
**Depends on:** T-02.
**Estimate:** 1.5 weeks.

Thin wrapper over `openhost-dial` with transfer-shaped UX. `oh-send ./file.mkv` prints a link, pins the sending session until the recipient connects (or timeout flag). `oh-send recv oh://…` receives. Homebrew tap (tracks `ROADMAP.md` Phase 3 distributable-binaries item).

**Acceptance:**
- `brew install kaicoder03/openhost/oh-send` works on macOS arm64 + x86_64.
- `curl -sSL install.oh-send.dev | sh` works on Linux.
- Scoop bucket for Windows (can land after launch if behind).
- `--json` output mode for scripting.
- `oh-send --version` matches `openhost-client` version from the workspace.

### T-07 Pairing UX — QR code + four-word fingerprint
**Depends on:** T-01, T-03.
**Blocks:** T-05 polish.
**Estimate:** 2 weeks.

Most transfer sessions are one-shot link-sends; but recurring-recipient pairing (the core allowlist flow) needs a UX that isn't "paste this base32 blob." Ship both a QR code (scan with phone to auto-pair) and a BIP39-style four-word fingerprint (speakable over the phone) — `spec/04-security.md` §7.3 already specs the fingerprint.

**Acceptance:**
- Sender and recipient see the same four words before the first transfer.
- QR code pairing works on iOS 16+ and Android 12+ camera apps (no custom app needed).
- Visual design reviewed and approved by the designer hire (per business plan §10).

### T-08 In-browser identity persistence + export
**Depends on:** T-03.
**Estimate:** 1 week.

IndexedDB-backed key storage; one-click encrypted export to a paper-backup JSON; one-click restore. No cloud sync in Y1 — users who need cross-device identity use the CLI or the future Drop app.

**Acceptance:**
- Key never leaves the browser unless the user explicitly clicks export.
- Export file is encrypted with a user-chosen passphrase (Argon2id + ChaCha20-Poly1305).
- Clear warning UX if the user clears browser storage ("your identity is gone; that's what you asked for").

---

## Track 3 — Launch operations

### T-09 ★ Landing page, demo video, docs
**Depends on:** T-05 alpha.
**Estimate:** 2 weeks.

Deploy `LANDING.md` as the production site. Record the 5-second demo (real browser, no stock footage, no "actor looking at laptop" cliché). Ship `/docs` with the protocol explainer, self-host guide, and comparison pages targeting "WeTransfer alternative," "Send Anywhere alternative," "Dropbox Transfer alternative," "HIPAA file transfer" keywords.

**Acceptance:**
- Demo video < 2 MB (we're not a streaming service; don't embed YouTube).
- Comparison pages cite sources for every competitor claim. Update quarterly.
- `/status` page live and linked in footer.
- Privacy policy and terms reviewed by counsel before launch (not after).

### T-10 Observability + abuse signals
**Depends on:** T-01, T-05.
**Estimate:** 1.5 weeks.

Aligns with `ROADMAP.md` Phase 3 observability item. Ship `/health` on the daemon, Prometheus metrics, structured logs. Add a minimal abuse-signal pipeline: Pkarr pubkeys reported for distributing reported content get flagged (we can't read content, but we can observe *that* a pubkey is mass-fanning out links). Publish a transparency report template at M12.

**Acceptance:**
- Grafana dashboard reviewed by the on-call rotation before launch.
- PagerDuty / Opsgenie alerts for: Pkarr relay down, TURN region down, relayed-byte ratio > 15%, error budget burn.
- Abuse-signal pipeline documented in `SECURITY.md` with clear scope (we log metadata only, never content; we never decrypt).

### T-11 ★ HN / r/selfhosted / Lobsters launch
**Depends on:** T-05, T-09, T-10.
**Estimate:** launch week (day 1 HN, week 1 follow-ups).
**Not shipped before:** every Track 1 + Track 2 ticket above is closed.

Dual-post: HN ("Show HN: oh-send — WeTransfer without the upload") and r/selfhosted (lead with the self-host pitch, not the hosted product). Lobsters a day later. Prep the `README.md` and repo top-of-file for a flood of first-time visitors. Assign on-call for launch day.

**Acceptance:**
- ≥ 50k unique visitors week-one.
- ≥ 1k self-host installs reporting via opt-in telemetry.
- Zero credential-exposure / takedown / abuse incident in launch week (if this fails we pause paid launch).
- Post-mortem written in week 2, regardless of outcome.

### T-12 Paid launch (Pro tier, $5/mo)
**Depends on:** T-11 stable, T-01 TURN quota enforcement watertight.
**Estimate:** 2 weeks, starts M5.
**Post-launch gate:** relayed-byte ratio ≤ 12% and no sustained incident for 4 weeks.

Stripe integration. Pro unlocks: multi-concurrent transfers, 100 GB/month relayed, custom `oh-send.dev/<handle>` vanity URL, 30-day pair history, priority support (shared inbox SLA). No feature that requires us to see file contents. Pricing: $5/mo or $48/yr.

**Acceptance:**
- Stripe webhook handler is idempotent and tested.
- Customer-portal self-service for billing changes (no support-ticket bottleneck).
- First 200 Pro subs targeted by M6 per business plan §12.

---

## Calendar (aggregated)

```
Week:        1  2  3  4  5  6  7  8  9  10 11 12 13
T-01 TURN    ▓▓▓▓▓▓▓▓▓▓▓▓
T-02 stream  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
T-03 WASM             ▓▓▓▓▓▓▓▓
T-04 Pkarr            ▓▓▓▓▓▓
T-05 web                      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
T-06 CLI                          ▓▓▓▓▓▓
T-07 pair                                ▓▓▓▓▓▓▓▓
T-08 idp                                 ▓▓▓▓
T-09 landing                                   ▓▓▓▓▓▓▓▓
T-10 obs                                          ▓▓▓▓▓▓
T-11 launch                                             ▓▓
T-12 paid                        (starts M5 — outside 90-day window)
```

Critical path is T-01 → T-03 → T-05 → T-09 → T-11. Everything else is parallelizable.

## Risks this plan does not yet mitigate

- If T-01 slips by more than 2 weeks, the launch date (week 13) slips 1:1. Budget 20% schedule risk on T-01 specifically — it depends on operational unknowns (NAT variety in the real world).
- If the Safari WebRTC data-channel quirks we flagged in T-03 turn out to be blocking (not just slow), Safari support moves to fast-follow and we launch Chrome + Firefox only. Decision gate at end of week 4.
- If the designer hire (business plan §10) lands later than week 3, T-07 starts late; pairing UX is the weakest plausible product area and we should not ship without design review.

## What this plan does not include

- Marketing spend (no paid ads in the 90 days — see business plan §8).
- Teams tier (Q3 2026, separate scope doc in `products/oh-business/` when we get there).
- Drop native apps (M15+ per business plan §12).
- SOC2 (M18 per business plan §12).

Update this doc in-place as tickets land; do not create a parallel tracking surface.
