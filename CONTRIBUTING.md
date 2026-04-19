# Contributing to openhost

Thanks for looking. openhost is pre-1.0 software with a small surface area and a deliberate pace — small, focused changes land faster than sweeping rewrites, and the protocol specification is the authoritative contract for every crate.

This document covers:

- [Dev setup](#dev-setup)
- [Running the tests](#running-the-tests)
- [PR cadence](#pr-cadence)
- [Proposing a spec change](#proposing-a-spec-change)
- [Filing good bug reports](#filing-good-bug-reports)
- [Security reports](#security-reports)
- [Where to ask questions](#where-to-ask-questions)

## What kinds of changes are welcome

- **Bug fixes** with a reproducing test case.
- **Docs**: clarifications to the site guides, examples under `examples/`, per-crate READMEs, protocol prose under `spec/`.
- **New examples** of services you want to see exposed over openhost — follow the shape of [`examples/personal-site/`](examples/personal-site/).
- **Crate improvements** that match the roadmap in [`ROADMAP.md`](ROADMAP.md).
- **Spec changes** — see [Proposing a spec change](#proposing-a-spec-change) below; please discuss in an issue first for anything non-trivial.

What's out of scope without discussion: broad re-architectures, additional substrates beyond Pkarr + Mainline DHT, and anything that conflicts with the scope in [`spec/04-security.md`](spec/04-security.md).

## Dev setup

- **Rust 1.90 (stable).** Pinned via [`rust-toolchain.toml`](rust-toolchain.toml) — `rustup` fetches it automatically the first time you build. Install `rustup` from <https://rustup.rs/> if you don't have it.
- **pnpm 10+** — only if you're going to touch the documentation site under `site/`.
- **A working C toolchain.** Linux: `build-essential` or equivalent. macOS: Xcode command line tools. Windows: MSVC. `ring` uses assembly fast paths that need a C compiler.

Clone and sanity check:

```bash
git clone https://github.com/kaicoder03/openhost.git
cd openhost
cargo check --workspace          # compiles every crate, no binaries produced
```

Optional: build the production binaries that the examples reference.

```bash
cargo build --release -p openhost-daemon
cargo build --release --features cli -p openhost-client
```

## Running the tests

The full workspace suite is fast — under ten seconds on a warm machine for everything except the integration tests that spin up a real WebRTC stack.

```bash
# Unit + integration tests.
cargo test --workspace --all-features --no-fail-fast

# Lints — CI fails on any warning.
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Formatting — CI fails on drift.
cargo fmt --all --check
```

### Opt-in real-network tests

A handful of tests are gated behind `--features real-network` and `#[ignore]`. They publish to public Pkarr relays + the Mainline DHT. CI never runs them; run manually before publishing a relay-related change:

```bash
cargo test -p openhost-daemon --features real-network -- --ignored
cargo test -p openhost-pkarr --features real-network -- --ignored
```

### Documentation site

```bash
cd site && pnpm install && pnpm build
```

The site is built and deployed by `.github/workflows/pages.yml` on every push to `main` that touches `site/` or `spec/`.

## PR cadence

We merge one PR at a time through the same five-step loop every time:

1. **Plan.** Open an issue (or a draft PR with just a plan) for non-trivial changes so scope is clear before you write code. For small bug fixes, a commit message that explains the problem is enough.
2. **Implement** on a topic branch off `main`. Small, focused commits; a fixup commit or two for lint/fmt is fine.
3. **Self-review.** Read your own PR diff on GitHub before requesting review. The [PR template](.github/PULL_REQUEST_TEMPLATE.md) lists the exact checklist to run through.
4. **Fix every concern** raised in review, not just the ones flagged high-priority. Push follow-up commits to the same branch; GitHub squashes at merge.
5. **Merge.** Squash-merge keeps `main`'s history to one commit per PR, matching the titles under [`git log`](https://github.com/kaicoder03/openhost/commits/main).

A few conventions:

- **Conventional commit subjects**: `feat(daemon): …`, `fix(pkarr): …`, `docs: …`, `chore: …`. Verbose body; one paragraph minimum explaining *why*.
- **Spec changes** get an explicit "Protocol change" checkbox on the PR template with a compatibility note. See below.
- **CHANGELOG updates** go in the `[Unreleased]` section of [`CHANGELOG.md`](CHANGELOG.md) as part of the PR, not a follow-up.
- **Co-authoring**: credit tools and humans who helped with a `Co-Authored-By:` trailer on the commit.

## Proposing a spec change

The protocol lives at [`spec/`](spec/) and is the canonical contract between every implementation. A change there is a change to the wire format, record layout, channel binding, or threat model — anything a future client could trip over.

- **Open an issue first** for non-trivial spec changes (ABI-breaking layout, new record shape, a new handshake step). A PR can follow once direction is clear.
- **Minor clarifications** (wording, typos, examples that don't change semantics) are fine as a direct PR.
- Every spec-touching PR must fill in the **Compatibility** section of the PR template: what breaks, which protocol-version field moves, what clients must do to interop across the change.
- `spec/**` is markdown-linted by `.github/workflows/spec-lint.yml`; see the errors reported there if your PR fails the workflow.

## Filing good bug reports

Use the [`Bug report`](https://github.com/kaicoder03/openhost/issues/new?template=bug_report.yml) template. Three attachments that turn "something's broken" into "actionable":

1. **`openhost-resolve --json oh://<host-pubkey>/`** — for anything involving discovery. This proves (or disproves) that the daemon's record is reaching you at all.
2. **Daemon log at debug level:**

   ```bash
   RUST_LOG=openhost_daemon=debug,openhost_pkarr=debug openhostd run 2>&1 | tee /tmp/openhostd.log
   ```

   Trim to the 30-second window around your reproduction and paste it into the bug report.
3. **Client-side stderr** from the failing invocation:

   ```bash
   openhost-dial oh://<host-pubkey>/your/path 2>&1 | head -80
   ```

The [Troubleshooting guide](https://kaicoder03.github.io/openhost/guides/troubleshoot/) is a reasonable place to check before filing — it covers the most common failure modes and their diagnostic commands.

For **feature requests**, use the [`Feature request`](https://github.com/kaicoder03/openhost/issues/new?template=feature_request.yml) template. Concrete user stories ("I want to expose X because Y") land faster than open-ended asks.

## Security reports

**Do not file security vulnerabilities as public issues.** Use GitHub's private Security Advisories:

<https://github.com/kaicoder03/openhost/security/advisories/new>

See [`SECURITY.md`](SECURITY.md) for scope and the 72-hour response target. The [threat model in `spec/04-security.md`](spec/04-security.md) is canonical for what's in-scope.

## Where to ask questions

- **Concrete bugs or feature requests:** open a GitHub issue using the templates linked above.
- **General questions** ("does openhost handle X?", "should I use it for Y?"): open an issue with the *question* label. GitHub Discussions is not currently enabled on this repo; if you'd find it useful, that itself is worth an issue.
- **Spec questions** deserve a dedicated issue so the answer stays findable.

Thanks again. If something in this document is wrong or unclear, a PR to fix it is the best way to tell us.
