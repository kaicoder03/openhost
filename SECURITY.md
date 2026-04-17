# Security Policy

openhost is a cryptographic protocol and set of clients that aim to give self-hosters a direct, end-to-end encrypted path between paired devices and their own servers. Security issues are taken seriously, and this document explains how to report them and what scope the project considers in-scope.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.** Instead:

1. Open a **private security advisory** at <https://github.com/kaicoder03/openhost/security/advisories/new>.
2. Include a clear description of the issue, steps to reproduce (proof-of-concept code is welcome), affected components, and an assessment of impact.
3. If the issue involves a cryptographic construction or protocol flaw, cite the relevant spec sections from `spec/` so we can reason about it together.

During the pre-alpha period, responses may take several business days. Once the project has active releases, the target initial-acknowledgement window is **72 hours** and the target fix window is **30 days** for high-severity issues.

## Coordinated disclosure

We prefer coordinated disclosure:

- We'll confirm receipt, assess severity, and work with you on a fix timeline.
- Public disclosure happens after a fix is available, or at a mutually agreed date if a fix is not feasible.
- Security researchers who report valid issues will be credited in the advisory and the changelog unless they prefer otherwise.

## In-scope

- The openhost protocol as specified in `spec/`
- All Rust crates in this repository (`crates/`)
- The browser extension (`extension/`, when present)
- The iOS and macOS applications (`apple/`, when present)
- The build, release, and signing pipelines in `.github/workflows/`

## Out-of-scope

- Attacks that require compromising the host operating system or a paired device
- Denial-of-service attacks mounted by a global passive adversary that require sustained control of the Mainline DHT
- Social-engineering attacks against individual users that do not exploit a protocol flaw
- Issues in third-party dependencies that are already publicly tracked (please report those upstream)
- The public Pkarr relays and STUN endpoints that openhost clients use — those are operated by other projects. Please report issues there to their respective maintainers.

## Threat model

The full threat model is documented in [`spec/04-security.md`](spec/04-security.md), including explicit boundaries for what the protocol defends against and what it does not.

## No bug bounty (yet)

openhost does not currently offer monetary rewards for vulnerability reports. If that changes, it will be announced here.
