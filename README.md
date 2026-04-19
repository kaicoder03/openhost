# openhost

**Your home server. Reachable. Nothing else in between.**

openhost lets you reach services running on your own computers — from any paired device, anywhere — over end-to-end encrypted WebRTC, addressed by a public key, discovered on the BitTorrent Mainline DHT.

- **No port forwarding.** WebRTC hole-punches through NAT.
- **No tunnel service.** Traffic goes directly between your devices and your server; nothing in the middle can read it.
- **No account.** Your Ed25519 public key *is* your address.
- **No servers we run.** The project owns no domain and operates no infrastructure. Discovery uses public substrates (Mainline DHT, public Pkarr relays).

## Status

**`v0.1.0` shipped** — the daemon, client library, WebRTC listener, channel binding, and HTTP forwarder are all in `main` and tagged. No binary releases yet; build from source. See [`CHANGELOG.md`](CHANGELOG.md) for what landed, [`ROADMAP.md`](ROADMAP.md) for what's next, and [`SECURITY.md`](SECURITY.md) before exposing a service.

## How it works

A small daemon runs on your home server and publishes a signed DNS record, keyed by your Ed25519 public key, to the Mainline DHT (via [Pkarr](https://pkarr.org/)). Paired clients — a browser extension on desktop, native apps on iOS and macOS — resolve that record, negotiate a direct WebRTC connection using the published ICE candidates, and speak HTTP to your local service over an end-to-end encrypted data channel.

See [`spec/00-overview.md`](spec/00-overview.md) for the full protocol.

## Quickstart

Bring up a local HTTP service, expose it over openhost, dial it from a second machine:

```bash
# Host machine: clone, build, start an upstream, run.
git clone https://github.com/kaicoder03/openhost.git && cd openhost
cargo build --release -p openhost-daemon
cargo build --release --features cli -p openhost-client

mkdir -p ~/sites && echo '<h1>hello</h1>' > ~/sites/index.html
# Any local HTTP server will do; these examples assume port 8080.
python3 -m http.server 8080 --bind 127.0.0.1 --directory ~/sites &

mkdir -p ~/.config/openhost
cp examples/personal-site/daemon.toml ~/.config/openhost/daemon.toml
./target/release/openhostd run        # prints "openhostd: up pubkey=<zbase32>"

# Client machine (after copying the same three binaries):
openhost-dial oh://<zbase32-pubkey>/
```

The full walkthrough — including how to pair a persistent client identity and tighten the allowlist — is in the site's [Quickstart guide](https://kaicoder03.github.io/openhost/guides/quickstart/). Three service-specific examples live under [`examples/`](examples/).

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | Rust workspace: daemon, client library, FFI surface |
| `spec/` | Protocol specification (canonical markdown) |
| `site/` | Public website + docs (Astro + Starlight + Tailwind) |
| `extension/` | Browser extension (M5+) |
| `apple/` | iOS and macOS apps (M6/M7) |
| `examples/` | Worked walkthroughs: `personal-site/`, `jellyfin/`, `home-assistant/`, plus a generic `daemon.toml` template |

## Building from source

```bash
# Rust workspace (toolchain is pinned via rust-toolchain.toml — rustup fetches it automatically)
cargo check --workspace

# Docs site (uses pnpm)
cd site && pnpm install && pnpm dev
```

## Roadmap

Post-v0.1 work is sequenced in [`ROADMAP.md`](ROADMAP.md). Phase 1 closes the three known limitations from the `v0.1.0` release notes and Phase 2 lands operator-facing docs (quickstart, install, troubleshoot, worked examples for Jellyfin and Home Assistant). Phase 3+ tracks longer-horizon work: distributable binaries, observability, keychain backends, the `webrtc-rs` sans-I/O migration, browser extension, and native apps.

## Security

Reports of vulnerabilities: **please use GitHub's private Security Advisories** rather than filing a public issue. See [`SECURITY.md`](SECURITY.md) for scope and response commitments.

The threat model is documented in [`spec/04-security.md`](spec/04-security.md). **openhost is pre-audit software: `v0.1.0` has shipped but no third-party security review has taken place. Do not use it to expose services you cannot afford to have compromised.**

## Contributing

Bug reports, docs, new examples, and protocol clarifications are all welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for dev setup, test commands, PR cadence, and what makes a bug report actionable.

## License

Dual-licensed under either of:

- Apache License 2.0 — [`LICENSE-APACHE`](LICENSE-APACHE)
- MIT License — [`LICENSE-MIT`](LICENSE-MIT)

at your option. Contributions are accepted under the same dual terms.
