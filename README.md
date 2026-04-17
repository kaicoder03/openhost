# openhost

**Your home server. Reachable. Nothing else in between.**

openhost lets you reach services running on your own computers — from any paired device, anywhere — over end-to-end encrypted WebRTC, addressed by a public key, discovered on the BitTorrent Mainline DHT.

- **No port forwarding.** WebRTC hole-punches through NAT.
- **No tunnel service.** Traffic goes directly between your devices and your server; nothing in the middle can read it.
- **No account.** Your Ed25519 public key *is* your address.
- **No servers we run.** The project owns no domain and operates no infrastructure. Discovery uses public substrates (Mainline DHT, public Pkarr relays).

## Status

**Pre-alpha.** The protocol is being specified. No user-facing builds are shipping yet. Watch the repo for the first M1 tag.

## How it works

A small daemon runs on your home server and publishes a signed DNS record, keyed by your Ed25519 public key, to the Mainline DHT (via [Pkarr](https://pkarr.org/)). Paired clients — a browser extension on desktop, native apps on iOS and macOS — resolve that record, negotiate a direct WebRTC connection using the published ICE candidates, and speak HTTP to your local service over an end-to-end encrypted data channel.

See [`spec/00-overview.md`](spec/00-overview.md) for the full protocol.

## Repository layout

| Path | Contents |
|---|---|
| `crates/` | Rust workspace: daemon, client library, FFI surface |
| `spec/` | Protocol specification (canonical markdown) |
| `site/` | Public website + docs (Astro + Starlight + Tailwind) |
| `extension/` | Browser extension (M5+) |
| `apple/` | iOS and macOS apps (M6/M7) |
| `examples/` | Worked examples — Jellyfin, Home Assistant, personal sites |

## Building from source

```bash
# Rust workspace (toolchain is pinned via rust-toolchain.toml — rustup fetches it automatically)
cargo check --workspace

# Docs site (uses pnpm)
cd site && pnpm install && pnpm dev
```

## Security

Reports of vulnerabilities: **please use GitHub's private Security Advisories** rather than filing a public issue. See [`SECURITY.md`](SECURITY.md) for scope and response commitments.

The threat model is documented in [`spec/04-security.md`](spec/04-security.md). **openhost is pre-alpha software and has not been audited. Do not use it to expose services you cannot afford to have compromised.**

## License

Dual-licensed under either of:

- Apache License 2.0 — [`LICENSE-APACHE`](LICENSE-APACHE)
- MIT License — [`LICENSE-MIT`](LICENSE-MIT)

at your option. Contributions are accepted under the same dual terms.
