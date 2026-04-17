---
title: openhost Protocol — Overview
---

# openhost Protocol — Overview

**Status:** Draft (M0). Subject to breaking change until the first tagged release.

openhost is a protocol for reaching a self-hosted HTTP service from a paired client device, without opening a port on the host, without a tunnel service in the data path, and without depending on any infrastructure operated by the openhost project itself.

The design uses three existing, mature technologies:

1. **WebRTC data channels** — browser-native, NAT-traversing, DTLS 1.3-encrypted transport.
2. **[Pkarr](https://pkarr.org/)** over the BitTorrent **Mainline DHT** — signed DNS records keyed by Ed25519 public keys, resolvable without any DNS server openhost operates.
3. **Ed25519 identities** — the host's public key *is* its address.

## Goals

- **No port forwarding.** The host is reachable without any inbound firewall rule.
- **No tunnel service in the data path.** Traffic is end-to-end encrypted between client and host; no third party ever sees plaintext.
- **No vendor relationship.** openhost runs no servers, owns no domains, and charges no fees. A client that conforms to this spec is a complete client forever.
- **Cryptographic pairing, not network pairing.** A client's authority to connect derives from its keypair, not its network location.
- **Professional clients.** Desktop browser extension, native iOS/macOS apps. CLI is for operators, not end-users.

## Non-goals

- Generalized VPN or mesh networking (see Tailscale, Nebula).
- Public web hosting for arbitrary audiences (see Cloudflare Tunnel, ngrok).
- Anonymity at the transport layer (see Tor). openhost discloses the host's public key by design.
- High-throughput streaming with latency guarantees. WebRTC data channels are reliable, ordered, and suitable for HTTP-sized payloads; bulk streaming is possible but not optimized.

## Document set

| Document | Contents |
|---|---|
| [`01-wire-format.md`](01-wire-format.md) | Identity encoding, connection sequence, DataChannel framing grammar |
| [`02-pairing.md`](02-pairing.md) | QR + BIP39 + SAS pairing protocol *(drafted at M2)* |
| [`03-pkarr-records.md`](03-pkarr-records.md) | Record schema, relay and DHT fan-out, Nostr tertiary substrate |
| [`04-security.md`](04-security.md) | Threat model, invariants, and identified attacks with mitigation status |

Test vectors for every primitive live in [`test-vectors/`](test-vectors/).

## Architecture

```
┌────────────────────────────────────────┐        ┌────────────────────────────────────────┐
│  Client (iOS / macOS / extension)      │        │  Host (Mac, Linux server, Pi, ...)     │
│                                        │        │  ┌──────────────────────────────────┐  │
│  Renders user's self-hosted service    │        │  │ Existing HTTP server             │  │
│  (Jellyfin, Home Assistant, Gitea, ... │        │  │ on 127.0.0.1:<port>              │  │
│                                        │        │  └───────────────▲──────────────────┘  │
│  fetch() ──►                           │        │                  │  loopback HTTP      │
│                                        │        │                  │                     │
│  openhost client:                      │        │  openhost daemon:                      │
│   1. Resolve pubkey via Pkarr          │        │   1. Publish signed record to Pkarr    │
│   2. WebRTC offer/answer               │ DTLS / │   2. Accept WebRTC DTLS handshake      │
│   3. HTTP-over-DataChannel             │◄──────►│   3. Forward streams to loopback       │
└────────────────┬───────────────────────┘        └────────────────┬───────────────────────┘
                 │                                                 │
                 ▼                                                 ▼
         ┌──────────────────────────────────────────────────────────────┐
         │   Public discovery substrate: Mainline DHT + Pkarr relays    │
         │   (plus optional Nostr relays as a tertiary path; see 03)    │
         └──────────────────────────────────────────────────────────────┘
```

## Implementation-level decision records

### WebRTC crate choice

openhost-daemon and openhost-client depend on the [`webrtc`](https://crates.io/crates/webrtc) Rust crate. At the time of the M0 specification (April 2026):

- `webrtc` v0.17.x is the final Tokio-coupled release line; feature-frozen in January 2026 with only bug fixes going forward on that branch.
- `webrtc` v0.20-alpha and later target a sans-I/O architecture on top of the new `rtc` crate, allowing runtime-agnostic embedding.

**M3 and v0.1 use v0.17.x** for stability. Migrating to the sans-I/O line is tracked as a post-v0.1 task and will be undertaken once v0.20 reaches a stable release.

### Ed25519 library choice

openhost uses [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) v2 for signing and verification. All Ed25519 keypairs in openhost are generated via a system CSPRNG and pass strict RFC 8032 compliance (strict canonicalization on verification, no malleable signatures accepted). See [`04-security.md`](04-security.md) for the rationale.

## Versioning

The protocol version is carried in the top-level Pkarr TXT record as `v=openhost1`. A breaking change increments the integer; clients reject records with a version they do not implement.

Within `openhost1`, the record schema, framing, and handshake sequence are specified in this document set. Backwards-compatible extensions append new record names or framing type codes; those are negotiated by feature probes, not by version bumps.
