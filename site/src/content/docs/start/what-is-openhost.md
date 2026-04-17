---
title: What is openhost?
description: A one-page introduction to the openhost protocol and why a self-hoster might care.
sidebar:
  order: 1
---

openhost is a protocol and a set of clients that let you reach a service running on your own computer — from a phone, a laptop, or a tablet, anywhere you happen to be — without forwarding a port, renting a tunnel, or handing your traffic to a third party.

## What it is

Three pieces, all mature technology that exists for other reasons:

- **WebRTC data channels.** Browsers already know how to hole-punch through NAT and set up end-to-end encrypted links. openhost uses that transport for HTTP.
- **Pkarr over the BitTorrent Mainline DHT.** A 15-year-old peer-to-peer DHT with millions of nodes, used to publish signed DNS records keyed by Ed25519 public keys. There is no DNS server the openhost project runs.
- **Your Ed25519 keypair as your identity.** The public key *is* the address. The private key never leaves the device it was generated on.

When you pair a client to a host, the client's public key goes onto a local allowlist on the host. From then on, connections work anywhere either device has an internet path.

## What it is not

- Not a VPN. It does not give you a network interface for arbitrary traffic.
- Not a public hosting service. The host's pubkey is its address — you wouldn't put that on a business card.
- Not anonymous. The pubkey is visible to anyone watching the DHT. What's private is the data that flows between paired devices.
- Not a substitute for a real domain when you want public audiences. For that, use Cloudflare Tunnel or a regular web host.

## Why a self-hoster would use it

You already own the computer the service runs on. You already own your data. The question is: why are you renting the network path between yourself and your server?

ngrok, Tailscale Funnel, and Cloudflare Tunnel all solve reachability by putting a company in the middle. That's a reasonable trade — those companies are competent — but it's still a trade. A company can change its pricing. A company can shut down. A company can, in certain jurisdictions, be compelled to hand over data. openhost removes that middle entirely.

## Status

Pre-alpha. The protocol is being specified; builds are not yet shipping. Watch [the repository](https://github.com/kaicoder03/openhost) for the M1 tag.

## Next

- [Comparison](/openhost/start/comparison/) — openhost vs. ngrok, Tailscale, Cloudflare, port forwarding
- [Specification overview](/openhost/spec/00-overview/) — the protocol in technical detail
- [Threat model](/openhost/spec/04-security/) — what openhost defends against and what it does not
