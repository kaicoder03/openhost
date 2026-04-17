---
title: openhost vs. the alternatives
description: How openhost compares to ngrok, Tailscale Funnel, Cloudflare Tunnel, and port forwarding for a self-hoster.
sidebar:
  order: 2
---

If you self-host, you've likely already tried one of these solutions for reaching your services from outside your LAN. Each of them works. Each of them trades away something a self-hoster actually cares about. Here's a clear-eyed comparison.

## ngrok

**What it does well.** Stupid-easy setup — one command and you have a public URL. Great for ad-hoc demos, webhook development, and debugging. First-class support for inspecting request/response traffic in their dashboard.

**What it trades away.**

- **Traffic flows through ngrok's servers.** TLS is terminated at ngrok; they can see your plaintext data. For an app you actively use, that's a lot of trust.
- **Free tier gives you a random URL.** For a stable domain you pay at least $5/month.
- **Requires an ngrok account.** Stored API tokens, authenticated agents, all the usual SaaS dependencies.

**When ngrok is still the right choice.** Short-lived demos. Webhook development. Anything you'd show a customer in a meeting and then shut down.

## Tailscale Funnel

**What it does well.** Tailscale is an excellent mesh VPN. Funnel extends it to expose one of your tailnet endpoints to the public internet at a `*.ts.net` subdomain, with automatic HTTPS and a clean access-control model. The engineering quality is very high.

**What it trades away.**

- **Requires a Tailscale account.** Your tailnet membership, access grants, and identity all live in Tailscale's coordination plane. If Tailscale goes away, your config goes with it.
- **Public endpoints are on `*.ts.net`** — fine for yourself, less so for sharing with non-Tailscale users.
- **DERP relay fallback** means when direct paths aren't available, your traffic flows through Tailscale-operated relays. The traffic is encrypted end-to-end, but the traffic graph is visible to them.
- **Funnel specifically is rate-limited on free tiers** and has caveats about what kinds of traffic are permitted.

**When Tailscale is still the right choice.** If you want a general-purpose mesh between many of your own devices and services, Tailscale (or its open-source cousin Headscale) is the right tool. openhost is not trying to be that.

## Cloudflare Tunnel

**What it does well.** Puts your service behind Cloudflare's global edge. Free for personal use (with a Cloudflare account). You get DDoS protection, their WAF, their caching — all the things Cloudflare is good at.

**What it trades away.**

- **Cloudflare terminates your TLS at their edge** and re-encrypts to your origin. This is how caching and WAF work; it's also an architectural decision to trust Cloudflare with your plaintext. Fine for public blogs, harder to swallow for private dashboards.
- **You must own a domain on Cloudflare.** Small cost, small ongoing commitment, but not nothing — and it makes the whole setup dependent on your continued Cloudflare relationship.
- **One company, one point of policy.** Cloudflare's business decisions (like who they will and won't host) affect you.

**When Cloudflare Tunnel is still the right choice.** If you're exposing a site to the *public* internet (a blog, a product landing page), and you *want* the caching/WAF layer, Cloudflare Tunnel is hard to beat.

## Port forwarding + DDNS

**What it does well.** Free, no accounts, no middle layer. Direct connections. You own the whole path.

**What it trades away.**

- **Your router has to cooperate.** If your ISP uses CGNAT (increasingly common on consumer connections), port forwarding doesn't work at all.
- **Exposes a public port.** That port is now scanned constantly by the internet. Keeping the service patched and hardened is entirely on you.
- **DDNS still needs a domain**, typically a paid one, unless you use a free DDNS provider — which reintroduces a middle party with weaker guarantees.

**When port forwarding is still the right choice.** You have a static or near-static IP, CGNAT isn't in the picture, and you want zero dependencies. Honestly, if that describes you, keep doing what you're doing.

## How openhost is different

- **No middle.** openhost connections go straight from client to host. Nothing in the data path sees plaintext. The only server openhost uses for discovery is the public Mainline DHT — which isn't operated by anyone in particular, has existed for 15+ years, and has ~15 million nodes.
- **No account.** Your identity is an Ed25519 keypair. There is no signup, no auth flow, no password.
- **No company.** The openhost project owns no domain, runs no infrastructure, and charges nothing. If the project went away tomorrow, a spec-conforming client would keep working as long as the public DHT and Pkarr relays stayed online.
- **No port open.** WebRTC hole-punches through NAT for the common cases, including most CGNAT setups.
- **Address stability.** Your host's address is its pubkey. It never expires. It never changes (unless you rotate the key, which you might never do).

## The honest downside

openhost is pre-alpha. It isn't audited. It doesn't have apps you can install from the App Store yet. For a self-hoster who just wants to reach Jellyfin on their phone *today*, Tailscale Funnel is the pragmatic choice.

What openhost is betting on: that "competent company in the middle" is not the only option available for the self-hoster use case, and that with mature off-the-shelf cryptography and a decade-old DHT, a zero-middle design is tractable.

If that bet resonates with you, [follow the repo](https://github.com/kaicoder03/openhost) and wait for the M1 tag.
