# openhost-daemon

Host-side openhost daemon. Publishes a signed Pkarr record that binds the
host's Ed25519 public key to a DTLS certificate fingerprint; republishes
every 30 minutes. WebRTC listener, channel binding, and the localhost
forwarder land in subsequent PRs (see roadmap in `CHANGELOG.md`).

## Quick start

```bash
# Print the host's oh:// URL (generates an identity if one doesn't exist yet)
cargo run -p openhost-daemon -- identity show --config examples/daemon.toml

# Start the daemon: publishes a record every 30 minutes, blocks until Ctrl-C
cargo run -p openhost-daemon -- run --config examples/daemon.toml
```

A default config is seeded automatically on first run if `--config` is
omitted; the path is platform-specific (`~/.config/openhost/config.toml`
on Linux, `~/Library/Application Support/openhost/config.toml` on macOS).

## Config schema

```toml
[identity]
store = { kind = "fs", path = "~/.config/openhost/identity.key" }

[pkarr]
# Empty falls back to the bundled default relay list plus the Mainline DHT.
relays = ["https://pkarr.pubky.app"]
republish_secs = 1800  # 30 min, matches spec §1

[dtls]
cert_path = "~/.config/openhost/dtls.pem"
rotate_secs = 86400    # 24 h

[log]
level = "info"
```

## Subcommands

| Command | Effect |
|---|---|
| `openhostd run` | Load identity, generate/load DTLS cert, publish pkarr record, block on SIGINT / SIGTERM |
| `openhostd identity show` | Print `oh://<zbase32-pubkey>/` and the raw z-base-32 key. Generates the identity file on first call. |
| `openhostd identity rotate` | Regenerate the DTLS certificate. Keeps the Ed25519 identity. Warns to restart the daemon so the new fingerprint reaches the next signed record. |

## Files

Everything the daemon writes is mode `0600` on Unix:

- `identity.key` — 32 raw bytes, the Ed25519 seed. Rotating this changes
  your public key; treat the file like a private key.
- `dtls.pem` — ECDSA P-256 keypair + self-signed cert bundled as PEM. The
  SHA-256 fingerprint of the cert's DER is what clients pin.

## Verifying a live record

After `openhostd run` comes up, fetch the record from a public relay:

```bash
PUBKEY=$(cargo run -q -p openhost-daemon -- identity show --config examples/daemon.toml | head -1 | sed 's|oh://||; s|/$||')
curl -s "https://pkarr.pubky.app/$PUBKEY" | xxd | head -20
```

## Acting as a listener (PR #5)

The daemon now accepts inbound WebRTC offers via
`openhost_daemon::PassivePeer::handle_offer(offer_sdp)`. The signalling
plumbing (offer-record polling over Pkarr) is PR #7's job; library
callers can drive the listener directly for tests or custom signalling.

- Inbound offers **MUST** assert `a=setup:active` or `a=setup:actpass`
  (standard WebRTC). Anything else is rejected before any
  `RTCPeerConnection` is built.
- DTLS handshakes complete against the cert whose SHA-256 fingerprint
  is pinned in the daemon's published record (`openhost-resolve` prints
  it if you want to verify).

## Forwarding to a local HTTP service (PR #6)

Configure a `[forward]` section to route every inbound `REQUEST_*`
frame to a loopback HTTP server. Omit the section and the daemon keeps
the PR #5 stub 502 response path.

```toml
[forward]
# Only http:// is supported; TLS upstreams land in a future PR.
target = "http://127.0.0.1:8080"

# Optional. Defaults to the target's authority ("127.0.0.1:8080"
# above). Override when the upstream service expects a specific
# `Host` value (e.g. a Host-based router on the upstream side).
host_override = "my-service.local"

# Cap on the inbound request body. Requests larger than this trigger
# a framing-violation teardown. Default 16 MiB.
max_body_bytes = 16777216
```

### SSRF defences (spec §7.12)

Every forwarded request gets these protections applied before the
upstream sees it:

- **Hop-by-hop headers stripped** (RFC 7230 §6.1): `Connection`,
  `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`,
  `Trailer`, `Transfer-Encoding`, `Upgrade`.
- **Provenance headers blocked**: `X-Forwarded-For`, `X-Forwarded-Host`,
  `X-Forwarded-Proto`, `Forwarded`, `X-Real-IP`. Client-supplied values
  never leak through.
- **Host header pinned** to the configured target authority
  (or `host_override` if set).
- **Websocket upgrades rejected**. `Upgrade: websocket` inbound
  requests fail with a typed error; per-path gating lands in a future
  PR.
- **Upstream response sanitised too**: hop-by-hop headers dropped and
  `Content-Length` rewritten to match the buffered body size so a
  misbehaving upstream can't smuggle `Transfer-Encoding: chunked`
  through the openhost binary frame codec.

## What this crate does NOT (yet) deliver

## What this crate does NOT (yet) deliver

- Channel binding (spec §7.1 / RFC 8844 mitigation) — PR #5.5.
- Offer-record polling + allowlist + per-IP / per-pubkey rate limit — PR #7.
- Client-side WebRTC offerer — PR #8 (`openhost-client`).
- Self-hosted STUN / IPv6-only mode — PR #9.
- Keychain integration. `FsKeyStore` is the only backend until PR #10.
- HTTPS upstreams + per-path websocket upgrade gating — post-v0.1.

## Opt-in smoke test

A real-network integration test is gated behind the `real-network`
feature so it never runs in CI (public relays are shared and
rate-limited). Run it manually before merging publisher-path changes:

```bash
cargo test -p openhost-daemon --features real-network -- --ignored
```
