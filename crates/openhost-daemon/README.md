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

## What this PR does NOT deliver

- No WebRTC listener. Published `ice` list ships empty — nothing yet to
  handshake against.
- No localhost forwarding; no allowlist; no channel binding.
- No keychain integration. `FsKeyStore` is the only backend.
- No self-hosted STUN.

All of these are tracked for future PRs on the road to v0.1.

## Opt-in smoke test

A real-network integration test is gated behind the `real-network`
feature so it never runs in CI (public relays are shared and
rate-limited). Run it manually before merging publisher-path changes:

```bash
cargo test -p openhost-daemon --features real-network -- --ignored
```
