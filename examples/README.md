# openhost examples

Worked walkthroughs for common self-hosted services. Each subdirectory carries a complete `daemon.toml` and a short `README.md` showing how to pair a client and what success looks like.

| Example | Target service | Works today? |
|---|---|---|
| [`personal-site/`](personal-site/) | A static site served by `caddy file-server` on `127.0.0.1:8080` | Yes — end-to-end. |
| [`jellyfin/`](jellyfin/) | Jellyfin on `127.0.0.1:8096` | Partial — REST API works; WebSocket-based playback / live notifications do not. |
| [`home-assistant/`](home-assistant/) | Home Assistant on `127.0.0.1:8123` | Partial — `/api/` REST works; the Lovelace UI relies on WebSockets, which are globally rejected at `v0.1.0`. |

A generic starter template lives at [`daemon.toml`](daemon.toml) — useful when the service you want to expose doesn't match any of the above.

## Why "partial"?

The daemon's `forward` module rejects every `Upgrade: websocket` request unconditionally at `v0.1.0` (see `spec/01-wire-format.md §4` and the `WebSocketUnsupported` error in `crates/openhost-daemon/src/error.rs`). Per-path WebSocket gating is tracked in [`ROADMAP.md`](../ROADMAP.md) under Phase 3+. Services that are REST-first (Jellyfin's library API, Home Assistant's `/api/` surface, anything static) work today; services whose browsers rely on WebSockets for the live experience need that follow-up PR to work end-to-end.

## Copying a walkthrough

Each `daemon.toml` is a complete file. Copy it to `~/.config/openhost/daemon.toml`, adjust the `[forward].target` if your service listens on a different port, and run `openhostd run`. No other edits required for the host side; pairing a client still follows [the quickstart guide](https://kaicoder03.github.io/openhost/guides/quickstart/).
