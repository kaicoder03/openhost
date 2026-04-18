# Jellyfin (REST-only)

Expose a [Jellyfin](https://jellyfin.org/) media server's REST API over openhost. Library browsing, item metadata, poster art, and most API-client integrations work. The web UI at `/web/` will load its shell but will NOT function fully — see [Gotchas](#gotchas) before you plan around it.

## Prerequisites

- Jellyfin installed and listening on `http://127.0.0.1:8096` (the default).
- `openhostd`, `openhost-dial`, `openhost-resolve` on your `PATH` — see [site/install](https://kaicoder03.github.io/openhost/guides/install/).

## 1. Confirm Jellyfin is up locally

```bash
curl -sI http://127.0.0.1:8096/System/Info/Public
```

Expected: `HTTP/1.1 200 OK`.

## 2. Copy this example's config

```bash
install -d -m 0700 ~/.config/openhost
cp examples/jellyfin/daemon.toml ~/.config/openhost/daemon.toml
```

## 3. Start the daemon

```bash
openhostd run
```

Watch for the "openhostd: up" line and copy the `pubkey=…` value.

## 4. Dial the REST API from a second machine

```bash
openhost-dial oh://<zbase32-pubkey>/System/Info/Public --json | jq .
```

You should see something like:

```json
{
  "status": 200,
  "status_line": "HTTP/1.1 200 OK",
  "headers": [
    ["Content-Type", "application/json; charset=utf-8"],
    ...
  ],
  "body_utf8": "{\"LocalAddress\":\"http://127.0.0.1:8096\",\"ServerName\":\"MyJellyfin\",\"Version\":\"…\",\"Id\":\"…\"}"
}
```

That's Jellyfin responding to a real HTTP request traversing the client's NAT, hole-punched through WebRTC, channel-binding-authenticated, forwarded to `127.0.0.1:8096` by the daemon.

## 5. Authenticated requests

Most of Jellyfin's API requires an `X-Emby-Token` header (the "API key" you can mint in *Dashboard → API Keys*). `openhost-dial` passes custom headers verbatim:

```bash
openhost-dial oh://<zbase32-pubkey>/Users \
  -H "X-Emby-Token: <your-api-key>" \
  --json | jq '.body_utf8 | fromjson | .[].Name'
```

## 6. Lock it down

Follow [Step 5 of the quickstart](https://kaicoder03.github.io/openhost/guides/quickstart/#5-pair-the-client-switch-to-enforced-mode) to flip `enforce_allowlist = true` and add your client pubkey to `watched_clients`.

## Gotchas

- **WebSocket features are off.** Jellyfin's web client uses WebSockets for live updates (transcoding progress, notifications). openhost v0.1.0 rejects every `Upgrade: websocket` request globally (`spec/01-wire-format.md §4`, `ForwardError::WebSocketUnsupported`). The web UI will load its HTML/CSS shell but stay stuck on a loading spinner. Per-path WebSocket gating is tracked in [`ROADMAP.md`](../../ROADMAP.md).
- **Direct-play streaming does not work.** Jellyfin's `/Videos/{id}/stream` endpoint usually returns a `206 Partial Content` over chunked transfer-encoding and is happy to work through openhost for small files, but transcoded playback starts a WebSocket for progress reporting, which fails.
- **Don't expose this to the internet without authentication.** `enforce_allowlist = false` during the smoke test means anyone who learns your pubkey + a valid client keypair can hit your Jellyfin. Tighten the allowlist (Step 6 above) before leaving the daemon running.
- **Large posters / library listings.** A full library dump can exceed the default 16 MiB body cap. This example bumps `max_body_bytes` to 32 MiB; raise it further if your library is huge.
- **API key is visible to the daemon.** The daemon forwards your `X-Emby-Token` unchanged to Jellyfin. The daemon is on the same machine as Jellyfin in this setup, so the trust boundary is unchanged from a local `curl`.
