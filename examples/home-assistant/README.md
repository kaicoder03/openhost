# Home Assistant (REST-only)

Expose a [Home Assistant](https://www.home-assistant.io/) instance's REST API over openhost. State reads, service calls, history queries, and any integration that talks `/api/` work. **The Lovelace web UI does not work** at `v0.1.0` because the browser ships a WebSocket connection on page load and that is globally rejected — see [Gotchas](#gotchas).

## Prerequisites

- Home Assistant Core / Container / Supervised running on `http://127.0.0.1:8123`.
- A long-lived access token from HASS *Profile → Long-Lived Access Tokens*.
- `openhostd`, `openhost-dial`, `openhost-resolve` on your `PATH`.

## 1. Confirm HASS is up locally

```bash
curl -sH "Authorization: Bearer <your-long-lived-token>" \
     http://127.0.0.1:8123/api/ | jq .
```

Expected:

```json
{ "message": "API running." }
```

## 2. Copy this example's config

```bash
install -d -m 0700 ~/.config/openhost
cp examples/home-assistant/daemon.toml ~/.config/openhost/daemon.toml
```

The `host_override = "127.0.0.1:8123"` line in this `daemon.toml` is important for HASS — see [Gotchas](#gotchas).

## 3. Start the daemon

```bash
openhostd run
```

Copy the `pubkey=…` value from the "openhostd: up" log line.

## 4. Hit the HASS API from a second machine

```bash
# State of a specific entity.
openhost-dial oh://<zbase32-pubkey>/api/states/sun.sun \
  -H "Authorization: Bearer <your-long-lived-token>" \
  --json | jq '.body_utf8 | fromjson | {state, attributes: .attributes | {next_rising, next_setting}}'
```

Expected:

```json
{
  "state": "above_horizon",
  "attributes": {
    "next_rising": "2026-04-19T06:23:14+00:00",
    "next_setting": "2026-04-19T20:41:07+00:00"
  }
}
```

Service calls also work — flipping a light from the second machine:

```bash
openhost-dial oh://<zbase32-pubkey>/api/services/light/turn_on \
  -X POST \
  -H "Authorization: Bearer <your-long-lived-token>" \
  -H "Content-Type: application/json" \
  -d '{"entity_id":"light.living_room"}'
```

## 5. Lock it down

Pair your client per [Step 5 of the quickstart](https://kaicoder03.github.io/openhost/guides/quickstart/#5-pair-the-client-switch-to-enforced-mode) and flip the daemon into `enforce_allowlist = true` mode. The long-lived token is now the second line of defence behind the openhost allowlist.

## Gotchas

- **Lovelace UI does not work.** The HASS frontend opens `wss://<host>/api/websocket` on page load; openhost v0.1.0 rejects every `Upgrade: websocket` handshake (`spec/01-wire-format.md §4`, `ForwardError::WebSocketUnsupported`). You'll see the HASS loading spinner, nothing else. Per-path WebSocket gating is tracked in [`ROADMAP.md`](../../ROADMAP.md); until it ships, Home Assistant is a REST-API-only integration.
- **Companion apps do not work for the same reason.** The iOS / Android HASS Companion apps subscribe via WebSocket. REST-only works; real-time push doesn't.
- **`Host` is pinned defensively.** HASS core doesn't reject on Host mismatch, but some reverse-proxy integrations and custom components do compare the incoming `Host` header against configured values. This example sets `host_override = "127.0.0.1:8123"` so the forwarded request looks indistinguishable from a direct `curl` against localhost. Drop that line if you have reason to preserve the client's originating Host.
- **Long-lived tokens are bearer secrets.** The daemon forwards `Authorization` unchanged. The daemon and HASS run on the same machine here, so the trust boundary is unchanged from local curl; it's worth saying out loud anyway.
- **Don't expose without pairing.** With `enforce_allowlist = false`, anyone who learns your pubkey + generates an Ed25519 keypair can reach HASS's `/api/`. Pair and tighten before leaving the daemon up for more than a smoke test.
