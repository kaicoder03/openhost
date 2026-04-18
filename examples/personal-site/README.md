# Personal static site

Expose a static site (HTML, CSS, images) via openhost. No WebSockets, no streaming, no quirks — this is the cleanest case for the protocol today and the fastest way to verify your setup end-to-end.

## Prerequisites

- `openhostd`, `openhost-dial`, `openhost-resolve` on your `PATH` — see [site/install](https://kaicoder03.github.io/openhost/guides/install/).
- [Caddy](https://caddyserver.com/) installed (any web server works; Caddy is the simplest single-binary choice).

## 1. Serve your site locally

```bash
mkdir -p ~/sites && cd ~/sites
cat > index.html <<'HTML'
<!doctype html>
<html><body><h1>Hello from my home server</h1></body></html>
HTML
caddy file-server --root ~/sites --listen 127.0.0.1:8080 --browse
```

Verify locally:

```bash
curl http://127.0.0.1:8080/
```

## 2. Copy this example's config

```bash
install -d -m 0700 ~/.config/openhost
cp examples/personal-site/daemon.toml ~/.config/openhost/daemon.toml
```

## 3. Start the daemon

```bash
openhostd run
```

Watch for the readiness line:

```
INFO openhost_daemon::app: openhostd: up pubkey=<zbase32-pubkey> dtls_fp=AB:CD:…
```

Copy the `pubkey=…` value.

## 4. Dial from a second machine

```bash
openhost-dial oh://<zbase32-pubkey>/
```

Expected output — status + headers on stderr, HTML body on stdout:

```
HTTP/1.1 200 OK
Content-Type: text/html

<!doctype html>
<html><body><h1>Hello from my home server</h1></body></html>
```

Subresources work too:

```bash
openhost-dial oh://<zbase32-pubkey>/some/image.png > /tmp/fetched.png
```

## 5. Lock it down

Once you've confirmed dialing works, tighten the daemon:

1. Persist a client identity on the client machine and pair it per [the quickstart's Step 5](https://kaicoder03.github.io/openhost/guides/quickstart/#5-pair-the-client-switch-to-enforced-mode).
2. Flip `enforce_allowlist = false` → `true` in `daemon.toml`.
3. Populate `watched_clients = ["<client-pubkey-zbase32>"]`.
4. Restart the daemon.

## Gotchas

- **Range requests work.** Caddy honours `Range: bytes=…`, the openhost daemon forwards the header unchanged, the client sees a `206 Partial Content`. Large files stream in chunks without any special config.
- **CORS is your problem, not openhost's.** The daemon does not mangle `Access-Control-*` headers; if your site needs them, set them in Caddy.
- **`Host` is rewritten.** The daemon's forwarder pins `Host` to the configured target's authority (`127.0.0.1:8080`). If your site uses Host-based virtual hosting locally, move that logic upstream of this forward target.
