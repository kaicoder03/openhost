---
title: Quickstart
description: Bring up an openhost daemon and dial it from a second machine in under five minutes.
sidebar:
  order: 2
---

This walkthrough takes you from built binaries to a live end-to-end HTTP request over openhost. You'll need [two machines](#prerequisites) and about five minutes.

## Prerequisites

- The three binaries from [Install](/openhost/guides/install/) — `openhostd`, `openhost-dial`, `openhost-resolve` — on your `PATH`.
- A **host machine** (the computer that runs the service you want to reach) with an HTTP service listening on `127.0.0.1`. Any will do; for this walkthrough we'll use `python3 -m http.server 8000` in an empty directory.
- A **client machine** (a different computer, ideally on a different network) with at least `openhost-dial` installed.

Both machines need outbound internet; inbound port forwarding is **not** required.

## 1. Start an upstream service on the host

In one terminal on the host machine:

```bash
mkdir /tmp/openhost-demo && cd /tmp/openhost-demo
echo "hello from openhost" > index.html
python3 -m http.server 8000
```

This exposes a trivial HTTP service on `http://127.0.0.1:8000/`.

## 2. Configure the daemon

Create `~/.config/openhost/daemon.toml` on the host machine:

```toml
[identity]
store = { type = "fs", path = "~/.config/openhost/identity.key" }

[pkarr]
# Relays default to the bundled public list; leaving this empty uses them.
relays = []
republish_secs = 1800

[pkarr.offer_poll]
# Start permissive for the smoke test. Flip this to `true` after step 5
# and pair your client explicitly.
enforce_allowlist = false
# Poll known client zones once per second for offer records.
poll_secs = 1
# Add your client's pubkey here after step 3 so the daemon knows
# whose zone to watch. Until then the list is empty.
watched_clients = []

[dtls]
cert_path = "~/.config/openhost/dtls.pem"

[forward]
# Point this at the upstream service you started in step 1.
target = "http://127.0.0.1:8000"
```

The daemon expands `~` automatically; the parent directory is created on first run.

## 3. Launch the daemon

```bash
openhostd run
```

On first boot the daemon generates a fresh Ed25519 identity, a self-signed DTLS certificate, and publishes a signed record to the public Pkarr relays. Watch the log for:

```
INFO openhost_daemon::app: openhostd: DTLS certificate generated
INFO openhost_pkarr::publisher: openhost-pkarr: initial publish succeeded attempt=1
INFO openhost_daemon::app: openhostd: up pubkey=… dtls_fp=…
```

The `pubkey=…` value on the "up" line is what the client will dial. Copy it.

In a separate terminal on the host:

```bash
openhostd identity show
```

prints the same pubkey in a predictable location. Keep that terminal open; you'll need it.

## 4. Dial from the client

Switch to the client machine. In a terminal:

```bash
openhost-dial oh://<paste-pubkey-here>/
```

You should see the response on stderr (status line + headers) and the body on stdout:

```
openhost-dial: client_pk=<ephemeral-client-pk> dialing GET
HTTP/1.1 200 OK
Content-Type: text/html
Server: SimpleHTTP/0.6 Python/3.12.0

<!DOCTYPE html>
<html>...<li><a href="index.html">index.html</a></li>...
```

That's a real HTTP request, traversing the client's NAT, hole-punched through WebRTC, authenticated with channel binding, forwarded to the upstream service on `127.0.0.1:8000` by the daemon.

## 5. Pair the client (switch to enforced mode)

Ephemeral keys are fine for the smoke test; for actual use the daemon should only accept your client's identity. On the client:

```bash
# Persist the client's identity so future dials use the same pubkey.
dd if=/dev/urandom of=~/.config/openhost/client.key bs=32 count=1
chmod 0600 ~/.config/openhost/client.key

# Print the pubkey that matches that seed.
openhost-dial --help >/dev/null  # any command with --identity picks it up
```

There is no standalone keygen CLI in v0.1; the ephemeral-keypair path is usable today, and pairing against a persistent key will be simpler once the `openhost-keygen` helper lands (tracked in [`ROADMAP.md`](https://github.com/kaicoder03/openhost/blob/main/ROADMAP.md)). For now, using the `--identity` flag with a file you created with `dd` is the supported approach.

Grab the matching pubkey (a future tool will print it; until then, the easiest path is to pipe it through any client tool that logs `client_pk=`). Add it to the host:

```bash
openhostd pair add <client-pubkey-zbase32>
```

The CLI prints a one-line confirmation noting that the running daemon will pick this up automatically — the pair-DB file watcher reloads within ~250 ms without a SIGHUP.

Then tighten the daemon config:

```toml
[pkarr.offer_poll]
enforce_allowlist = true                  # was: false
watched_clients = ["<client-pubkey-zbase32>"]
```

Restart the daemon. Now only paired clients succeed.

## 6. Verify the record on its own

If a dial fails, run the debug resolver first:

```bash
openhost-resolve oh://<daemon-pubkey>/ --json
```

This fetches the host's signed pkarr record and prints the decoded contents. If this succeeds, discovery is working and the problem is downstream. See [Troubleshooting](/openhost/guides/troubleshoot/) for what to check next.

## One known caveat

At `v0.1.0` a full WebRTC answer SDP — after ICE trickles fully — can still exceed the BEP44 1000-byte packet budget on some configurations, even after PR #15's answer-record fragmentation. If `openhost-dial` reliably returns `PollAnswerTimeout` against a real-world daemon, that's the residual size gap; it is the next line item after Phase 2 on [`ROADMAP.md`](https://github.com/kaicoder03/openhost/blob/main/ROADMAP.md). For `v0.1.0` testing, the server-side flow is still fully exercised and the daemon's log will confirm the answer was queued.
