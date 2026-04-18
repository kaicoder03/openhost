---
title: Troubleshooting
description: Common failure modes at v0.1.0 — what to check, in what order.
sidebar:
  order: 3
---

Order your debugging from the outside in: confirm the record is discoverable, then the answer returns, then the handshake completes, then the upstream responds. Most dial failures stop at one of the first two steps.

Before you start, re-run the daemon with verbose logs so the rest of these steps have context:

```bash
RUST_LOG=openhost_daemon=debug,openhost_pkarr=debug openhostd run
```

## "The DHT / relays can't find my record"

**Symptom:** `openhost-resolve oh://<pubkey>/` returns no record, or `openhost-dial` never moves past "dialing".

**Check:**

1. **Look for a successful initial publish** in the daemon log:

   ```
   INFO openhost-pkarr: initial publish succeeded attempt=1
   ```

   If you see `initial publish retries exhausted` instead, every configured relay is rejecting the record or unreachable. Check your outbound network.

2. **Confirm the public relays accept your pubkey.** The bundled defaults are `https://pkarr.pubky.app` and `https://relay.iroh.network`. Run the resolver with a single explicit relay to isolate:

   ```bash
   openhost-resolve oh://<pubkey>/ --relay https://pkarr.pubky.app --fast
   ```

   `--fast` skips the 1.5 s grace window so you get a clean success/failure.

3. **Verify clock skew.** The protocol enforces a ±2-hour freshness window on records (`spec/01-wire-format.md §3`). A machine with a badly-set clock will publish records the resolver immediately rejects. `timedatectl status` (Linux) or `sntp -sS pool.ntp.org` (macOS) both work.

## "A relay is returning 5xx"

**Symptom:** The publisher logs `warn!` lines with HTTP 500/502/503 from the relay host.

The bundled default relays are **shared public infrastructure**, rate-limited and occasionally unavailable. Override them in `~/.config/openhost/daemon.toml`:

```toml
[pkarr]
relays = [
  "https://your-own-relay.example.com",
]
```

Mainline DHT publishing still happens regardless of the relay list; relays are a convenience for faster lookup. A daemon with `relays = []` publishes only to the DHT and is still discoverable — just slower.

## "The client times out with `PollAnswerTimeout`"

**Symptom:** `openhost-dial` errors with `openhost-dial: failed to round-trip request: PollAnswerTimeout(30)` (or whatever `--timeout` you passed).

Three common causes, in order of likelihood:

1. **The client's pubkey isn't in the daemon's watched list.** The daemon only polls offer records under pubkeys listed in `pkarr.offer_poll.watched_clients`. If you're using the ephemeral keypair `openhost-dial` generates, that pubkey changes every invocation — add it explicitly or switch to a persisted identity via `--identity <path>`.

2. **Allowlist enforcement is on and the client isn't paired.** Check `openhostd pair list`; the client pubkey must appear. With `enforce_allowlist = true` (the default as of `v0.1.0`), an unpaired offer is silently dropped after unseal, and no answer is ever produced.

3. **The residual answer-size gap.** Real WebRTC answer SDPs — after full ICE trickle — still exceed the BEP44 1000-byte packet budget on some configurations, even with PR #15's fragmentation. The daemon produces the answer and queues it, but the publisher evicts it. You can confirm by checking the daemon log for:

   ```
   WARN openhost-pkarr: answer entry evicted — packet would exceed BEP44 1000-byte limit
   ```

   This is tracked as the next line item after Phase 2 in [`ROADMAP.md`](https://github.com/kaicoder03/openhost/blob/main/ROADMAP.md); there is no clean workaround at `v0.1.0`.

## "The DTLS handshake fails"

**Symptom:** Daemon log shows `webrtc error: handshake failed`, or the client gets an `openhost-dial: WebRtcSetup` error after a successful poll.

**Check:**

1. **Fingerprint pin agrees on both sides.** The resolved record's `dtls_fp` **must** equal the daemon's own "up" line:

   ```bash
   openhost-resolve oh://<pubkey>/ | grep dtls_fp
   ```

   Compared with the daemon's:

   ```
   INFO openhost_daemon::app: openhostd: up … dtls_fp=AB:CD:…
   ```

   A mismatch usually means the client resolved a cached or stale record — retry with `--fast` to skip the grace window and pick up the freshest.

2. **Cert rotation crossed mid-dial.** `dtls.rotate_secs` defaults to 86400 (24 h). If your daemon rotated between the resolver fetching the record and the handshake starting, the fingerprint won't match. Retry.

3. **UDP traffic is blocked.** WebRTC needs outbound UDP to the STUN servers and to the eventual peer. Corporate / hotel networks sometimes drop it. A quick test: `nc -u -v stun.l.google.com 19302` from both sides.

## "`openhostd pair add` doesn't seem to take effect"

**Symptom:** Paired a client, but the daemon still rejects their offers.

The pair-DB file watcher reloads the allow list within ~250 ms; look for this on the daemon side:

```
INFO openhost_daemon::pair_watcher: openhostd: pair-DB file watcher armed
INFO openhost_daemon::app: openhostd: pairing DB reloaded; republishing source=file-watcher
```

If you see the "armed" line but never the "reloaded" line, the watcher is running but not seeing file events. Two common reasons:

- **Network filesystem.** inotify (Linux) and FSEvents (macOS) do not fire reliably on NFS, SMB, or FUSE mounts. If `~/.config/openhost/allow.toml` is on a remote filesystem, move the pair DB to a local path via `pairing.db_path` in your config, or fall back to SIGHUP on Unix (`kill -HUP $(pgrep openhostd)`) / a restart on Windows.
- **Spawn failure.** If the watcher never armed, you'll see a `warn!` at daemon startup: `pair-DB file watcher could not be started`. Check the path exists and the parent directory is writable.

## Still stuck

Capture the `RUST_LOG=openhost_daemon=debug,openhost_pkarr=debug` output from the daemon plus the exact `openhost-dial` invocation and open an issue on [GitHub](https://github.com/kaicoder03/openhost/issues). Bug reports that include the `openhost-resolve --json` output for your host are dramatically easier to act on.
