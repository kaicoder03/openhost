# Distribution artifacts

Service-manager files and other artifacts that help operators run the daemon in production. Each subdirectory is self-contained — install or skip per your environment.

## What's here

| Path | Purpose |
|---|---|
| [`systemd/openhostd.service`](systemd/openhostd.service) | Linux systemd unit with resource limits and basic sandboxing. |
| [`launchd/com.openhost.openhostd.plist`](launchd/com.openhost.openhostd.plist) | macOS launchd property list (user or system agent). |

A Homebrew tap (`kaicoder03/homebrew-openhost`) is planned once at least one tagged release has produced binary artifacts via `.github/workflows/release.yml`. That workflow landed in PR #23; the first release it runs against will be the trigger for the tap.

## Linux: systemd

1. Install the binaries under `/usr/local/bin/` (see [install guide](https://kaicoder03.github.io/openhost/guides/install/)).
2. Create the system user the unit runs as:

   ```bash
   sudo useradd --system --home-dir /var/lib/openhost --create-home --shell /usr/sbin/nologin openhost
   sudo install -d -m 0700 -o openhost -g openhost /var/lib/openhost /etc/openhost
   ```

3. Install the unit:

   ```bash
   sudo install -m 0644 distribution/systemd/openhostd.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now openhostd.service
   ```

4. Inspect:

   ```bash
   systemctl status openhostd
   journalctl -u openhostd -f
   ```

The unit points `$HOME` at `/var/lib/openhost` and expects the daemon config at `/etc/openhost/daemon.toml`. Adjust the unit's `Environment=OPENHOST_CONFIG=…` line if you keep config elsewhere.

Uninstall:

```bash
sudo systemctl disable --now openhostd.service
sudo rm /etc/systemd/system/openhostd.service
sudo systemctl daemon-reload
```

## macOS: launchd

The plist can run as a **user agent** (per-account, loaded at login) or a **system daemon** (machine-wide, loaded at boot). User-agent is the right choice for a personal home server; system-daemon is for shared-user setups.

### User agent (recommended)

```bash
install -d -m 0700 ~/Library/LaunchAgents ~/Library/Logs/openhost
install -m 0644 distribution/launchd/com.openhost.openhostd.plist \
  ~/Library/LaunchAgents/com.openhost.openhostd.plist

# Edit the plist to point `WorkingDirectory` and `StandardOutPath` at
# paths inside your home directory if the defaults don't suit. Then:
launchctl load ~/Library/LaunchAgents/com.openhost.openhostd.plist
```

Inspect:

```bash
launchctl list | grep openhost
tail -f ~/Library/Logs/openhost/openhostd.log
```

Uninstall:

```bash
launchctl unload ~/Library/LaunchAgents/com.openhost.openhostd.plist
rm ~/Library/LaunchAgents/com.openhost.openhostd.plist
```

### System daemon

Same file, but install to `/Library/LaunchDaemons/` with owner `root:wheel` and load with `sudo launchctl load`. Edit the plist's `UserName` key first.

## Security note

Both unit files run the daemon as an **unprivileged** user by default. The daemon does not need root — it binds no privileged port, writes no files outside its state directory, and talks to upstream services over loopback. If you find yourself editing the unit file to grant more permissions, double-check first; the defaults are deliberate.
