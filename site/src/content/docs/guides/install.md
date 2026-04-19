---
title: Install openhost
description: Download pre-built binaries or build from source.
sidebar:
  order: 1
---

As of `v0.3.0+` (once the first release fires the binary workflow) you have two options: grab a pre-built archive from GitHub Releases, or build from source. Pre-built is the fast path.

## Pre-built binaries

Download the archive for your platform from the [GitHub Releases page](https://github.com/kaicoder03/openhost/releases/latest):

| Platform | Archive |
|---|---|
| Linux x86_64 | `openhost-linux-x86_64.tar.gz` |
| macOS Apple Silicon (M-series) | `openhost-macos-aarch64.tar.gz` |
| macOS Intel | `openhost-macos-x86_64.tar.gz` |
| Windows x86_64 | `openhost-windows-x86_64.zip` |

Each archive carries three binaries (`openhostd`, `openhost-dial`, `openhost-resolve`), the `CHANGELOG.md`, both `LICENSE-*` files, and the `distribution/` tree (systemd unit + launchd plist + install notes).

```bash
# Linux / macOS
curl -sSL https://github.com/kaicoder03/openhost/releases/latest/download/openhost-linux-x86_64.tar.gz \
  | tar xz
install -m 0755 openhost-linux-x86_64/openhost* ~/.local/bin/

# Windows PowerShell
Invoke-WebRequest -Uri https://github.com/kaicoder03/openhost/releases/latest/download/openhost-windows-x86_64.zip -OutFile openhost.zip
Expand-Archive openhost.zip -DestinationPath .
```

Verify:

```bash
openhostd --version
openhost-dial --version
openhost-resolve --version
```

All three should print the same version, matching the release tag.

### Running as a service

- **Linux (systemd):** copy `distribution/systemd/openhostd.service` into `/etc/systemd/system/` and follow the [distribution README](https://github.com/kaicoder03/openhost/blob/main/distribution/README.md).
- **macOS (launchd):** copy `distribution/launchd/com.openhost.openhostd.plist` to `~/Library/LaunchAgents/`.
- **Windows:** run `openhostd run` from a terminal for now; a Windows Service wrapper is tracked as a future ROADMAP item.

### Homebrew

macOS (Apple Silicon + Intel) and Linux x86_64 can install via Homebrew once the tap repo is live:

```bash
brew tap kaicoder03/openhost
brew install openhost
```

The formula ships the three binaries (`openhostd`, `openhost-dial`, `openhost-resolve`) only; follow [Running as a service](#running-as-a-service) above for `launchd` / `systemd` setup.

The tap repo at `kaicoder03/homebrew-openhost` is a companion to the main repo; it's created + populated by a maintainer on the first v0.3.0+ release. If the `brew tap` above fails with a 404, the tap is not yet live — install directly from the formula in the main repo instead:

```bash
brew install --HEAD https://raw.githubusercontent.com/kaicoder03/openhost/main/distribution/homebrew/openhost.rb
```

See [`distribution/homebrew/README.md`](https://github.com/kaicoder03/openhost/blob/main/distribution/homebrew/README.md) for the formula source, the pre-tap testing procedure, and the maintainer's tap-setup checklist.

## Build from source

Fallback when pre-built isn't an option: a supported platform that isn't on the pre-built list, or a build-from-HEAD for pre-release work.

### Prerequisites

- **Rust 1.90** (stable). The repository pins this version via `rust-toolchain.toml`, so `rustup` fetches it automatically the first time you build.
- **pnpm** (only if you also want to work on this documentation site).
- **macOS, Linux, or Windows**. The daemon has been exercised on all three.

Install `rustup` from [rustup.rs](https://rustup.rs/) if you don't have it; no other Rust setup is required.

### Clone and build

```bash
git clone https://github.com/kaicoder03/openhost.git
cd openhost

# Daemon + (optional) debug CLI that reads pkarr records.
cargo build --release -p openhost-daemon

# Client crate, including the openhost-dial + openhost-resolve binaries
# that sit behind the `cli` feature.
cargo build --release --features cli -p openhost-client
```

The first build fetches the pinned toolchain and every dependency, and will take 3–8 minutes on a warm machine. Subsequent builds are incremental.

### Where the binaries land

```
target/release/openhostd        # host daemon
target/release/openhost-dial    # client CLI — dial a host, get an HTTP response
target/release/openhost-resolve # debug CLI — inspect a host's published pkarr record
```

Copy them into a directory on your `PATH`; `~/.local/bin` or `/usr/local/bin` are common choices.

```bash
install -m 0755 target/release/openhostd        ~/.local/bin/
install -m 0755 target/release/openhost-dial    ~/.local/bin/
install -m 0755 target/release/openhost-resolve ~/.local/bin/
```

### Platform notes

- **macOS.** The build uses a forked [`webrtc`](https://github.com/kaicoder03/webrtc) crate pinned via the workspace's `[patch.crates-io]`. Apple's toolchain occasionally lags on `rustls`/`ring` ABI compatibility; if a build fails, a `rustup toolchain update stable` is usually enough.
- **Linux.** No distro-specific packages required beyond a working C toolchain for `ring`'s assembly fast paths (`build-essential` on Debian/Ubuntu, `base-devel` on Arch).
- **Windows.** Build works under both MSVC and GNU toolchains; MSVC gets better download sizes. The pair-DB file watcher uses ReadDirectoryChangesW under the hood; no extra configuration needed.

## What's next

Homebrew tap, Windows Service wrapper, and musl / Alpine Linux builds are tracked in [`ROADMAP.md`](https://github.com/kaicoder03/openhost/blob/main/ROADMAP.md). Binary releases for Linux x86_64, macOS (aarch64 + x86_64), and Windows x86_64 fire automatically on every `v*` tag via `.github/workflows/release.yml`.

With the binaries in place, head to [Quickstart](/openhost/guides/quickstart/) to bring up a reachable service.
