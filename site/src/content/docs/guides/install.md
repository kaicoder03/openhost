---
title: Install openhost
description: Build the daemon and client binaries from source; distributable packages are on the roadmap.
sidebar:
  order: 1
---

openhost is pre-release software and does not yet ship distributable binaries. For `v0.1.0` you build from source; the Rust toolchain handles the rest.

## Prerequisites

- **Rust 1.90** (stable). The repository pins this version via `rust-toolchain.toml`, so `rustup` fetches it automatically the first time you build.
- **pnpm** (only if you also want to work on this documentation site).
- **macOS, Linux, or Windows**. The daemon has been exercised on all three during v0.1 development; binary-release artifacts for each land in a future release.

Install `rustup` from [rustup.rs](https://rustup.rs/) if you don't have it; no other Rust setup is required.

## Clone and build

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

## Verify

```bash
openhostd --version
openhost-dial --version
openhost-resolve --version
```

All three should print `0.1.0`.

## Platform notes

- **macOS.** The build uses a forked [`webrtc`](https://github.com/kaicoder03/webrtc) crate pinned via the workspace's `[patch.crates-io]`. Apple's toolchain occasionally lags on `rustls`/`ring` ABI compatibility; if a build fails, a `rustup toolchain update stable` is usually enough.
- **Linux.** No distro-specific packages required beyond a working C toolchain for `ring`'s assembly fast paths (`build-essential` on Debian/Ubuntu, `base-devel` on Arch).
- **Windows.** Build works under both MSVC and GNU toolchains; MSVC gets better download sizes. The pair-DB file watcher uses ReadDirectoryChangesW under the hood; no extra configuration needed.

## Coming later

Distributable binaries, a Homebrew tap, a systemd unit, and a launchd plist are tracked in [`ROADMAP.md`](https://github.com/kaicoder03/openhost/blob/main/ROADMAP.md) under Phase 3+. Until those land, "install from source" is the supported path.

With the binaries in place, head to [Quickstart](/openhost/guides/quickstart/) to bring up a reachable service.
