# oh-send

Developer-first ad-hoc file transfer built on openhost. Ships as a web app (WASM client) and a CLI; both reuse the `openhost-client` crate so every bytes-on-the-wire guarantee of the core protocol applies unchanged.

## Why this lives inside the openhost monorepo

oh-send is the first commercial surface on top of the openhost protocol. During Y1 the product and the core protocol will iterate together — wire-format changes, streaming transfer, TURN fallback — and one repo means one CI, one release cadence, and no version-skew debugging. At M9, once the protocol surface stabilizes for external consumers, oh-send can be extracted to its own repo; the crate boundaries are already clean.

The openhost workspace stays the **core**: protocol, daemon, client, spec. Nothing under `products/` is a dependency of anything under `crates/`. `products/` depends on `crates/`, never the reverse.

## Relationship to existing repo layout

```
openhost/
├── crates/               # core protocol — do not depend on products/
│   ├── openhost-core
│   ├── openhost-pkarr
│   ├── openhost-pkarr-wasm
│   ├── openhost-daemon
│   ├── openhost-client
│   └── openhost-ffi
├── spec/                 # wire format, security model — source of truth
├── site/                 # project docs (docs.openhost.dev)
├── extension/            # browser extension (Phase 3 roadmap)
├── apple/                # iOS/macOS native shells (Phase 3+ roadmap)
└── products/
    └── oh-send/          # THIS DIRECTORY
        ├── LANDING.md    # marketing copy for oh-send.dev
        ├── TICKETS.md    # 90-day execution plan
        ├── web/          # WASM + TS web client (added in T-03)
        └── cli/          # thin wrapper over openhost-client (added in T-02)
```

## Product surface

Two entry points, same protocol:

1. **Web** (`oh-send.dev`) — drag-and-drop in the browser, consumes `openhost-pkarr-wasm` + a WASM build of `openhost-client`. No install. This is the acquisition surface.
2. **CLI** (`oh-send`) — Homebrew + scoop + curl installer. Re-exports `openhost-dial` with a transfer-shaped UX (`oh-send ./file.mp4` prints a shareable URL). This is the power-user surface.

Both produce the same `oh://<pubkey>/<token>` URL. A recipient opens it in either surface; the bytes flow peer-to-peer through whichever path NAT allows.

## Explicit non-goals (Y1)

- No cloud storage, no account system, no sync, no team workspaces (Teams tier is added on top in `products/oh-business/` in Y2).
- No mobile app — that's `products/oh-drop/`, launched M18.
- No paid features that break P2P purity — any Pro feature must be implementable without a server-side copy of the file.

## Current status

Scaffolding only. See `TICKETS.md` for the 90-day sequence; `LANDING.md` for the copy the web client will render.
