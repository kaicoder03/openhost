# openhost browser extension

**Status:** scaffold only. No protocol code yet. See the
[Implementation plan](#implementation-plan-future-prs) below for the PR
sequence that fills this directory in.

## Overview

The openhost browser extension lets a Chrome (and eventually Firefox) user
navigate to `oh://<zbase32-pubkey>/path` and see the page hosted by that
public key, with no account, no tunnel service, and no intermediary that
can read the traffic. It is the browser equivalent of the `openhost-dial`
CLI in [`crates/openhost-client/`](../crates/openhost-client/): it
resolves the Pkarr record for `<pubkey>`, seals a WebRTC offer, waits for
a per-client answer fragment, completes the DTLS handshake with a pinned
certificate fingerprint, runs the §7.6 channel-binding HMAC, and then
speaks HTTP over the resulting end-to-end encrypted data channel. When
that all succeeds the browser renders the response like any other HTTP
response.

The same invariants from [`spec/04-security.md`](../spec/04-security.md)
§1 apply to the extension:

1. The host's Ed25519 private key never reaches the extension.
2. The data channel is end-to-end DTLS-encrypted from the browser socket
   to the daemon process.
3. Each extension install has its own Ed25519 client keypair; the host's
   `_allow` record gates access.
4. DTLS fingerprints are pinned to the host pubkey via the signed Pkarr
   record.
5. Channel binding defeats RFC 8844 unknown-key-share attacks.

Today this directory is a scaffold: the manifest, a placeholder service
worker, a README (this file), and a Node `package.json` with
placeholder lint/build scripts. No Pkarr resolver, no WebRTC signalling,
no WASM yet.

## Architecture (planned)

```
                       ┌────────────────────────────────────┐
                       │              browser               │
                       │                                    │
┌──────────────┐       │   ┌───────────────────────────┐    │
│  oh://<pk>/  │──────▶│   │  extension service worker │    │
│   URL bar    │       │   │  (PR #28.4 URL handler)   │    │
└──────────────┘       │   └────────────┬──────────────┘    │
                       │                │                   │
                       │                ▼                   │
                       │   ┌───────────────────────────┐    │
                       │   │  WASM core (PR #28.2-3)   │    │
                       │   │   ├─ openhost-pkarr       │    │
                       │   │   │   (resolve record)    │    │
                       │   │   └─ openhost-client      │    │
                       │   │       (Dialer + Session)  │    │
                       │   └────────────┬──────────────┘    │
                       │                │                   │
                       │                ▼                   │
                       │   ┌───────────────────────────┐    │
                       │   │  browser RTCPeerConnection│    │
                       │   │   (DTLS 1.3 data channel) │    │
                       │   └────────────┬──────────────┘    │
                       └────────────────┼───────────────────┘
                                        │
                      Mainline DHT +    │   direct WebRTC
                      public Pkarr      │   (hole-punched
                      relays (resolve)  │    via STUN)
                                        │
                       ┌────────────────▼───────────────────┐
                       │         openhost-daemon            │
                       │   (same code that powers CLI host) │
                       │                                    │
                       │   - serves Pkarr record            │
                       │   - negotiates sealed offer/answer │
                       │   - terminates DTLS                │
                       │   - forwards HTTP to localhost:N   │
                       └────────────────────────────────────┘
```

The key design point: the extension is **openhost-client running in a
browser**. Everything the native CLI dialer does — Pkarr resolve,
sealed-box offer, answer-fragment polling, channel-binding HMAC, HTTP
framing on the data channel — happens inside the extension process,
compiled to WebAssembly. The browser's native `RTCPeerConnection` is
the only piece that the WASM doesn't own.

## Implementation plan (future PRs)

- **PR #28 (this one).** Scaffold. Directory layout (`src/`, `wasm/`,
  `public/`, `scripts/`), a stub MV3 `manifest.json`, a placeholder
  `src/background.js` that logs a roadmap pointer, a Node `package.json`
  with echo-only `lint` / `build` scripts, and this README. No protocol
  logic. Loadable as an unpacked extension (Chrome will accept it as a
  valid MV3 manifest) but does nothing.

- **PR #28.2.** WASM build of
  [`openhost-pkarr`](../crates/openhost-pkarr/)'s resolver module.
  `scripts/build-wasm.sh` drives `wasm-pack` with a
  `browser`-targeted pkg. A standalone test harness (loaded from
  `src/dev/resolver-probe.js`, not shipped in the production bundle)
  resolves a known pubkey against 3 public Pkarr relays and prints
  the decoded record + ICE fragments. No service-worker integration
  yet; this PR only proves the resolver compiles, links, and returns
  a parsed record.

- **PR #28.3.** WASM build of `openhost-client`'s `Dialer` and
  `OpenhostSession`. Wires the WASM into a tiny dev page that opens a
  real `RTCPeerConnection` against a locally running `openhostd`.
  **Known unresolved problem:** browser WebRTC APIs do not currently
  expose an RFC 5705 DTLS exporter — `RTCPeerConnection` has no
  `export_keying_material`-equivalent in WebIDL, so the CLI dialer's
  §7.6 channel-binding HMAC has no direct counterpart in a stock
  browser. Candidate paths (all open, none committed): (a) a proposal
  to plumb the exporter through `RTCDtlsTransport`; (b) a WASM-internal
  DTLS stack that owns the handshake and thus the exporter, at the
  cost of the browser's NAT traversal; (c) an alternative binding
  construction (e.g. `tls-server-end-point`-style fingerprint binding)
  that doesn't require the exporter. Picking one — and potentially
  relaxing the spec requirement that browser clients speak the same
  channel-binding protocol as CLI clients, with a written trade-off —
  is part of this PR's scope. Success criterion: a browser-native
  end-to-end dial matching the in-process `OpenhostSession` test from
  PR #12, with an explicit decision on the channel-binding path.

- **PR #28.4.** Service-worker URL handler. Catches navigations to
  `oh://<pubkey>/...` and routes them to an internal HTTP endpoint
  backed by a dial to `<pubkey>`. **Mechanism TBD** — registering a
  custom protocol scheme in an MV3 extension is not a single solved
  API. Candidates: `chrome.declarativeNetRequest` URL rewrite (works
  for http(s) URLs but not arbitrary schemes), a `webNavigation`
  listener that hijacks navigations before they hit the net stack,
  `navigator.registerProtocolHandler` from a packaged page (limited to
  a small allowlist of schemes; `oh` is not on it), or a native
  messaging host that proxies the scheme. Firefox's equivalents differ
  again. This PR's first task is prototyping each path against Chrome
  stable + Firefox stable and picking the one with the narrowest
  permission footprint; the readme here will be updated with the
  decision. The service worker holds the long-lived `OpenhostSession`
  and tears it down on idle. First PR where typing `oh://...` in the
  address bar actually does something.

- **PR #28.5.** Popup UI — first-run identity generation
  (`crypto.subtle.generateKey` → sealed in IndexedDB), pairing flow
  (QR-code scan of the BIP39 SAS from §7.3), a device-management
  page that lists paired hosts and lets the user revoke a session
  token. Minimal React-free HTML + vanilla JS; no build tool.

- **PR #28.6+.** Firefox parity (the MV3 permission model is close
  but not identical — in particular, `declarativeNetRequest` support
  and the set of available `host_permissions` differ), localization
  strings, and submission to the Chrome Web Store and the Mozilla
  Add-ons store. Reproducible-build script (§7.4) gated on PR #28.6
  so the published artifact can be bit-reproduced from a tagged
  commit.

Each PR is independently shippable and loadable as an unpacked
extension; the `manifest.json` starts at minimum-permissions and
narrows scope only as each PR introduces features that require it.

## Why each piece lives where it lives

### `manifest.json`

MV3 (`manifest_version: 3`) because Chrome MV2 extensions stop
loading on the stable channel in 2024 and Firefox has shipped MV3
support since 109. MV3 also unlocks the permission posture we need:
`declarativeNetRequest` rules can be installed without the broad
`webRequest` permission, so we never need to read request bodies of
unrelated sites.

The scaffold ships with empty `permissions` and `host_permissions`
arrays. **Every future PR that adds a permission must justify it in
its PR description** — see §7.4 in the security spec. In particular,
the extension will never request:

- `tabs` — we don't need active-tab metadata.
- `cookies` — openhost is account-free; cookies for third-party
  sites are off-limits.
- `<all_urls>` or similar broad host patterns — we only dial
  `oh://` URLs, which the MV3 URL-protocol-handler API will let us
  claim without blanket host access.

### `src/`

All hand-written JS for the extension goes here:

- `background.js` — the MV3 service worker. Today it's a stub that
  logs a roadmap pointer. PR #28.4 turns it into the `oh://` URL
  handler; PR #28.5 adds the popup's backing message router.
- `dev/` (future) — dev-only probes (`resolver-probe.js` in PR #28.2,
  `dialer-probe.js` in PR #28.3) that are excluded from the packaged
  extension.
- WASM glue — the thin JS wrapper that `wasm-pack` emits next to each
  WASM module, imported by `background.js`.

### `wasm/`

Output directory for `wasm-pack` builds of `openhost-pkarr` and
`openhost-client`. Empty today; populated by
`scripts/build-wasm.sh` starting in PR #28.2. `wasm/pkg/` is
gitignored so that committed state stays source-only.

### `public/`

Static assets shipped with the extension: icons (PR #28.5 adds the
first real SVG / PNG set), the popup HTML, any localized string
tables. Empty today.

The scaffold `manifest.json` deliberately **does not declare an
`icons` block** — declaring paths to files that don't exist causes
Chrome to log a load warning and Firefox to refuse the extension
outright. PR #28.5 will add both the icon assets under
`public/icons/` and the matching `icons` block in the manifest in a
single change.

### `scripts/`

Dev-time scripts: the WASM builder (PR #28.2), a manifest linter that
validates the JSON against the Chrome MV3 schema (PR #28.4 when we
start gaining permissions and the linter becomes load-bearing), and a
packager that produces the `.zip` / `.crx` artifacts for store
submission (PR #28.6). No scripts ship yet.

## Security posture

This extension is subject to the requirements in
[`spec/04-security.md`](../spec/04-security.md) §7.4 ("Browser
extension as an attack surface"): minimum-permission manifest, no
broad origin access, reproducible builds, strict CSP, no remote code.
It inherits §7.12's hop-by-hop-header and `X-Forwarded-For` rules
from the shared `openhost-client` code once that ships as WASM in
PR #28.3 — the same sanitisation path the daemon runs in
`crates/openhost-daemon/src/forward.rs` is the path the WASM will
run in the browser.

Concretely, the extension **will not**:

- Read the content of arbitrary web pages. It has no content scripts
  and will never request `<all_urls>` or any broad host permission.
- Inject scripts into pages. MV3 + no content-script declaration
  makes this structurally impossible for the packaged artifact.
- Access browser cookies, history, bookmarks, or tab metadata.
  None of these permissions are in `manifest.json` today and none
  will ever be added.
- Load remote code. MV3 forbids `eval()` and remote script imports
  by default; we will ship a strict CSP
  (`script-src 'self'; object-src 'self'`) starting in PR #28.4 to
  make the prohibition explicit in the manifest rather than
  implicit in MV3's defaults.
- Contact third-party analytics, telemetry, or error-reporting
  services. The only network requests the extension makes are
  Pkarr relay queries (HTTP GET to public relays listed in the
  openhost spec), direct WebRTC peer connections, and STUN
  candidate gathering. All three are either end-to-end encrypted or
  limited to public-key discovery.

Every PR that touches `manifest.json` must update the
[Implementation plan](#implementation-plan-future-prs) and justify the
permission diff in the PR description.

## Local development

Not runnable yet — this PR ships directory structure and a placeholder
manifest only. Once PR #28.2 lands, the development flow will be:

```bash
cd extension

# install dev deps (none in PR #28; wasm-pack + Chrome MV3 linter land in 28.2)
npm install

# build the WASM modules and copy them into wasm/pkg/
npm run build

# lint the manifest + JS glue
npm run lint
```

To load the extension into Chrome today:

1. Open `chrome://extensions`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select this `extension/` directory.
4. Chrome will load the scaffold and log the roadmap pointer from
   `src/background.js` to the service-worker devtools console. That
   is the complete current feature set.

The scaffold does not render any UI, intercept any navigation, or
contact any network. Any apparent network activity from an installed
scaffold build is a bug and should be reported as a security issue per
[`SECURITY.md`](../SECURITY.md).
