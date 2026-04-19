// openhost extension service worker (MV3).
//
// PR #28.3 Phase 6 wires up the URL handler: the service worker
// listens for navigations to `oh://<pk>/...`, cancels them, and opens
// the extension-served viewer tab which then runs the dial.
//
// The resolver probe from PR #28.2 is kept; to exercise it directly
// (without going through a tab) uncomment the block at the bottom.

import { installOhNavigationHandler } from "./url_handler/oh_navigator.js";

console.log(
  "openhost extension: service worker booted; arming oh:// handler",
);

installOhNavigationHandler();

// ---------------------------------------------------------------------------
// PR #28.2 resolver probe — dev-only, stays opt-in.
//
// To exercise the four WASM decode exports without the full dial:
//
//   1. Build the WASM pkg:  `./extension/scripts/build-wasm.sh`
//   2. Uncomment the lines below; replace <pubkey> with a 52-char
//      zbase32 pubkey of a running openhost daemon.
//   3. Reload the unpacked extension in chrome://extensions.
//
// import { runResolverProbe } from "./dev/resolver-probe.js";
// runResolverProbe("<pubkey-zbase32>");
