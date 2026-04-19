// openhost extension service worker (MV3).
//
// PR #28.2 ships the first real code alongside this stub: a WASM
// build of openhost-pkarr's resolver read path. The service worker
// stays passive by default so the installed extension does not make
// any network requests without an operator opt-in. Uncomment the
// probe wiring at the bottom of this file to exercise the four
// resolver exports.
//
// PR #28.3 will replace the probe-wiring scaffolding here with the
// WASM-compiled Dialer state machine. PR #28.4 will register the
// `oh://` URL handler. Until then, loading the extension just prints
// a single roadmap line to the service-worker devtools console.

console.log(
  "openhost extension: scaffolding only; see extension/README.md for the roadmap",
);

// ---------------------------------------------------------------------------
// PR #28.2 resolver probe — dev-only.
//
// To exercise the four wasm-bindgen exports (parse_host_record,
// decode_and_verify, decode_offer, decode_answer_fragments):
//
//   1. Build the WASM pkg:  `./extension/scripts/build-wasm.sh`
//   2. Uncomment the lines below; replace <pubkey> with a 52-char
//      zbase32 pubkey of a running openhost daemon. Your own daemon's
//      pubkey is the easiest — read it from openhostd's logs.
//   3. Reload the unpacked extension in chrome://extensions.
//   4. Inspect the service-worker devtools console; you should see
//      four `[probe] …` log lines.
//
// import { runResolverProbe } from "./dev/resolver-probe.js";
// runResolverProbe("<pubkey-zbase32>");
