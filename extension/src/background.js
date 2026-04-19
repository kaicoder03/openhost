// openhost extension service worker.
//
// This file is a placeholder shipped with PR #28 (scaffold only).
// It exists so the MV3 manifest has a valid `background.service_worker`
// target and so Chrome will load the unpacked extension without error.
//
// PR #28.4 will replace this stub with the `oh://` URL handler: a
// declarativeNetRequest rule that rewrites `oh://<pubkey>/<path>` to
// an internal HTTP endpoint backed by an `OpenhostSession` dial to
// `<pubkey>`. PR #28.3 will import the WASM-compiled Dialer here.
//
// Until then, loading the extension just prints this line to the
// service-worker devtools console:

console.log(
  "openhost extension: scaffolding only; see extension/README.md for the roadmap"
);
