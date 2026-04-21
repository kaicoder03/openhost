// openhost extension service worker (MV3).
//
// Architecture (post-PR-#41):
//
//   ┌────────────────────────────────────────────────┐
//   │ Chrome tab                                     │
//   │   URL: chrome-extension://<ext>/oh/<pk>/...    │
//   │   Every fetch hits the SW.                     │
//   └──────────────────┬─────────────────────────────┘
//                      │ fetch event
//                      ▼
//   ┌────────────────────────────────────────────────┐
//   │ Service Worker (this file)                     │
//   │  - claims fetches under /oh/<pk>/*             │
//   │  - forwards them to the offscreen doc via      │
//   │    chrome.runtime.sendMessage                  │
//   │  - wraps the offscreen reply in a Response     │
//   └──────────────────┬─────────────────────────────┘
//                      │ runtime message
//                      ▼
//   ┌────────────────────────────────────────────────┐
//   │ Offscreen document (offscreen.html + .js)      │
//   │  - holds the OpenhostSession (RTCPeerConnection│
//   │    is only available in a document context,    │
//   │    not in MV3 SWs)                             │
//   │  - session cache per daemon-pk                 │
//   │  - performs the dial + session.request call    │
//   │  - returns {head, bodyBuf, status} over the    │
//   │    runtime channel                             │
//   └────────────────────────────────────────────────┘
//
// Why offscreen: MV3 service workers do not expose WebRTC APIs. The
// `chrome.offscreen` API (Chrome 109+) lets an extension open a hidden
// document whose context supports every web API. The SW spins up the
// offscreen page on first `oh://` fetch and keeps it alive by setting
// `reasons = ["USER_MEDIA"]` which the API explicitly permits for
// long-lived WebRTC-holding documents.

import { installOhNavigationHandler } from "./url_handler/oh_navigator.js";
import { loadOrCreateClientSeed } from "./dialer/openhost_session.js";
import initWasm, {
  client_pubkey_from_seed,
} from "../wasm/pkg/openhost_pkarr.js";

console.log(
  "openhost extension: service worker booted; arming oh:// handler",
);

installOhNavigationHandler();

// Surface the per-install client pubkey on every SW boot.
(async () => {
  try {
    await initWasm();
    const seed = await loadOrCreateClientSeed();
    console.log(
      "openhost dialer: client_pubkey_zbase32 =",
      client_pubkey_from_seed(seed),
    );
  } catch (err) {
    console.warn("openhost: could not derive client pubkey at boot:", err);
  }
})();

// ---------------------------------------------------------------------------
// SW fetch proxy — forwards to offscreen doc (PR #41)
// ---------------------------------------------------------------------------

const OFFSCREEN_URL = "offscreen.html";
let offscreenReady = null;

/**
 * Ensure the offscreen document exists. Chrome allows at most one
 * offscreen doc per extension. We return a memoised promise so
 * concurrent first-fetches don't race `createDocument`.
 */
function ensureOffscreen() {
  if (offscreenReady) return offscreenReady;
  offscreenReady = (async () => {
    try {
      const exists = await chrome.offscreen.hasDocument();
      if (exists) return;
    } catch (_) {
      // `hasDocument` is Chrome 116+; on older versions fall through
      // to createDocument and let it fail with "already exists" which
      // we swallow.
    }
    try {
      await chrome.offscreen.createDocument({
        url: OFFSCREEN_URL,
        reasons: ["USER_MEDIA"],
        justification:
          "openhost holds a long-lived WebRTC session to the home daemon",
      });
    } catch (err) {
      if (!/already exists/i.test(String(err && err.message))) throw err;
    }
  })();
  // Reset the memoised promise if creation fails so the next fetch
  // retries rather than inheriting a permanently-failed state.
  offscreenReady.catch(() => {
    offscreenReady = null;
  });
  return offscreenReady;
}

const OH_PATH_RE = /^\/oh\/([a-z0-9]{52})(\/.*)?$/i;

// Resolve the openhost scope a given fetch should be served against.
// A page at `chrome-extension://<ext>/oh/<pk>/index.html` can make a
// fetch to an absolute path like `/api/videos`, which the browser
// resolves against the extension ORIGIN, not the page's directory —
// so the resulting URL pops out of the `/oh/<pk>/` scope and 404s.
// We fix that by inspecting the referrer: if the requesting page is
// under `/oh/<pk>/`, we rewrite the fetch to be under the same pk's
// scope too. This makes relative and absolute URLs both "just work"
// the way a regular website would.
function resolveOhScope(event) {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return null;

  const direct = OH_PATH_RE.exec(url.pathname);
  if (direct) {
    return {
      daemonPkZ: direct[1].toLowerCase(),
      path: (direct[2] || "/") + (url.search || ""),
    };
  }

  // Referer-based rewrite for same-origin absolute paths.
  const referrer = event.request.referrer;
  if (!referrer) return null;
  let refUrl;
  try {
    refUrl = new URL(referrer);
  } catch {
    return null;
  }
  if (refUrl.origin !== self.location.origin) return null;
  const ref = OH_PATH_RE.exec(refUrl.pathname);
  if (!ref) return null;
  return {
    daemonPkZ: ref[1].toLowerCase(),
    path: url.pathname + (url.search || ""),
  };
}

self.addEventListener("fetch", (event) => {
  // Diagnostic: log every fetch the SW sees so we can tell whether
  // Chrome is routing subresource / API fetches through us at all.
  console.log(
    "[sw-fetch]",
    event.request.method,
    event.request.url,
    "referrer:",
    event.request.referrer || "(none)",
  );
  const scope = resolveOhScope(event);
  if (!scope) return;
  event.respondWith(handleOhFetch(scope.daemonPkZ, scope.path, event.request));
});

// Take control of any already-open pages on install + activate so
// subresource fetches from previously-loaded documents route through
// this worker rather than going direct to Chrome's file handler.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) =>
  event.waitUntil(self.clients.claim()),
);

// Uint8Array ↔ base64 helpers mirror the offscreen side. See
// offscreen.js for why we don't just pass ArrayBuffers through
// chrome.runtime.sendMessage (JSON-serialisation eats them).
function bytesToBase64(u8) {
  let bin = "";
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
  }
  return btoa(bin);
}
function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function handleOhFetch(daemonPkZ, path, request) {
  try {
    await ensureOffscreen();

    const headers = {};
    for (const [k, v] of request.headers.entries()) {
      if (k.toLowerCase() === "host") continue;
      headers[k] = v;
    }
    const bodyB64 =
      request.method === "GET" || request.method === "HEAD"
        ? null
        : bytesToBase64(new Uint8Array(await request.arrayBuffer()));

    const reply = await chrome.runtime.sendMessage({
      kind: "openhost-request",
      daemonPkZ,
      method: request.method,
      path,
      headers,
      bodyB64,
    });
    if (!reply || reply.error) {
      throw new Error(reply ? reply.error : "offscreen: no reply");
    }
    return buildResponseFromOpenhost(reply);
  } catch (err) {
    console.error("openhost SW: fetch failed", err, { daemonPkZ, path });
    return new Response(
      `openhost dial error: ${err && err.message ? err.message : err}`,
      { status: 502, headers: { "content-type": "text/plain" } },
    );
  }
}

function buildResponseFromOpenhost(reply) {
  const { head = "", bodyB64 } = reply;
  const bodyBuf = bodyB64 ? base64ToBytes(bodyB64) : null;
  const lines = head.split(/\r?\n/);
  const statusLine = lines[0] || "HTTP/1.1 200 OK";
  const m = /^HTTP\/\d\.\d\s+(\d+)\s*(.*)$/.exec(statusLine);
  const status = m ? parseInt(m[1], 10) : 200;
  const statusText = m ? m[2] : "";
  const headers = new Headers();
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    try {
      headers.append(name, value);
    } catch {
      /* forbidden header — skip */
    }
  }
  return new Response(bodyBuf, { status, statusText, headers });
}
