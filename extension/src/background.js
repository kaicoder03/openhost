// openhost extension service worker (MV3).
//
// Two responsibilities:
//
// 1. PR #28.3 Phase 6: URL handler — cancel `oh://` navigations and
//    redirect them into our SW-claimed `/oh/<pk>/...` scope.
//
// 2. PR #40: Service-Worker proxy for native in-browser rendering.
//    Every `fetch` of a URL under `chrome-extension://<ext>/oh/*` is
//    intercepted and routed through a live OpenhostSession's data
//    channel. Subresource loads inside the rendered page (CSS, JS,
//    images, video range requests) are transparently proxied by the
//    SAME SW instance, so a video-server page (HTML + styles.css +
//    app.js + videos) loads natively — no sandboxed iframe, no
//    404s on relative-URL assets.
//
// Session model: one OpenhostSession per daemon pubkey, cached for
// the SW's lifetime. Concurrent fetches (browsers fire many per page
// load) are serialised through a single promise chain per session —
// the wire format supports multiplexing via `request_id` (PR #40 wire
// codec), but fully-concurrent multiplex awaits a follow-up PR to
// the session + daemon. Serial is strictly better than the previous
// sandboxed-iframe flow and ships the user's primary ask.

import { installOhNavigationHandler } from "./url_handler/oh_navigator.js";
import { dialOhUrl } from "./dialer/openhost_session.js";

console.log(
  "openhost extension: service worker booted; arming oh:// handler",
);

installOhNavigationHandler();

// ---------------------------------------------------------------------------
// SW fetch proxy — PR #40
// ---------------------------------------------------------------------------

/**
 * Cache of in-flight or established OpenhostSession promises, keyed
 * by daemon zbase32 pubkey. The promise shape means concurrent
 * fetches for the same daemon share one dial.
 */
const sessions = new Map();

/**
 * Matches the SW-claimed scope: `/oh/<52-char-zbase32>/<rest-of-path>`.
 * The `rest-of-path` is optional (a root `/oh/<pk>` or `/oh/<pk>/`
 * both route to path `/` on the daemon). Anything outside this scope
 * falls through to Chrome's default handler (e.g. extension-internal
 * resources at `/src/...`, `/wasm/...`, or the popup page).
 */
const OH_PATH_RE = /^\/oh\/([a-z0-9]{52})(\/.*)?$/i;

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  // Only claim paths inside our own extension origin.
  if (url.origin !== self.location.origin) return;
  const match = OH_PATH_RE.exec(url.pathname);
  if (!match) return; // not our scope — let Chrome handle it

  const daemonPkZ = match[1].toLowerCase();
  const path = (match[2] || "/") + (url.search || "");
  event.respondWith(handleOhFetch(daemonPkZ, path, event.request));
});

/**
 * Dial (or reuse) a session for the given daemon pubkey, then run
 * `session.request(...)` and translate the openhost response into a
 * native `Response` object the browser can render.
 */
async function handleOhFetch(daemonPkZ, path, request) {
  try {
    const session = await getOrDialSession(daemonPkZ);
    const headers = {};
    for (const [k, v] of request.headers.entries()) {
      // `host` is hard-coded by `session.request` to "openhost"; skip
      // the browser's computed value which would otherwise double.
      if (k.toLowerCase() === "host") continue;
      headers[k] = v;
    }
    const body =
      request.method === "GET" || request.method === "HEAD"
        ? null
        : new Uint8Array(await request.arrayBuffer());
    const resp = await session.request(request.method, path, headers, body);
    return buildResponseFromOpenhost(resp);
  } catch (err) {
    console.error("openhost SW: fetch failed", err, { daemonPkZ, path });
    // Serve a user-facing error page so the tab at least shows
    // something — avoids opaque "This site can't be reached".
    return new Response(
      `openhost dial error: ${err && err.message ? err.message : err}`,
      { status: 502, headers: { "content-type": "text/plain" } },
    );
  }
}

/**
 * Session cache + dial-once semantics. Concurrent callers awaiting
 * the same daemon share one Promise. On RTCPeerConnection close /
 * failure the entry is purged so the next fetch re-dials.
 */
function getOrDialSession(daemonPkZ) {
  let pending = sessions.get(daemonPkZ);
  if (pending) return pending;
  pending = (async () => {
    const session = await dialOhUrl(`oh://${daemonPkZ}/`);
    // Serialise concurrent `.request()` calls behind a single chain.
    // The current session + daemon don't yet multiplex on request_id;
    // without the lock, overlapping fetches would interleave
    // REQUEST_BODY frames and corrupt both responses.
    const origRequest = session.request.bind(session);
    let chain = Promise.resolve();
    session.request = (method, path, headers, body) => {
      const next = chain.then(() =>
        origRequest(method, path, headers, body),
      );
      // Swallow errors on the chain so one failing request doesn't
      // poison the next; the awaiter still sees the rejection.
      chain = next.catch(() => {});
      return next;
    };
    // Evict on connection failure so the next fetch re-dials.
    try {
      session._pc.addEventListener("connectionstatechange", () => {
        const s = session._pc.connectionState;
        if (s === "failed" || s === "closed" || s === "disconnected") {
          sessions.delete(daemonPkZ);
        }
      });
    } catch (e) {
      console.warn("openhost SW: could not attach pc state listener", e);
    }
    return session;
  })();
  // If the dial itself fails, drop the cached rejection so the next
  // fetch gets a fresh chance rather than inheriting the failure.
  pending.catch(() => sessions.delete(daemonPkZ));
  sessions.set(daemonPkZ, pending);
  return pending;
}

/**
 * Parse the openhost response `{ head, body }` shape into a native
 * `Response` the browser can render. `head` is an HTTP/1.1 status
 * line + headers block (terminated by \r\n\r\n, already stripped).
 */
function buildResponseFromOpenhost(resp) {
  const lines = (resp.head || "").split(/\r?\n/);
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
    // Browser rejects some hop-by-hop + forbidden headers on Response
    // (content-length, transfer-encoding, connection, etc.). Best
    // effort — set what we can, silently skip the rest.
    try {
      headers.append(name, value);
    } catch {
      // ignore
    }
  }
  return new Response(resp.body, { status, statusText, headers });
}

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
