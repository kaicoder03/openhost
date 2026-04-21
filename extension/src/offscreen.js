// Offscreen document — holds the OpenhostSession on behalf of the
// service worker. MV3 SWs don't expose RTCPeerConnection, so the dial
// + session-request happens here. One offscreen doc per extension;
// multiple daemons share this doc via a per-daemon session cache.

import { dialOhUrl } from "./dialer/openhost_session.js";

// Forward every console.log in this offscreen doc over to the SW so
// it shows up in SW DevTools (or in any tool listening to the SW
// console — Playwright, for instance). Offscreen docs don't surface
// as pages in most automation APIs, so without this the whole dial
// flow is opaque from outside.
(function forwardLogs() {
  const levels = ["log", "info", "warn", "error"];
  for (const lvl of levels) {
    const orig = console[lvl].bind(console);
    console[lvl] = (...args) => {
      try {
        chrome.runtime.sendMessage({
          kind: "openhost-log",
          level: lvl,
          args: args.map((a) => {
            try { return typeof a === "string" ? a : JSON.stringify(a); }
            catch { return String(a); }
          }),
        }).catch(() => {});
      } catch {}
      orig(...args);
    };
  }
})();

console.log("openhost offscreen: booted, awaiting SW requests");

// sessions: Map<daemonPkZ, Promise<OpenhostSession>>.
// Promise-valued entries deduplicate concurrent first-dials.
const sessions = new Map();

function getOrDialSession(daemonPkZ) {
  let pending = sessions.get(daemonPkZ);
  if (pending) return pending;
  pending = (async () => {
    const session = await dialOhUrl(`oh://${daemonPkZ}/`);
    // Serialise concurrent `.request()` calls through a single chain;
    // wire v2's `request_id` field is scaffolded but daemon-side
    // concurrent dispatch ships in a later PR.
    const orig = session.request.bind(session);
    let chain = Promise.resolve();
    session.request = (method, path, headers, body) => {
      const next = chain.then(() => orig(method, path, headers, body));
      chain = next.catch(() => {});
      return next;
    };
    try {
      session._pc.addEventListener("connectionstatechange", () => {
        const s = session._pc.connectionState;
        if (s === "failed" || s === "closed" || s === "disconnected") {
          console.log(
            "openhost offscreen: PC transitioned to",
            s,
            "— closing + evicting",
            daemonPkZ,
          );
          sessions.delete(daemonPkZ);
          // Without this the RTCPeerConnection + its ICE agent + its
          // TURN allocation stay alive forever: the PC keeps sending
          // STUN checks through the relay with its own stale ufrag,
          // which the daemon discards as a mismatched-session, which
          // in turn masks the real ICE state of any *new* dial.
          try { session._pc.close(); } catch {}
          try { session._dc.close(); } catch {}
        }
      });
    } catch (e) {
      console.warn("openhost offscreen: pc state listener attach failed", e);
    }
    return session;
  })();
  pending.catch(() => sessions.delete(daemonPkZ));
  sessions.set(daemonPkZ, pending);
  return pending;
}

// Uint8Array ↔ base64 helpers. chrome.runtime.sendMessage JSON-
// serialises its payloads, which destroys `ArrayBuffer` / `Uint8Array`
// into an empty `{}`. We therefore base64 the request + response
// bytes as they cross the SW ↔ offscreen boundary.
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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.kind !== "openhost-request") return false;
  (async () => {
    try {
      const session = await getOrDialSession(msg.daemonPkZ);
      const body =
        msg.bodyB64 == null ? null : base64ToBytes(msg.bodyB64);
      const resp = await session.request(
        msg.method,
        msg.path,
        msg.headers || {},
        body,
      );
      const respBytes =
        resp.body instanceof Uint8Array
          ? resp.body
          : new Uint8Array(resp.body || new ArrayBuffer(0));
      sendResponse({
        head: resp.head,
        bodyB64: bytesToBase64(respBytes),
      });
    } catch (err) {
      console.error("openhost offscreen: request failed", err);
      sendResponse({
        error: err && err.message ? err.message : String(err),
      });
    }
  })();
  return true; // keep the channel open for async sendResponse
});
