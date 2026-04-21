// Offscreen document — holds the OpenhostSession on behalf of the
// service worker. MV3 SWs don't expose RTCPeerConnection, so the dial
// + session-request happens here. One offscreen doc per extension;
// multiple daemons share this doc via a per-daemon session cache.

import { dialOhUrl } from "./dialer/openhost_session.js";

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
          sessions.delete(daemonPkZ);
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

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.kind !== "openhost-request") return false;
  (async () => {
    try {
      const session = await getOrDialSession(msg.daemonPkZ);
      const body =
        msg.bodyBuf == null ? null : new Uint8Array(msg.bodyBuf);
      const resp = await session.request(
        msg.method,
        msg.path,
        msg.headers || {},
        body,
      );
      // `resp.body` is a Uint8Array view; pass its underlying buffer
      // so structured-clone can transfer it without a copy.
      const buf = resp.body instanceof Uint8Array ? resp.body.buffer : resp.body;
      sendResponse({ head: resp.head, bodyBuf: buf });
    } catch (err) {
      console.error("openhost offscreen: request failed", err);
      sendResponse({
        error: err && err.message ? err.message : String(err),
      });
    }
  })();
  return true; // keep the channel open for async sendResponse
});
