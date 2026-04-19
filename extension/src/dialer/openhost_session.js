// Browser-side OpenhostSession skeleton (PR #28.3 Phase 6).
//
// Owns an RTCPeerConnection and drives the dial handshake by calling
// into `openhost-pkarr-wasm` for sealing / cert-fp binding / frame
// codec. JS never touches the client Ed25519 secret directly; it
// lives in IndexedDB and is passed as raw bytes into WASM only.
//
// ## Status — what ships in PR #28.3
//
// This file establishes the class shape + wires the resolver (PR
// #28.2) + the WASM primitives (Phase 4) into a single entry point
// `dialOhUrl(ohUrl)`. The actual publish-offer step is deferred to
// **PR #28.3.1** because it requires two things not available yet:
//
//   1. A WASM-exported `client_pubkey_from_seed(seed) -> zbase32` so
//      JS can compute its own identity pubkey without re-implementing
//      Ed25519 point multiplication in JS. Cheap follow-up.
//   2. A WASM-exported `build_offer_packet(client_sk, daemon_pk, sealed)
//      -> Uint8Array` that returns the serialized pkarr `SignedPacket`
//      bytes ready for a Pkarr relay PUT. Today the relay API expects
//      a full BEP44 mutable-item body (Ed25519 signature + DNS wire
//      format). Shipping it as WASM reuses the existing
//      `openhost_pkarr::encode_with_answers` path with no client-side
//      wire-format duplication.
//
// Both gaps are small, scoped follow-ups on the same branch. The
// rest of the extension (URL handler, viewer, manifest, service
// worker) is wired up in this PR so the review surface stays
// digestible.

import init, {
  decode_and_verify,
  decode_answer_fragments,
  seal_offer,
  open_answer,
  compute_cert_fp_binding,
  sign_auth_client,
  verify_auth_host,
  encode_frame,
} from "../../wasm/pkg/openhost_pkarr.js";
import { FrameReader } from "../session/frame_reader.js";

// Wire constants (mirror `openhost_core::wire::FrameType` + spec §4).
export const FRAME = Object.freeze({
  REQUEST_HEAD: 0x01, REQUEST_BODY: 0x02, REQUEST_END: 0x03,
  RESPONSE_HEAD: 0x11, RESPONSE_BODY: 0x12, RESPONSE_END: 0x13,
  AUTH_NONCE: 0x30, AUTH_CLIENT: 0x31, AUTH_HOST: 0x32,
  ERROR: 0xF0, PING: 0xFE, PONG: 0xFF,
});

export const BINDING_MODE_CERT_FP = 0x02;

const RELAYS = [
  "https://relay.pkarr.org",
  "https://pkarr.pubky.app",
  "https://pkarr.pubky.org",
];
const STUN = [{ urls: "stun:stun.l.google.com:19302" }];

let initPromise = null;
export function ensureWasmInit() {
  if (!initPromise) initPromise = init();
  return initPromise;
}

export function parseOhUrl(ohUrl) {
  const m = /^oh:\/\/([a-z0-9]{52})(\/.*)?$/i.exec(ohUrl);
  if (!m) throw new Error(`invalid oh:// URL: ${ohUrl}`);
  return { daemonPkZ: m[1].toLowerCase(), path: m[2] || "/" };
}

export async function fetchHostPacket(daemonPkZ) {
  for (const r of RELAYS) {
    try {
      const resp = await fetch(`${r}/${daemonPkZ}`);
      if (resp.ok) return new Uint8Array(await resp.arrayBuffer());
    } catch {}
  }
  throw new Error(`no relay returned a packet for ${daemonPkZ}`);
}

// Per-install client identity. 32-byte Ed25519 seed lives in
// IndexedDB; `indexedDB` is available in MV3 service workers since
// Chrome 85+ (2020). PR #28.5 adds pairing + backup UX; for now the
// seed is generated on first use and never surfaced.
export async function loadOrCreateClientSeed() {
  const db = await new Promise((res, rej) => {
    const r = indexedDB.open("openhost", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("identity");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  const tx = db.transaction("identity", "readwrite");
  const store = tx.objectStore("identity");
  let seed = await new Promise((res, rej) => {
    const g = store.get("client_seed");
    g.onsuccess = () => res(g.result);
    g.onerror = () => rej(g.error);
  });
  if (!seed) {
    seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    await new Promise((res, rej) => {
      const p = store.put(seed, "client_seed");
      p.onsuccess = () => res();
      p.onerror = () => rej(p.error);
    });
  }
  return seed instanceof Uint8Array ? seed : new Uint8Array(seed);
}

// A live WebRTC session — post-binding, ready for HTTP round-trips.
// Constructed internally by `dialOhUrl`; opaque to callers.
export class OpenhostSession {
  constructor({ pc, dc, reader, hostRecord, clientPkZ, daemonPkZ }) {
    this._pc = pc; this._dc = dc; this._reader = reader;
    this.hostRecord = hostRecord;
    this.clientPkZ = clientPkZ; this.daemonPkZ = daemonPkZ;
  }

  // Send one HTTP/1.1 request, return a Response-shaped object.
  async request(method, path, headers = {}, body = null) {
    const headLines = [`${method} ${path} HTTP/1.1`, "Host: openhost"];
    for (const [k, v] of Object.entries(headers)) headLines.push(`${k}: ${v}`);
    const headBytes = new TextEncoder().encode(headLines.join("\r\n") + "\r\n\r\n");
    this._dc.send(encode_frame(FRAME.REQUEST_HEAD, Array.from(headBytes)));
    if (body) this._dc.send(encode_frame(FRAME.REQUEST_BODY, Array.from(body)));
    this._dc.send(encode_frame(FRAME.REQUEST_END, []));

    const headFrame = await this._reader.next();
    if (headFrame.frame_type !== FRAME.RESPONSE_HEAD) {
      throw new Error(`expected RESPONSE_HEAD, got 0x${headFrame.frame_type.toString(16)}`);
    }
    const respHead = new TextDecoder().decode(new Uint8Array(headFrame.payload));
    const bodyChunks = [];
    while (true) {
      const f = await this._reader.next();
      if (f.frame_type === FRAME.RESPONSE_BODY) bodyChunks.push(new Uint8Array(f.payload));
      else if (f.frame_type === FRAME.RESPONSE_END) break;
      else if (f.frame_type === FRAME.ERROR) {
        throw new Error(`daemon error: ${new TextDecoder().decode(new Uint8Array(f.payload))}`);
      } else throw new Error(`unexpected frame 0x${f.frame_type.toString(16)}`);
    }
    const total = bodyChunks.reduce((n, c) => n + c.length, 0);
    const body_out = new Uint8Array(total);
    let off = 0;
    for (const c of bodyChunks) { body_out.set(c, off); off += c.length; }
    return { head: respHead, body: body_out };
  }

  close() {
    try { this._dc.close(); } catch {}
    try { this._pc.close(); } catch {}
  }
}

// Full dial. **Not runnable end-to-end in PR #28.3** — see the status
// block at the top of this file for the Phase 6.1 gap.
export async function dialOhUrl(ohUrl) {
  await ensureWasmInit();
  const { daemonPkZ, path } = parseOhUrl(ohUrl);
  const nowTs = BigInt(Math.floor(Date.now() / 1000));

  // 1. Resolve + verify host record via the PR #28.2 WASM path.
  const hostPacket = await fetchHostPacket(daemonPkZ);
  const hostRecord = decode_and_verify(hostPacket, daemonPkZ, nowTs);

  // 2. Client identity.
  const clientSeed = await loadOrCreateClientSeed();

  // 3-12: handshake wiring. Marked as a deliberate throw until the
  // publish bridge (WASM `build_offer_packet` + `client_pubkey_from_seed`)
  // lands in PR #28.3.1. The resolver probe in
  // `extension/src/dev/resolver-probe.js` still exercises the
  // already-shipped WASM surface end-to-end.
  throw new Error(
    `openhost extension: dial pipeline wired up through WASM seal/binding/framing, ` +
    `but the Pkarr publish bridge is pending PR #28.3.1 (need WASM ` +
    `build_offer_packet + client_pubkey_from_seed). Target: ${daemonPkZ}${path}. ` +
    `Host fingerprint: ${hostRecord.dtls_fingerprint_hex}. ` +
    `Client seed is persisted in IndexedDB (32 bytes).`
  );
}
