// Browser-side OpenhostSession (PR #28.3 Phase 6 + 6.1).
//
// Owns an RTCPeerConnection and drives the full dial handshake by
// calling into `openhost-pkarr-wasm` for sealing / cert-fp binding /
// frame codec / pkarr packet signing. JS never touches the client
// Ed25519 secret directly; it lives in IndexedDB and is passed as
// raw bytes into WASM only.
//
// End-to-end flow:
//   1. Resolve host packet (fetch from a Pkarr relay, WASM-verify).
//   2. Load or create a per-install client seed (IndexedDB).
//   3. Build RTCPeerConnection + data channel, create offer SDP.
//   4. WASM `seal_offer` → `build_offer_packet` (Ed25519-signed
//      BEP44 body) → HTTP PUT to a Pkarr relay.
//   5. Poll host zone for `_answer-<client-hash>-*` fragments; WASM
//      `decode_answer_fragments` + `open_answer`.
//   6. Apply answer SDP; await DTLS `connected` + DC `open`.
//   7. Channel binding: AUTH_NONCE → compute cert-fp binding →
//      sign_auth_client → send AUTH_CLIENT → verify AUTH_HOST.
//   8. Return a live OpenhostSession; caller issues HTTP via
//      session.request("GET", "/path").

import init, {
  decode_and_verify,
  decode_answer_fragments,
  seal_offer,
  open_answer,
  compute_cert_fp_binding,
  sign_auth_client,
  verify_auth_host,
  encode_frame,
  client_pubkey_from_seed,
  build_offer_packet,
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

// Full dial: resolve → seal + publish offer → poll answer → WebRTC
// connect → cert-fp binding handshake → return a live session.
export async function dialOhUrl(ohUrl, opts = {}) {
  await ensureWasmInit();
  const { daemonPkZ, path } = parseOhUrl(ohUrl);
  const nowTsBig = BigInt(Math.floor(Date.now() / 1000));

  // 1. Resolve + verify host record.
  const hostPacket = await fetchHostPacket(daemonPkZ);
  const hostRecord = decode_and_verify(hostPacket, daemonPkZ, nowTsBig);
  if (hostRecord.pubkey_zbase32 !== daemonPkZ) {
    // decode_and_verify already passed, so this is belt-and-suspenders —
    // the WASM layer pins the pubkey it was asked about into the DTO.
    // A mismatch here means something upstream re-shaped the struct.
    throw new Error(
      `host-record pubkey mismatch: asked ${daemonPkZ}, got ${hostRecord.pubkey_zbase32}`,
    );
  }
  const daemonSalt = hexToBytes(hostRecord.salt_hex);

  // 2. Client identity.
  const clientSeed = await loadOrCreateClientSeed();
  const clientPkZ = client_pubkey_from_seed(clientSeed);

  // 3. Build RTCPeerConnection + data channel.
  const pc = new RTCPeerConnection({ iceServers: STUN });
  const dc = pc.createDataChannel("openhost", { ordered: true });
  const reader = new FrameReader();
  dc.binaryType = "arraybuffer";
  dc.onmessage = e => reader.push(e.data);
  dc.onerror = e => reader.fail(new Error(`DC error: ${e}`));

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await waitForIceComplete(pc);
  const offerSdp = pc.localDescription.sdp;

  // 4. Seal + publish offer.
  const sealed = seal_offer(daemonPkZ, clientPkZ, offerSdp, BINDING_MODE_CERT_FP);
  const packet = build_offer_packet(clientSeed, daemonPkZ, sealed, BigInt(Math.floor(Date.now() / 1000)));
  await publishOfferPacket(clientPkZ, packet);

  // 5. Poll answer fragments on the daemon's zone. The host's DTLS
  // fingerprint was already verified under the BEP44 signature during
  // step 1; threading it here lets the v2 compact-blob branch
  // reconstruct the full SDP locally.
  const answerSdp = await pollAnswer({ daemonPkZ, daemonSalt, clientPkZ, clientSeed,
                                       hostDtlsFpHex: hostRecord.dtls_fingerprint_hex,
                                       timeoutMs: opts.answerTimeoutMs ?? 30_000 });

  // 6. Apply answer + wait for DTLS Connected.
  await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
  await waitForPcConnected(pc, opts.connectTimeoutMs ?? 10_000);
  await waitForDcOpen(dc, opts.connectTimeoutMs ?? 10_000);

  // 7. Channel-binding handshake.
  const nonceFrame = await reader.next(opts.bindingTimeoutMs ?? 10_000);
  if (nonceFrame.frame_type !== FRAME.AUTH_NONCE) {
    throw new Error(`expected AUTH_NONCE, got 0x${nonceFrame.frame_type.toString(16)}`);
  }
  const nonce = new Uint8Array(nonceFrame.payload);
  const certDer = await readRemoteCertDer(pc);
  const authBytes = compute_cert_fp_binding(certDer, daemonPkZ, clientPkZ, nonce);
  const authClientPayload = sign_auth_client(clientSeed, authBytes);
  dc.send(encode_frame(FRAME.AUTH_CLIENT, Array.from(authClientPayload)));

  const hostFrame = await reader.next(opts.bindingTimeoutMs ?? 10_000);
  if (hostFrame.frame_type !== FRAME.AUTH_HOST) {
    throw new Error(`expected AUTH_HOST, got 0x${hostFrame.frame_type.toString(16)}`);
  }
  const ok = verify_auth_host(daemonPkZ, authBytes, new Uint8Array(hostFrame.payload));
  if (!ok) {
    pc.close();
    throw new Error("AUTH_HOST signature did not verify — aborting session");
  }

  return new OpenhostSession({ pc, dc, reader, hostRecord, clientPkZ, daemonPkZ });
}

// ---- helpers ----

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function waitForIceComplete(pc) {
  return new Promise(res => {
    if (pc.iceGatheringState === "complete") return res();
    const check = () => {
      if (pc.iceGatheringState === "complete") {
        pc.removeEventListener("icegatheringstatechange", check);
        res();
      }
    };
    pc.addEventListener("icegatheringstatechange", check);
  });
}

function waitForPcConnected(pc, timeoutMs) {
  return new Promise((res, rej) => {
    if (pc.connectionState === "connected") return res();
    const timer = setTimeout(() => rej(new Error(`PC connect timeout (${timeoutMs}ms)`)), timeoutMs);
    const check = () => {
      if (pc.connectionState === "connected") { clearTimeout(timer); res(); }
      else if (["failed","closed","disconnected"].includes(pc.connectionState)) {
        clearTimeout(timer); rej(new Error(`PC state: ${pc.connectionState}`));
      }
    };
    pc.addEventListener("connectionstatechange", check);
  });
}

function waitForDcOpen(dc, timeoutMs) {
  return new Promise((res, rej) => {
    if (dc.readyState === "open") return res();
    const timer = setTimeout(() => rej(new Error(`DC open timeout (${timeoutMs}ms)`)), timeoutMs);
    dc.addEventListener("open", () => { clearTimeout(timer); res(); }, { once: true });
    dc.addEventListener("error", e => { clearTimeout(timer); rej(new Error(`DC error: ${e}`)); }, { once: true });
  });
}

async function readRemoteCertDer(pc) {
  // RTCDtlsTransport.getRemoteCertificates() returns an ArrayBuffer[]
  // (Chromium). Only the first cert is the peer's leaf.
  //
  // On some Chromium builds the cert array is populated *just after*
  // connectionState flips to "connected"; a short retry loop avoids a
  // false AUTH_NONCE-before-cert race on fast local connections.
  const transport = pc.sctp?.transport;
  if (!transport || typeof transport.getRemoteCertificates !== "function") {
    throw new Error("RTCDtlsTransport.getRemoteCertificates() unavailable");
  }
  const deadline = Date.now() + 1000;
  while (Date.now() < deadline) {
    const certs = transport.getRemoteCertificates();
    if (certs && certs.length > 0) return new Uint8Array(certs[0]);
    await new Promise(r => setTimeout(r, 25));
  }
  throw new Error("remote DTLS cert not available 1s after DC open");
}

async function publishOfferPacket(clientPkZ, packetBytes) {
  let lastErr;
  for (const r of RELAYS) {
    try {
      const resp = await fetch(`${r}/${clientPkZ}`, {
        method: "PUT", body: packetBytes,
        headers: { "Content-Type": "application/pkarr.org.relays.v1+octet" },
      });
      if (resp.ok) return;
      lastErr = new Error(`${r} → ${resp.status}`);
    } catch (e) { lastErr = e; }
  }
  throw new Error(`all relays rejected offer publish: ${lastErr?.message ?? "unknown"}`);
}

async function pollAnswer({ daemonPkZ, daemonSalt, clientPkZ, clientSeed, hostDtlsFpHex, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const packet = await fetchHostPacket(daemonPkZ);
      const ans = decode_answer_fragments(packet, daemonSalt, clientPkZ);
      if (ans) {
        const opened = open_answer(clientSeed, ans.sealed_base64url, hostDtlsFpHex);
        if (opened.daemon_pk_zbase32 !== daemonPkZ) {
          throw new Error("answer's inner daemon_pk does not match the packet signer");
        }
        return opened.answer_sdp;
      }
    } catch (e) {
      // Keep polling on transient decode / relay errors.
      if (e?.message && /verify|disagree|malformed|mismatch/i.test(e.message)) throw e;
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(`answer poll timed out after ${timeoutMs}ms`);
}
