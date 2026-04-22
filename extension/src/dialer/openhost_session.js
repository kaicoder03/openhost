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

// Backpressure thresholds for RTCDataChannel.send — pause queuing
// new frames once the send buffer exceeds the high-water mark, resume
// when it drains past the low-water mark. Prevents the SCTP stack
// from surfacing "Failure to send data" on large request bodies.
const DC_BUFFER_HIGH_WATER = 1024 * 1024;
const DC_BUFFER_LOW_WATER = 256 * 1024;

async function sendFrameWithBackpressure(dc, frameType, payload) {
  while (dc.bufferedAmount > DC_BUFFER_HIGH_WATER) {
    if (dc.bufferedAmountLowThreshold !== DC_BUFFER_LOW_WATER) {
      dc.bufferedAmountLowThreshold = DC_BUFFER_LOW_WATER;
    }
    await new Promise((resolve) => {
      const onLow = () => {
        dc.removeEventListener("bufferedamountlow", onLow);
        resolve();
      };
      dc.addEventListener("bufferedamountlow", onLow);
      setTimeout(() => {
        dc.removeEventListener("bufferedamountlow", onLow);
        resolve();
      }, 50);
    });
  }
  dc.send(encode_frame(frameType, Array.from(payload)));
}

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
  const failures = [];
  for (const r of RELAYS) {
    // Cache-buster query param forces Chrome to skip any cached
    // opaque / empty-body CORS response and re-issue a preflight.
    // Public pkarr relays either ignore unknown query params or
    // accept them as a cache hint.
    const url = `${r}/${daemonPkZ}?t=${Date.now()}`;
    try {
      const resp = await fetch(url, {
        mode: "cors",
        credentials: "omit",
        cache: "no-store",
      });
      if (!resp.ok) {
        failures.push(`${r}: HTTP ${resp.status}`);
        continue;
      }
      const buf = new Uint8Array(await resp.arrayBuffer());
      console.log(
        `[fetchHostPacket] ${r} → HTTP ${resp.status}, type=${resp.type}, ${buf.length} bytes`,
      );
      if (buf.length === 0) {
        // A 200 with empty body is almost always CORS stripping the
        // payload from the view of `fetch()`. Don't pass it to WASM —
        // the pkarr decoder then panics on truncated-packet bounds.
        failures.push(`${r}: 200 OK but empty body (CORS strip?)`);
        continue;
      }
      return buf;
    } catch (err) {
      failures.push(`${r}: ${err && err.message ? err.message : err}`);
    }
  }
  throw new Error(
    `no relay returned a usable packet for ${daemonPkZ}: ${failures.join("; ")}`,
  );
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
    await sendFrameWithBackpressure(this._dc, FRAME.REQUEST_HEAD, headBytes);
    if (body) {
      // Chunk the request body so each DC message stays under the SCTP
      // send-buffer's high-water mark, and await `bufferedAmountLow`
      // between chunks so a large POST doesn't overrun the data channel.
      const bodyBytes = body instanceof Uint8Array ? body : new Uint8Array(body);
      const CHUNK = 60 * 1024;
      for (let offset = 0; offset < bodyBytes.length; offset += CHUNK) {
        const end = Math.min(offset + CHUNK, bodyBytes.length);
        await sendFrameWithBackpressure(
          this._dc,
          FRAME.REQUEST_BODY,
          bodyBytes.subarray(offset, end),
        );
      }
    }
    await sendFrameWithBackpressure(this._dc, FRAME.REQUEST_END, new Uint8Array(0));

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
  console.log("[dial] entering dialOhUrl");
  await ensureWasmInit();
  console.log("[dial] A1 ensureWasmInit done");
  const { daemonPkZ, path } = parseOhUrl(ohUrl);
  const nowTsBig = BigInt(Math.floor(Date.now() / 1000));
  console.log("[dial] A2 parsed URL, daemonPkZ=", daemonPkZ);

  // 1. Resolve + verify host record.
  const hostPacket = await fetchHostPacket(daemonPkZ);
  console.log("[dial] A3 fetched host packet,", hostPacket.length, "bytes");
  const hostRecord = decode_and_verify(hostPacket, daemonPkZ, nowTsBig);
  console.log("[dial] A4 decode_and_verify OK, record.version=", hostRecord.version);
  if (hostRecord.pubkey_zbase32 !== daemonPkZ) {
    throw new Error(
      `host-record pubkey mismatch: asked ${daemonPkZ}, got ${hostRecord.pubkey_zbase32}`,
    );
  }
  const daemonSalt = hexToBytes(hostRecord.salt_hex);
  console.log("[dial] A5 salt parsed");

  // 2. Client identity.
  const clientSeed = await loadOrCreateClientSeed();
  console.log("[dial] A6 loadOrCreateClientSeed OK, seed bytes=", clientSeed.length);
  const clientPkZ = client_pubkey_from_seed(clientSeed);
  console.log("openhost dialer: client_pubkey_zbase32 =", clientPkZ);

  // 3. Build RTCPeerConnection + data channel. When the resolved
  // host record carries a v3 `turn_endpoint` (daemon advertises an
  // embedded TURN relay), add it to the ICE servers list so the PC
  // can fall back to a relayed candidate when direct hole-punching
  // fails. The TURN password is derived from the daemon's public
  // key — both sides compute the same value without a shared secret.
  const iceServers = [...STUN];
  if (hostRecord.turn_ip && hostRecord.turn_port) {
    const { turnIceServerFor } = await import("./turn_creds.js");
    const turnServer = await turnIceServerFor(daemonPkZ, {
      ip: hostRecord.turn_ip,
      port: hostRecord.turn_port,
    });
    if (turnServer) {
      iceServers.push(turnServer);
      console.log(
        "openhost dialer: TURN relay advertised —",
        turnServer.urls[0],
      );
    }
  }
  const pc = new RTCPeerConnection({ iceServers });
  const dc = pc.createDataChannel("openhost", { ordered: true });
  // RAII-style teardown: any exception after this point MUST close the
  // PC + DC, otherwise the ICE agent keeps running in the background
  // forever (sending STUN checks to the daemon via the TURN relay,
  // confusing future dials with stale-ufrag traffic).
  let teardown = () => {
    try { pc.close(); } catch {}
    try { dc.close(); } catch {}
  };
  try {
    const reader = new FrameReader();
    dc.binaryType = "arraybuffer";
    dc.onmessage = e => reader.push(e.data);
    dc.onerror = e => {
      const err = e && e.error;
      const detail = err
        ? `${err.errorDetail || err.name || "?"}: ${err.message || ""} sctpCauseCode=${err.sctpCauseCode ?? "-"} httpRequestStatusCode=${err.httpRequestStatusCode ?? "-"}`
        : String(e);
      reader.fail(new Error(`DC error: ${detail}`));
    };
    dc.onclose = () => {
      reader.fail(new Error("DC closed"));
    };

    pc.addEventListener("icegatheringstatechange", () =>
      console.log("[dial] icegathering state=", pc.iceGatheringState));
    pc.addEventListener("icecandidateerror", (e) =>
      console.log("[dial] icecandidateerror url=", e.url, "errorText=", e.errorText));
    const offer = await pc.createOffer();
    console.log("[dial] createOffer OK");
    await pc.setLocalDescription(offer);
    console.log("[dial] setLocalDescription OK, initial gatheringState=", pc.iceGatheringState);
    await waitForIceComplete(pc, 8000);
    console.log("[dial] waitForIceComplete done, gatheringState=", pc.iceGatheringState);
    const offerSdp = pc.localDescription.sdp;
    const ufrag = (offerSdp.match(/a=ice-ufrag:(\S+)/) || [])[1];
    const pwd = (offerSdp.match(/a=ice-pwd:(\S+)/) || [])[1];

    // 4. Seal + publish offer.
    console.log("[dial] A7 offer SDP ready,", offerSdp.length, "chars",
      "ufrag=", ufrag, "pwd_len=", pwd?.length);
    const sealed = seal_offer(daemonPkZ, clientPkZ, offerSdp, BINDING_MODE_CERT_FP);
    console.log("[dial] A8 seal_offer OK");
    const packet = build_offer_packet(clientSeed, daemonPkZ, sealed, BigInt(Math.floor(Date.now() / 1000)));
    console.log("[dial] A9 build_offer_packet OK");
    await publishOfferPacket(clientPkZ, packet);
    console.log("[dial] A10 publishOfferPacket done");

    // 5. Poll answer fragments on the daemon's zone.
    const answerSdp = await pollAnswer({ daemonPkZ, daemonSalt, clientPkZ, clientSeed,
                                         hostDtlsFpHex: hostRecord.dtls_fingerprint_hex,
                                         timeoutMs: opts.answerTimeoutMs ?? 30_000 });

    // 6. Apply answer + wait for DTLS Connected.
    await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
    // Log the CURRENT pc.localDescription ufrag AFTER answer applied,
    // to catch Chrome mutating ufrag mid-session.
    const ufragNow = (pc.localDescription.sdp.match(/a=ice-ufrag:(\S+)/) || [])[1];
    console.log("[dial] A11 answer applied; local ufrag now=", ufragNow,
      "(was", ufrag, ")");
    await waitForPcConnected(pc, opts.connectTimeoutMs ?? 45_000);
    await waitForDcOpen(dc, opts.connectTimeoutMs ?? 45_000);

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
      throw new Error("AUTH_HOST signature did not verify — aborting session");
    }

    // Session handed off to caller; they own teardown.
    teardown = () => {};
    return new OpenhostSession({ pc, dc, reader, hostRecord, clientPkZ, daemonPkZ });
  } finally {
    teardown();
  }
}

// ---- helpers ----

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function waitForIceComplete(pc, timeoutMs = 8000) {
  return new Promise((res) => {
    if (pc.iceGatheringState === "complete") return res();
    const timer = setTimeout(() => {
      pc.removeEventListener("icegatheringstatechange", check);
      console.log("[dial] waitForIceComplete timeout; proceeding with partial candidates");
      res();
    }, timeoutMs);
    const check = () => {
      if (pc.iceGatheringState === "complete") {
        clearTimeout(timer);
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
  let successes = 0;
  // Publish to EVERY relay in parallel-ish so the daemon (which may
  // resolve from a different relay set) has a chance to see the
  // packet on whichever relay it polls. Returning after the first
  // ok is what we used to do; it left the other relays without the
  // record and broke cross-relay rendezvous.
  // Fan out to every relay in parallel with a per-relay deadline.
  // One slow or hung relay must not stall the whole dial; we only
  // need one success for the daemon's poller to pick up the offer.
  const RELAY_TIMEOUT_MS = 8000;
  const results = await Promise.all(RELAYS.map(async (r) => {
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), RELAY_TIMEOUT_MS);
    try {
      const resp = await fetch(`${r}/${clientPkZ}`, {
        method: "PUT", body: packetBytes, signal: ac.signal,
        headers: { "Content-Type": "application/pkarr.org.relays.v1+octet" },
      });
      return resp.ok
        ? { ok: true, relay: r }
        : { ok: false, err: new Error(`${r} → ${resp.status}`) };
    } catch (e) {
      return { ok: false, err: e };
    } finally {
      clearTimeout(timer);
    }
  }));
  for (const r of results) {
    if (r.ok) successes += 1;
    else lastErr = r.err;
  }
  if (successes === 0) {
    throw new Error(`all relays rejected offer publish: ${lastErr?.message ?? "unknown"}`);
  }
}

async function pollAnswer({ daemonPkZ, daemonSalt, clientPkZ, clientSeed, hostDtlsFpHex, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const packet = await fetchHostPacket(daemonPkZ);
      const ans = decode_answer_fragments(packet, daemonSalt, clientPkZ, daemonPkZ);
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
