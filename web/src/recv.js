// Web-app receive flow.
//
// - Parse the pairing code (BIP-39 words OR `oh+pair://` URI).
// - Derive the receiver Ed25519 seed via the WASM `pairing_roles`
//   binding from openhost-pkarr-wasm.
// - Dial `oh://<sender_pk_zbase32>/` via the shared `dialOhUrl` helper
//   (reused from the browser extension), injecting our derived seed so
//   the daemon's offer poller matches the advertised receiver pubkey.
// - Issue `GET /` over the data channel, collect the body, and trigger
//   a browser download with the filename from `Content-Disposition`
//   (falling back to `openhost-transfer.bin`).
// - Verify `X-Openhost-File-Sha256` if the sender advertised it.

import init, {
  pairing_roles,
} from "../wasm/pkg/openhost_pkarr.js";
import { dialOhUrl, FRAME } from "./dialer/openhost_session.js";

const codeEl = document.getElementById("code");
const btnEl = document.getElementById("recv-btn");
const statusEl = document.getElementById("status");

// Auto-fill from `?code=<uri>` deep link. Lets QR scanners + the
// Flutter app share one URL format.
const params = new URLSearchParams(location.search);
const deepCode = params.get("code");
if (deepCode) {
  codeEl.value = deepCode;
}

document.getElementById("recv-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  btnEl.disabled = true;
  statusEl.className = "status";
  statusEl.textContent = "";

  try {
    await run();
  } catch (err) {
    setError(`failed: ${err?.message ?? err}`);
  } finally {
    btnEl.disabled = false;
  }
});

async function run() {
  log("Loading crypto primitives…");
  await init();

  const raw = codeEl.value.trim();
  if (!raw) throw new Error("pairing code is empty");
  let roles;
  try {
    roles = pairing_roles(raw);
  } catch (err) {
    throw new Error(`invalid pairing code: ${err?.message ?? err}`);
  }
  const receiverSeed = new Uint8Array(roles.receiver_seed);
  const senderPk = roles.sender_pubkey_zbase32;
  log(`Derived roles.\n  sender:   oh://${senderPk}/\n  receiver: ${roles.receiver_pubkey_zbase32}`);

  log("Dialing sender (may take up to 120 s)…");
  const session = await dialOhUrl(`oh://${senderPk}/`, {
    clientSeed: receiverSeed,
    answerTimeoutMs: 120_000,
    connectTimeoutMs: 45_000,
  });
  log("Connected. Requesting file…");

  const { head, body } = await session.request("GET", "/");

  const { status, headers } = parseHead(head);
  if (status < 200 || status >= 300) {
    throw new Error(`sender responded with HTTP ${status}`);
  }

  const filename = filenameFromCd(headers) ?? "openhost-transfer.bin";
  const expectedSha = headers.get("x-openhost-file-sha256");

  if (expectedSha) {
    const digest = await crypto.subtle.digest("SHA-256", body);
    const gotHex = Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    if (gotHex.toLowerCase() !== expectedSha.toLowerCase()) {
      throw new Error(
        `sha256 mismatch: expected ${expectedSha}, got ${gotHex}`,
      );
    }
    log(`sha256 OK (${gotHex.slice(0, 16)}…)`);
  }

  const blob = new Blob([body], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
    a.remove();
  }, 30_000);

  setOk(
    `Received ${filename} (${body.length.toLocaleString()} bytes). File transfer complete.`,
  );

  try { await session.close(); } catch (_) {}
}

// Parse the HTTP/1.1 head string (already UTF-8 decoded by
// `OpenhostSession.request`) into `{ status, headers: Map }`. Header
// keys are lower-cased so callers can match case-insensitively.
function parseHead(headText) {
  const lines = headText.split("\r\n");
  const first = lines[0] ?? "";
  const m = /^HTTP\/\d\.\d\s+(\d{3})/.exec(first);
  const status = m ? Number(m[1]) : 0;
  const headers = new Map();
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const ix = line.indexOf(":");
    if (ix < 0) continue;
    headers.set(line.slice(0, ix).trim().toLowerCase(), line.slice(ix + 1).trim());
  }
  return { status, headers };
}

// Minimal RFC 6266 parse: pick filename="..." OR filename=... from the
// Content-Disposition value, then sanitise aggressively since the
// filename is sender-controlled.
function filenameFromCd(headers) {
  const cd = headers.get("content-disposition");
  if (!cd) return null;
  for (const part of cd.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith("filename=")) {
      let name = trimmed.slice("filename=".length);
      if (name.startsWith('"') && name.endsWith('"')) name = name.slice(1, -1);
      name = name.replace(/\.{2,}/g, "__").replace(/[^\w.-]/g, "_");
      return name || null;
    }
  }
  return null;
}

function log(msg) {
  statusEl.textContent += (statusEl.textContent ? "\n" : "") + msg;
  statusEl.scrollTop = statusEl.scrollHeight;
}

function setError(msg) {
  statusEl.className = "status err";
  statusEl.textContent = msg;
}

function setOk(msg) {
  statusEl.className = "status ok";
  statusEl.textContent += (statusEl.textContent ? "\n" : "") + msg;
}

// re-export FRAME so third-party debug consoles can introspect the wire
// constants; avoids "FRAME is unused" tree-shaking warnings.
export { FRAME };
