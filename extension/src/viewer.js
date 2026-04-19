// PR #28.3 Phase 6 viewer tab. Opens the `oh://<pk>/path` URL passed
// in via `?oh=…` query string, runs the dial, renders the response.
//
// Rendering strategy: sniff Content-Type, pick the simplest HTMLElement
// that can display it. Media types become <video>/<audio>/<img>;
// text/html renders in a sandboxed iframe; everything else is offered
// as a download link.
import { dialOhUrl, parseOhUrl } from "./dialer/openhost_session.js";

const statusEl = document.getElementById("status");
const contentEl = document.getElementById("content");
const targetEl = document.getElementById("target");

function setStatus(msg, isError = false) {
  statusEl.textContent = msg;
  statusEl.classList.toggle("error", isError);
}

const params = new URLSearchParams(window.location.search);
const ohUrl = params.get("oh");
if (!ohUrl) {
  setStatus("no oh:// URL supplied via ?oh= param", true);
} else {
  targetEl.textContent = ohUrl;
  run(ohUrl).catch(e => setStatus(`dial failed: ${e.message || e}`, true));
}

async function run(ohUrl) {
  const { daemonPkZ, path } = parseOhUrl(ohUrl);
  setStatus(`resolving ${daemonPkZ}…`);
  let session;
  try {
    session = await dialOhUrl(ohUrl);
  } catch (e) {
    setStatus(
      `dial failed: ${e.message}\n\n` +
      `PR #28.3 Phase 6 wired up the browser-side dialer skeleton + WASM ` +
      `primitives; the publish-offer bridge to Pkarr relays is deferred to ` +
      `PR #28.3.1. The WASM resolver probe at extension/src/dev/resolver-probe.js ` +
      `still works end-to-end — use that to smoke-test the resolver path today.`,
      true,
    );
    return;
  }

  setStatus(`dialed ${daemonPkZ}; GET ${path}…`);
  const resp = await session.request("GET", path);
  setStatus(`response head:\n${resp.head}`);
  await renderBody(resp);
  session.close();
}

async function renderBody({ head, body }) {
  const headerLine = head.split("\r\n").find(l => l.toLowerCase().startsWith("content-type:"));
  const contentType = headerLine ? headerLine.split(":", 2)[1].trim().split(";")[0].trim() : "";
  const blob = new Blob([body], { type: contentType || "application/octet-stream" });
  const url = URL.createObjectURL(blob);

  if (contentType.startsWith("video/")) {
    const v = document.createElement("video");
    v.controls = true; v.src = url; contentEl.appendChild(v);
  } else if (contentType.startsWith("audio/")) {
    const a = document.createElement("audio");
    a.controls = true; a.src = url; contentEl.appendChild(a);
  } else if (contentType.startsWith("image/")) {
    const img = document.createElement("img"); img.src = url; contentEl.appendChild(img);
  } else if (contentType === "text/html") {
    const iframe = document.createElement("iframe");
    iframe.sandbox = "allow-same-origin";
    iframe.srcdoc = new TextDecoder().decode(body);
    iframe.style.width = "100%"; iframe.style.height = "80vh"; iframe.style.border = "1px solid #ddd";
    contentEl.appendChild(iframe);
  } else {
    const a = document.createElement("a");
    a.href = url; a.download = "openhost-response"; a.textContent = `download (${body.length} bytes)`;
    contentEl.appendChild(a);
  }
}
