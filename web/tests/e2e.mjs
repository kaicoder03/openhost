// CLI-send → Web-recv end-to-end test.
//
// 1. Launch a headless Chromium via Playwright.
// 2. Load http://localhost:PORT/recv.html?code=<uri from `oh send`>.
// 3. Click Receive, wait for the download event.
// 4. Compare the downloaded bytes' sha256 with the sender's input.

import { chromium } from "/tmp/oh-browser/node_modules/playwright/index.mjs";
import { readFile, writeFile, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import crypto from "node:crypto";

const WEB_PORT = Number(process.env.WEB_PORT ?? "8000");
const PAIR_URI = process.env.PAIR_URI;
const INPUT_FILE = process.env.INPUT_FILE ?? "/tmp/oh-smoke/test.bin";

if (!PAIR_URI) {
  console.error("ERROR: set PAIR_URI=oh+pair://... before running.");
  process.exit(2);
}

const expectedSha = crypto
  .createHash("sha256")
  .update(await readFile(INPUT_FILE))
  .digest("hex");

const browser = await chromium.launch({
  headless: false,
  // Chrome's WebRTC hides LAN IPs behind mDNS `.local` names by
  // default. webrtc-rs (used by the Mac CLI sender) does not
  // resolve mDNS, so the browser's host candidates become
  // unreachable. Opting out of the obfuscation exposes real LAN
  // IPs — fine for a localhost test; for production a browser
  // peer should rely on STUN srflx + TURN relay fallback instead.
  args: [
    "--disable-features=WebRtcHideLocalIpsWithMdns",
    "--disable-features=BlockInsecurePrivateNetworkRequests,PrivateNetworkAccessRespectPreflightResults",
    // Force default candidate policy — emit host + srflx + relay
    // on every interface rather than hiding private addresses.
    "--force-webrtc-ip-handling-policy=default",
  ],
});
const ctx = await browser.newContext({
  acceptDownloads: true,
});
const page = await ctx.newPage();
page.on("console", (msg) => console.log(`[page ${msg.type()}] ${msg.text()}`));
page.on("requestfailed", (req) =>
  console.log(`[reqfail] ${req.method()} ${req.url()} :: ${req.failure()?.errorText}`),
);
page.on("pageerror", (err) => console.log(`[page err] ${err.message}`));

const url = `http://localhost:${WEB_PORT}/recv.html?code=${encodeURIComponent(PAIR_URI)}`;
console.log(`opening ${url}`);
await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });

// Trigger the receive button.
const downloadPromise = page.waitForEvent("download", { timeout: 180_000 });
await page.click("#recv-btn");

console.log("waiting for download…");
const download = await downloadPromise;
const suggestedName = download.suggestedFilename();
console.log(`download fired: ${suggestedName}`);
const tmp = await mkdtemp(join(tmpdir(), "oh-web-e2e-"));
const downloadedPath = join(tmp, suggestedName);
await download.saveAs(downloadedPath);

const downloadedBytes = await readFile(downloadedPath);
const gotSha = crypto.createHash("sha256").update(downloadedBytes).digest("hex");
console.log(`downloaded ${downloadedBytes.length} bytes; sha256=${gotSha}`);
console.log(`expected ${expectedSha}`);

if (gotSha !== expectedSha) {
  console.error("SHA256 MISMATCH");
  await browser.close();
  process.exit(1);
}

// Capture final DOM state for diagnostics.
const statusText = await page.textContent("#status");
console.log("status panel:\n" + statusText);
console.log("OK: byte-identical, end-to-end via web app");
await browser.close();
