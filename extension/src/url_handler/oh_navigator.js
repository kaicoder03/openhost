// `oh://` URL handler (PR #28.3 Phase 5 decision: webNavigation).
//
// Chrome MV3 has no native custom-scheme registration; the survey in
// `~/.claude/plans/tender-popping-kahn.md` §6 evaluated three candidates:
//
//   (a) `webNavigation.onBeforeNavigate` + programmatic redirect to
//       `chrome-extension://.../viewer.html?oh=...` — **chosen**.
//   (b) `declarativeNetRequest` rewrite on `https://openhost.invalid/...`
//       — requires users to type a non-`oh://` URL; UX regression.
//   (c) `registerProtocolHandler("oh", ...)` — Chromium's allowlist
//       rejects non-stdlib schemes; not shippable.
//
// `webNavigation.onBeforeNavigate` fires pre-DNS-resolution so we can
// cancel the URL-bar navigation and replace it with our extension tab.
// Redirecting at this stage avoids the "can't resolve oh://" error
// the omnibox would otherwise show, and costs only the
// `webNavigation` permission (no broad host access).

const VIEWER_URL = chrome.runtime.getURL("viewer.html");

export function installOhNavigationHandler() {
  if (!chrome.webNavigation) {
    console.warn("openhost: chrome.webNavigation unavailable — oh:// URLs will not intercept");
    return;
  }
  chrome.webNavigation.onBeforeNavigate.addListener(
    (details) => {
      if (!details.url.startsWith("oh://")) return;
      const target = `${VIEWER_URL}?oh=${encodeURIComponent(details.url)}`;
      chrome.tabs.update(details.tabId, { url: target });
    },
    { url: [{ schemes: ["oh"] }] },
  );
  console.log("openhost: oh:// URL handler armed");
}
