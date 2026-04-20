// `oh://` URL handler.
//
// Chrome MV3 has no native custom-scheme registration, so `oh://` URLs
// in the address bar never reach a DNS resolver. We intercept them at
// `webNavigation.onBeforeNavigate` (fires before any resolution
// attempt) and redirect the tab into our Service Worker's claimed
// scope at `chrome-extension://<ext>/oh/<daemon-pk>/<path>`.
//
// Post-PR-#40 the SW proxy (see `background.js`) intercepts every
// fetch under `/oh/*` and routes it through the openhost WebRTC
// session — the rendered page loads natively, subresources included.
// The legacy `viewer.html?oh=` shim is kept as a diagnostic fallback
// when the SW isn't active (e.g. first-install before the SW has
// claimed this origin).

const OH_URL_RE = /^oh:\/\/([a-z0-9]{52})(\/.*)?$/i;

export function installOhNavigationHandler() {
  if (!chrome.webNavigation) {
    console.warn("openhost: chrome.webNavigation unavailable — oh:// URLs will not intercept");
    return;
  }
  chrome.webNavigation.onBeforeNavigate.addListener(
    (details) => {
      if (!details.url.startsWith("oh://")) return;
      const match = OH_URL_RE.exec(details.url);
      if (!match) {
        console.warn("openhost: malformed oh:// URL, ignoring:", details.url);
        return;
      }
      const daemonPkZ = match[1].toLowerCase();
      const rest = match[2] || "/";
      // Redirect into the SW-claimed scope. The SW intercepts this
      // fetch (and every subsequent subresource fetch the rendered
      // page issues) and proxies through the openhost session.
      const target = chrome.runtime.getURL(`oh/${daemonPkZ}${rest}`);
      chrome.tabs.update(details.tabId, { url: target });
    },
    { url: [{ schemes: ["oh"] }] },
  );
  console.log("openhost: oh:// URL handler armed");
}
