# oh-send landing page copy

Source copy for `oh-send.dev`. The web client at `products/oh-send/web/` renders this content. Treat this file as the canonical text — if a headline changes here, it changes on the site.

---

## Hero

### Headline

**WeTransfer, without the upload.**

### Subhead

Drop a file. Get a link. The recipient opens it. The bytes go straight from your device to theirs — no server copy, no size cap, no account.

### Primary CTA

**Send a file** *(opens the drag-and-drop zone in place)*

### Secondary CTA

`brew install kaicoder03/openhost/oh-send` *(copy button)*

---

## The 5-second demo (above the fold, autoplays muted)

Three-panel loop, 5 seconds total:

1. **0–1.5s** — drag a `40 GB movie.mkv` into the browser. A link appears: `oh://kn7p…/9f2a`.
2. **1.5–3s** — the recipient opens the link on another laptop. Browser shows "Connecting directly to sender…" then "Transferring — 1.2 GB/s."
3. **3–5s** — progress bar fills. Caption overlay: *"No upload. No server copy. No size limit. No account."*

No stock footage. No "actors looking at laptops." A real browser recording.

---

## Three-feature block (below the fold)

### No upload step

Traditional transfer tools upload your file to their servers first, then let the recipient download it. We skip the middleman. Your file streams directly from your device to theirs over an encrypted WebRTC channel. A 40 GB export starts playing on the other end before it would have finished uploading to WeTransfer.

### True end-to-end encryption, by default

DTLS 1.3 with ChaCha20-Poly1305, channel-bound per RFC 8844. The keys are generated on your device and never leave it. We can't read your files. We couldn't decrypt them if we wanted to. We couldn't hand them over if a government asked. There is nothing to hand over.

### No account. Ever.

Your identity is an Ed25519 public key generated in your browser. No email, no password, no "sign in with Google." The recipient needs nothing installed — they just open the link. This isn't a free tier we'll take away later; it's how the protocol works.

---

## Comparison strip (single row, scannable)

| | oh-send | WeTransfer | Dropbox Transfer | Wormhole.app |
|---|---|---|---|---|
| Max file size (free) | **Unlimited** | 2 GB | 100 MB | 10 GB |
| Server sees your file | **Never** | Yes | Yes | Encrypted, but held |
| Account required | **No** | Recipient: no, Sender: yes | Yes | No |
| Works across any network | **Yes** | Yes | Yes | Yes |
| Open-source protocol | **Yes** | No | No | No |
| Price | **Free** | $12/mo for 20 GB | $10/mo | Free |

Footnote: when a direct connection isn't possible (8–12% of sessions, typically strict corporate firewalls or cellular carrier-grade NAT) we fall back to an encrypted relay. The relay can see ciphertext but not plaintext, and free accounts get 5 GB of relayed traffic per month before we ask you to upgrade.

---

## How it actually works (for skeptics, expandable section)

1. Your browser generates an Ed25519 keypair. Never leaves the device.
2. The public key is published to the Mainline DHT as a signed [Pkarr](https://pkarr.org) record — the same DHT that backs BitTorrent, decentralized and not operated by us.
3. The recipient's browser resolves the record, fetches your WebRTC offer, and attempts ICE hole-punching directly to your device.
4. DTLS 1.3 handshake with ChaCha20-Poly1305. Channel-bound using the DTLS exporter so [RFC 8844 unknown-key-share attacks](https://datatracker.ietf.org/doc/html/rfc8844) can't redirect your file.
5. Bytes stream. We see nothing. The spec is public at [github.com/kaicoder03/openhost/tree/main/spec](https://github.com/kaicoder03/openhost/tree/main/spec).

If you'd rather run it yourself: `brew install kaicoder03/openhost/openhost` on your laptop, add the recipient's pubkey to your allowlist, and you've got a fully self-hosted, identity-pinned transfer channel. No oh-send.dev involved.

---

## FAQ

**How is this different from AirDrop?**
AirDrop only works between Apple devices on the same Wi-Fi. oh-send works across any network and any OS — Windows to Mac, phone to laptop, across the world.

**How is this different from Signal file send?**
Signal caps files at ~100 MB. oh-send has no cap. Also: Signal requires a phone number; oh-send requires nothing.

**What if I close the tab mid-transfer?**
The transfer fails. There is no server copy to resume from. The recipient can re-request and the transfer restarts. This is a deliberate trade-off for zero server-side persistence. Resumable transfers (with the ciphertext staged on our relay for you, keys still local) land in the Pro tier — opt-in, not default.

**Is this legal for HIPAA / GDPR?**
The protocol is designed to be compatible with both because we are not a data processor — we never touch your file. Teams plan (Q3 2026) adds signed BAA/DPA, audit logs, and SOC2 Type I documentation. Ask us.

**Why should I trust you?**
Don't. Read [the spec](https://github.com/kaicoder03/openhost/tree/main/spec), run the daemon yourself, and verify the browser build is reproducible (coming with Phase 3 of the roadmap). oh-send.dev is a convenience; the protocol doesn't need us.

**What happens when I run out of free relayed bandwidth?**
Direct transfers still work (most of the time they already are direct). When a transfer needs the relay and you're over the 5 GB/month free limit, we ask you to upgrade or wait until next month. We never silently downgrade your transfer or touch the file contents.

---

## Footer

Open source. [Spec](https://github.com/kaicoder03/openhost/tree/main/spec) · [Source](https://github.com/kaicoder03/openhost) · [Security](https://github.com/kaicoder03/openhost/blob/main/SECURITY.md) · [Status](https://status.oh-send.dev)

---

## Copy-writing notes (for internal review, remove before deploy)

- **Voice:** technical, unapologetic, a little proud. Our readers are developers, homelabbers, and privacy-careful prosumers. They can tell when marketing copy is bullshit; don't write any.
- **Words to avoid:** "seamless," "effortless," "secure" (unqualified), "military-grade," "blockchain," "revolutionary," "empower," any adjective that could describe literally any SaaS.
- **Words to keep:** "directly," "no server copy," "by default," "open-source," concrete file sizes, concrete percentages.
- **The 5-second demo is the most important asset on the page.** If we can't ship a real recording that makes the magic moment obvious, we are not ready to launch.
- **Do not lead with encryption.** Lead with the user-visible benefit ("no upload step"). Encryption is *how*, not *why*.
- **Comparison table must be honest.** If Wormhole.app raises their cap, we update the table. Trust compounds.
