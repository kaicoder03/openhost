---
title: Security and Threat Model
---

# Security and Threat Model

**Status:** Draft (M0). This document is normative for claims about what openhost protects against and what it does not.

## 1. Invariants

Every openhost implementation **MUST** preserve these invariants. An implementation that cannot uphold all five is not an openhost implementation.

1. **A host's Ed25519 private key never leaves the host.** It is stored in the platform keychain (or equivalent hardware-backed store where available).
2. **Traffic between a paired client and its host is end-to-end DTLS-encrypted from the browser socket to the daemon process.** No intermediary — STUN server, Pkarr relay, DHT node, Nostr relay, ISP, or other network node — ever sees plaintext payload.
3. **Client authentication is cryptographic, not network-based.** Each paired client holds its own Ed25519 keypair; the host maintains an allowlist of permitted client public keys.
4. **The DTLS certificate fingerprint is pinned to the host's Ed25519 public key via the signed Pkarr record.** A malicious relay that substitutes a different fingerprint cannot forge a valid Pkarr signature.
5. **A post-DTLS channel-binding handshake cryptographically binds both public keys to the specific TLS session**, defeating [RFC 8844](https://www.rfc-editor.org/rfc/rfc8844) unknown-key-share attacks.

## 2. Threat model

### 2.1 In scope (openhost defends against these)

- Network adversaries on the path between client and host — ISPs, coffee-shop Wi-Fi, on-path attackers at the signaling layer.
- Malicious Pkarr relays. They can deny service (refuse to serve records) but cannot forge records without the host's Ed25519 private key.
- Moderate DHT attackers, including eclipse attempts against a specific pubkey. Defeated by the multi-substrate publication strategy in [`03-pkarr-records.md`](03-pkarr-records.md) §3.
- Malicious STUN servers. openhost ships with a self-hosted STUN implementation in the daemon and uses public STUN only as fallback; IPv6-only deployments skip STUN entirely.
- Compromised web pages running in the same browser as the extension. Mitigated by strict extension permissioning — see §3.4.
- Casual attackers who learn a host's public key. Discovery implies existence, not access; connecting still requires a client key on the allowlist.

### 2.2 Out of scope (openhost does NOT defend against these)

- Compromise of the host machine itself.
- Compromise of a paired client device.
- Global passive network observers correlating traffic patterns across substrates — timing and volume analysis of DTLS-encrypted streams.
- Nation-state adversaries mounting long-duration DHT eclipses or subverting multiple independent Pkarr relays simultaneously.
- Side-channel attacks against the underlying cryptographic libraries.
- Attacks on the user's browser or operating system outside openhost's code.

## 3. Identified attacks and their mitigations

The following attacks were identified during protocol design. Each row cites the required mitigation; all mitigations marked **required** are blockers for the v0.1 tag.

| # | Attack | Mitigation | Status |
|---|---|---|---|
| 7.1 | RFC 8844 unknown-key-share (Mallory publishes a record under his pubkey carrying the host's DTLS fingerprint) | Post-handshake channel-binding HMAC keyed by TLS exporter, covering both pubkeys and a daemon-generated nonce | spec-only (M0) — implemented in M3 — **required** |
| 7.2 | Malicious Pkarr relay denies or replays stale records | Query ≥3 independent public relays + direct DHT; select highest `seq`; internal 2-hour `ts` window | spec-only — implemented in M2 — **required** |
| 7.3 | QR pairing trust-on-first-use subversion | BIP39 4-word fingerprint display on both devices at pairing + post-handshake SAS derived from TLS exporter | spec-only — implemented in M6 — **required** |
| 7.4 | Browser extension as an attack surface | Minimum-permission manifest; no `tabs`, no `cookies`, no broad origin access; reproducible builds; strict CSP; no remote code | spec-only — implemented in M5 — **required** |
| 7.5 | STUN privacy leak (host IP disclosure to STUN provider) | Self-hosted STUN in daemon; public STUN (Cloudflare, not Google) as fallback; IPv6-only mode skips STUN | spec-only — implemented in M3 — **required** |
| 7.6 | DTLS role confusion | Daemon **MUST** advertise `a=setup:passive`; client **MUST** advertise `a=setup:active`; both pubkeys in canonical order enter the auth HMAC input | spec-only — implemented in M3 — **required** |
| 7.7 | Replay of stale Pkarr records | Internal `ts` field inside the signed payload; clients reject records older than 2 hours | spec-only — implemented in M2 — **required** |
| 7.8 | ICE candidate leaks reveal host's private topology to non-paired observers | Per-client sealed-box encryption of the ICE candidate blob; non-paired observers see only `_ice.*` records' existence | spec-only — implemented in M2 — **required** |
| 7.9 | Mainline DHT eclipse attack against a specific pubkey | Multi-substrate publication (DHT + relays + optional Nostr); client races all available substrates | spec-only — implemented in M2/M3 — **required** |
| 7.10 | iOS background suspension kills the WebRTC connection | Documented re-connection behavior; long-lived key storage in iOS keychain via native app (bypasses 7-day browser storage eviction) | spec-only — implemented in M7 — **required** |
| 7.11 | WebRTC library CVE exposure | Prefer `webrtc-rs` over Node bindings; daemon sandbox with macOS entitlements and non-root LaunchAgent; CVE feed subscription; unauthenticated-attempt rate limiting | ongoing |
| 7.12 | Localhost-forward SSRF from malicious request | Hop-by-hop headers stripped; `X-Forwarded-For`/`Forwarded` not passed through; `Host` forced to configured value; WebSocket upgrades gated by explicit per-path config | spec-only — implemented in M3 — **required** |
| 7.13 | Unauthorized connection attempts exhaust daemon resources | Hashed allowlist of client pubkeys in `_allow` record; daemon rejects connections from non-allowlisted pubkeys pre-DTLS; per-source-IP and per-pubkey rate limits | spec-only — implemented in M3 — **required** |

"Status" values:
- **spec-only** — specified here; no implementation yet.
- **implemented** — code exists and passes tests against the spec vectors.
- **ongoing** — requires continuous operational work, not a one-time fix.

## 4. Cryptographic primitives

openhost uses only well-audited, standard primitives:

| Purpose | Primitive | Crate / reference |
|---|---|---|
| Identity signatures | Ed25519 (RFC 8032, strict verification) | `ed25519-dalek` v2 |
| Sealed-box encryption (per-client ICE blobs) | libsodium `crypto_box_seal` (X25519 + XSalsa20-Poly1305) | `crypto_box` with `seal` feature |
| Channel binding | HKDF-SHA256 over TLS exporter (RFC 5705) | `hkdf`, `sha2` |
| HMAC for allowlist hashing | HMAC-SHA256 | `hmac`, `sha2` |
| Transport encryption | DTLS 1.3 | provided by the WebRTC implementation |
| Public key display | z-base-32 | `zbase32` |

No custom cryptography is defined anywhere in the openhost protocol. Any apparent departure from these primitives is a bug.

## 5. Security response

See [`../SECURITY.md`](../SECURITY.md) for the reporting process and response-time commitments.
