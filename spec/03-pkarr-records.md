---
title: Pkarr Records and Discovery
---

# Pkarr Records and Discovery

**Status:** Draft (M0).

This document specifies how openhost hosts publish and clients resolve discovery records, and what redundancy is required across public substrates.

## 1. Publication

A host **MUST** publish its signed DNS packet to at least one of the substrates described in §2. A host **SHOULD** publish to all substrates it has connectivity to, for resilience against any single substrate being censored, slow, or temporarily offline.

The signed packet is formed per [`01-wire-format.md`](01-wire-format.md) §2. The BEP44 mutable item key is the host's Ed25519 public key; the `seq` field is the Unix epoch time of publication.

The host **MUST** republish every 30 minutes, and **MUST** republish immediately on:

- Network interface change (new IP, new path).
- DTLS certificate rotation (updated `fp`).
- Allowlist modification.

## 2. Substrates

openhost uses three public substrates, in descending order of preference for resolution latency:

### 2.1 Public Pkarr HTTP relays

Pkarr relays are HTTPS endpoints that accept signed BEP44 records and serve them to clients. A client implementation **MUST** ship with a bundled list of known public relays, **MUST** query at least three independent substrates in parallel for any resolution (the bundled relays plus the Mainline DHT on native platforms, or — on browsers, where UDP is unavailable — at least three relays), and **MUST** accept the record with the highest `seq` value whose signature and internal timestamp both validate.

Browsers cannot speak the Mainline DHT directly (no UDP in the browser sandbox), so Pkarr relays are the primary substrate for the browser extension.

Known public relays at M0 (informational — the list is editable by the end user, and no specific relay is assumed online):

- `pkarr.pubky.app`
- `relay.iroh.network`

If all configured relays fail, resolution **MUST** fail; a client **MUST NOT** silently fall back to an unsigned source.

### 2.2 Mainline DHT (direct)

The daemon (Rust, native UDP socket access) **MUST** publish directly to the Mainline DHT in addition to any relays. The Rust client library, when embedded in a native app, **SHOULD** also resolve directly. This bypasses relay unavailability or censorship.

Direct DHT queries use [BEP44](https://www.bittorrent.org/beps/bep_0044.html) `get` operations keyed by the host's Ed25519 public key.

### 2.3 Nostr relays (tertiary)

As a defense-in-depth measure, openhost supports publishing the same signed record (re-wrapped in a Nostr event) to public Nostr relays. This is optional per-host; clients that implement it **MUST** verify the event signature matches the host's Ed25519 key before trusting the payload.

**Event envelope** (Nostr `kind: 30078` — [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md) parameterized replaceable event, using the `d` tag for per-host indexing):

```json
{
  "kind": 30078,
  "tags": [
    ["d", "openhost:<hex-pubkey>"],
    ["t", "openhost"],
    ["openhost-v", "1"]
  ],
  "content": "<base64 of the full BEP44-style signed blob>",
  "pubkey": "<hex of host Ed25519 public key, re-interpreted as a Nostr secp public key>"
}
```

**Note on signature scheme:** Nostr events are natively signed with secp256k1 Schnorr, while openhost identities are Ed25519. To avoid requiring hosts to maintain a second keypair, the openhost Nostr wrapper publishes the same BEP44-signed blob inside `content` rather than relying on Nostr's own signature. Clients **MUST** validate the Ed25519 signature over the blob; they **MAY** ignore the outer Nostr signature entirely. Relays that require a valid Nostr signature will reject these events — those relays are simply not usable by openhost, which is acceptable since Nostr is tertiary.

**A simpler alternative** (to be evaluated during M2): maintain a separate secp256k1 key per host for Nostr-only publishing, cross-signing by Ed25519 and secp at publish time. The decision between these approaches is deferred until M2 implementation begins.

Nostr support is **optional in clients and in hosts**. A v0.1 implementation is considered conformant whether or not it implements Nostr.

## 3. Resolution priority

A client resolving `<host-pubkey>` **SHOULD**:

1. Query all configured Pkarr relays in parallel.
2. In parallel (native platforms only), query the Mainline DHT directly.
3. In parallel (if enabled), query configured Nostr relays.
4. Accept the first record that validates (signature, timestamp window, and — if the client has any cached record for this host — a `seq` that is ≥ the cached `seq`).
5. Continue waiting on in-flight queries for up to 1.5 seconds after the first accepted record; if a later-arriving record has a higher `seq`, prefer it (handles cases where the first responder was stale).

A client **MUST NOT** use a record whose signature fails to verify, whose timestamp is outside the 2-hour window, or whose `seq` is strictly less than the last seen `seq` for the same host pubkey.

## 4. Republication at the client side

Clients **MUST NOT** republish records they observe. Only the holder of the Ed25519 private key may publish records under that key. A client that observes a stale record **MAY** proactively re-query other substrates, but **MUST NOT** pass observed records onward.

## 5. Test vectors

Packet construction, signing, and verification test vectors live in [`test-vectors/`](test-vectors/):

- [`pkarr_record.json`](test-vectors/pkarr_record.json) — the reference `SignedRecord` (canonical signing bytes, Ed25519 signature, and negative-validation cases). Every implementation **MUST** reproduce its `canonical_hex` and `signature_hex` for the fixed seed.
- [`pkarr_packet.json`](test-vectors/pkarr_packet.json) — the reference `SignedRecord` after passing through the Pkarr layer: the bytes of a well-formed `pkarr::SignedPacket` (32-byte public key, 64-byte BEP44 signature, 8-byte microsecond timestamp, encoded DNS packet). Implementations **MUST** decode these bytes back into the referenced `SignedRecord` and **MUST** produce byte-identical output when re-encoding the same record with the same signing seed against the same pkarr wire version.
