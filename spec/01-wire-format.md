---
title: Wire Format
---

# Wire Format

**Status:** Draft (M0).

This document specifies the openhost wire format: identity encoding, the Pkarr record schema, the connection-establishment sequence, and the HTTP-over-DataChannel framing. It is normative for v1 (`openhost1`).

Conformance language follows [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) / [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174): **MUST**, **SHOULD**, **MAY** carry their standard meanings.

## 1. Identity

Every openhost participant — hosts and clients alike — has an Ed25519 keypair.

- **Private key:** 32 bytes, generated from a system CSPRNG. Stored in the platform keychain (macOS Keychain / iOS Keychain / Linux Secret Service / Windows Credential Manager). It **MUST NOT** leave the device on which it was generated.
- **Public key:** 32 bytes, encoded for display and URLs in [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) (no padding). A 256-bit key encodes to 52 z-base-32 characters (`ceil(256 / 5) = 52`).

**Canonical URL form:**

```
oh://<zbase32-pubkey>[/<path>]
```

Example:

```
oh://8sxbksnfnwbzrhfsw7w7rqbt1bsafseqkk7oy83y5rdiswoofbcy/
```

Clients **MUST** reject any `oh://` URL whose host component fails z-base-32 decoding or does not decode to exactly 32 bytes.

## 2. Pkarr record schema

A host publishes a signed DNS packet as a BEP44 mutable item on the Mainline DHT and simultaneously to one or more public Pkarr relays. The packet's signing key is the host's Ed25519 keypair; the BEP44 `k` field is the host's public key. Record name suffixes are relative to the host's public key.

The packet **MUST** contain a single TXT resource record:

| Record name | Type | TTL | Contents |
|---|---|---|---|
| `_openhost` | TXT | 300 | `base64url(signature \|\| canonical_bytes)` — the 64-byte Ed25519 signature over `canonical_bytes` concatenated with the canonical byte representation of an `OpenhostRecord` (see below). |

`canonical_bytes` is the output of [`OpenhostRecord::canonical_signing_bytes`](../crates/openhost-core/src/pkarr_record/mod.rs), a deterministic, domain-separated encoding that carries every semantic field of the record — protocol version, Unix-seconds timestamp `ts`, DTLS fingerprint `dtls_fp`, declared `roles`, per-host allowlist `salt`, the `allow` list of 16-byte truncated HMAC entries, a per-paired-client `ice` list (each entry: 16-byte client hash + sealed-box ciphertext), and the informational `disc` hints string. Its exact layout is fixed in the openhost-core crate and reproduced verbatim in [`test-vectors/pkarr_record.json`](test-vectors/pkarr_record.json).

The base64url encoding uses the RFC 4648 §5 URL-safe alphabet without padding. If the encoded string exceeds 255 bytes, it **MUST** be split across multiple DNS character strings within the same TXT RDATA (per RFC 1035 §3.3.14); decoders reconstruct the payload by concatenating the character strings in the order they appear.

Two signatures bind the record:

- The **inner Ed25519 signature** (the 64-byte signature prefix of the `_openhost` TXT value) covers `canonical_bytes` and is produced by the host's Ed25519 identity key. Verifiers **MUST** re-check this signature against the host's public key before trusting the record.
- The **outer BEP44 signature** on the Pkarr packet itself is also produced by the same Ed25519 identity key — no separate keypair is used — and covers the bencoded DNS packet plus the BEP44 `seq` field. The `seq` field is set to the publication time in seconds since the Unix epoch (equal to `ts` inside the record).

**Constraints:**

- The encoded DNS packet (the BEP44 `v` value) **MUST** fit in 1000 bytes (the BEP44 mutable-item limit).
- `ts` is the publication time in seconds since the Unix epoch. Verifiers **MUST** reject records where `|now - ts| > 7200` (two hours).
- `dtls_fp` is the SHA-256 fingerprint of the daemon's DTLS certificate, 32 raw bytes inside `canonical_bytes`. The daemon **SHOULD** rotate this certificate daily or on restart.
- Each `client_hash` is 16 bytes of HMAC-SHA256 keyed by the per-host `salt` applied to the client's 32-byte Ed25519 public key. Unpaired observers see only that ICE blobs exist, not which client they address.
- Per-client ICE candidate ciphertext is a libsodium-compatible **sealed box** (`crypto_box_seal`): anonymous X25519 ephemeral sender to the recipient client's X25519 public key, with the XSalsa20-Poly1305 AEAD. The output is `ephemeral_pk || XSalsa20-Poly1305(shared_key, nonce = Blake2b-24(ephemeral_pk || recipient_pk), plaintext)`.
- The client's X25519 public key is derived from its Ed25519 identity via the Edwards-to-Montgomery conversion (libsodium's `crypto_sign_ed25519_pk_to_curve25519`), so clients and hosts maintain only one keypair.
- The `allow` list is carried inside `canonical_bytes` and lets clients verify they are paired before attempting a connection; the daemon uses it for dedupe.
- `disc` is informational; clients **MUST** try all substrates they know about regardless of the record's contents.

Republish cadence, relay fan-out, and resolver race semantics are specified in [`03-pkarr-records.md`](03-pkarr-records.md).

## 3. Connection establishment sequence

```
Client                                                    Daemon
  │                                                          │
  │ 1. Resolve <host_pubkey> via Pkarr (≥3 public relays     │
  │    raced against direct DHT query where available).      │
  │ 2. Verify BEP44 signature, reject if ts out of window,   │
  │    extract fp and _ice._<self-hash>.                     │
  │ 3. Decrypt _ice._<self-hash> with client's private key   │
  │    (sealed box; X25519 + XChaCha20-Poly1305).            │
  │                                                          │
  │ 4. Create RTCPeerConnection with daemon's ICE            │
  │    candidates as remoteDescription and a=setup:active.   │
  │ 5. Client publishes an ephemeral offer record under its  │
  │    own pubkey at _offer._<host-hash>, encrypted to the   │
  │    daemon's pubkey via sealed box.                       │
  │                                                          │
  │                                6. Daemon polls its own   │
  │                                   _offer.* records once  │
  │                                   per second, decrypts   │
  │                                   each, verifies the     │
  │                                   client pubkey is in    │
  │                                   _allow.                │
  │                                                          │
  │    ◄── 7. DTLS 1.3 handshake over hole-punched UDP ──►   │
  │                                                          │
  │ 8. Client MUST verify peer certificate fingerprint       │
  │    matches the `fp` value from the Pkarr record.         │
  │    Abort on mismatch.                                    │
  │                                                          │
  │ 9. Authentication channel binding (see 04-security §7.1): │
  │                                                          │
  │    Daemon → Client:                                      │
  │      AUTH_NONCE  : 32 random bytes                       │
  │                                                          │
  │    Client → Daemon:                                      │
  │      AUTH_CLIENT : client_pk (32 bytes)                  │
  │                  || Ed25519_sign(                        │
  │                         client_sk,                       │
  │                         auth_bytes(host_pk,              │
  │                                    client_pk,            │
  │                                    nonce))               │
  │                                                          │
  │    Daemon → Client:                                      │
  │      AUTH_HOST   : Ed25519_sign(                         │
  │                         host_sk,                         │
  │                         auth_bytes(host_pk,              │
  │                                    client_pk,            │
  │                                    nonce))               │
  │                                                          │
  │    where                                                 │
  │      auth_bytes(h, c, n) =                               │
  │        HKDF-SHA256(                                      │
  │          salt = "openhost-auth-v1",                      │
  │          ikm  = tls_exporter(                            │
  │                   label   = "EXPORTER-openhost-auth-v1", │
  │                   context = "",                          │
  │                   length  = 32),                         │
  │          info = "openhost-auth-v1" || h || c || n,       │
  │          length = 32)                                    │
  │                                                          │
  │    Both parties verify the counterparty's signature.     │
  │    On any failure, the connection MUST be torn down.     │
  │                                                          │
  │ 10. HTTP-over-DataChannel framing begins (§4).           │
```

**Rationale.** Two deliberate design choices worth naming explicitly:

1. **Client-first message order.** The daemon is the one that
   generates the nonce, but the client is the one whose Ed25519
   pubkey the daemon needs in order to compute `auth_bytes`. Letting
   the client send `AUTH_CLIENT` (carrying its pubkey as a 32-byte
   prefix alongside the signature) keeps the DTLS and handshake
   layers cleanly decoupled — the daemon doesn't need to read the
   offer record before DTLS-`Connected` fires. An earlier draft had
   the daemon sign first but required the daemon to pre-resolve
   `client_pk` by cracking open the sealed offer record at
   DTLS-setup time, a cross-layer coupling we chose to avoid.
2. **Empty DTLS exporter `context`.** webrtc-dtls v0.17.x rejects
   non-empty exporter `context` with `ContextUnsupported` (a TLS-1.3
   exporter spec-compliance gap). Rather than fork webrtc-dtls a
   second time, openhost folds the binding bytes into HKDF `info`
   instead. Cryptographically equivalent: the exporter secret is
   still session-unique, and HKDF still commits to
   `host_pk || client_pk || nonce`.

### 3.1 DTLS role

The daemon **MUST** assert `a=setup:passive` in its SDP. The client **MUST** assert `a=setup:active`. Receivers **MUST** reject SDP that does not match these assignments.

### 3.2 Fingerprint pinning

The `fp` value in the host's Pkarr record pins the expected DTLS certificate fingerprint. A client **MUST** abort the connection if the fingerprint negotiated during the DTLS handshake does not exactly equal `fp`. This prevents unknown-key-share attacks even in the presence of a malicious Pkarr relay (see [`04-security.md`](04-security.md)).

### 3.3 Offer and answer records

**Offer (client → daemon).** Per §3 step 5, the client publishes a
`SignedPacket` under its own Ed25519 pubkey containing **one** TXT
record at the single-label name

```
_offer-<host-hash-label>
```

where `host-hash-label = z_base_32(SHA-256(b"openhost-offer-host-v1" || daemon_pk)[0..16])`
— a 26-character lower-case alphanumeric string. The TXT value is
`base64url_nopad(sealed_ct)` where `sealed_ct` is a libsodium sealed-box
(`crypto_box_seal`) of the canonical plaintext below, addressed to
`public_key_to_x25519(daemon_pk)`.

The inner plaintext begins with a 1-byte `compression_tag` that
determines the layout of the remaining bytes:

```
offer_plaintext = compression_tag || body

  compression_tag : u8
      0x01 = Uncompressed (v1 legacy). `body` bytes are literal.
      0x02 = Zlib (v2, RFC 1950). `body` bytes are the RFC 1950 encoding
             of the uncompressed body below. Decompressed `body` size
             MUST NOT exceed 65536 bytes; decoders MUST reject
             oversized inputs.
      Other values MUST be rejected as malformed.

  body =  "openhost-offer-inner1"  (21 bytes)
       || client_pk                 (32 bytes)
       || sdp_len                   (u32 big-endian)
       || offer_sdp_utf8            (sdp_len bytes)
```

v0.1+ encoders **MUST** emit `compression_tag = 0x02`. v0.1+ decoders
**MUST** accept both `0x01` and `0x02` for backward compatibility
with pre-v0.1 blobs. Future codecs can claim new tag values without
invalidating existing implementations.

The inner `client_pk` **MUST** match the outer BEP44 signer pubkey.
The daemon verifies this on decode and rejects a mismatch.

**Answer (daemon → client).** The daemon publishes answer records as
**extra** TXT entries inside its existing `_openhost` `SignedPacket`, at
the single-label name

```
_answer-<client-hash-label>
```

where `client-hash-label = z_base_32(allowlist_hash(daemon_salt, client_pk))`
— reusing the same HMAC construction `_allow` uses (see §2). Putting
the answer TXT inside the same packet as `_openhost` is required because
BEP44 permits only one mutable item per pubkey.

The TXT value is `base64url_nopad(sealed_ct)` with the same
`compression_tag || body` framing as the offer. The answer body is:

```
  body =  "openhost-answer-inner1"   (22 bytes)
       || daemon_pk                   (32 bytes)
       || offer_sdp_hash              (32 bytes, SHA-256 of the UTF-8
                                       offer SDP being answered)
       || sdp_len                     (u32 big-endian)
       || answer_sdp_utf8             (sdp_len bytes)
```

`offer_sdp_hash` binds the answer to a specific offer; a racing
adversary cannot splice a valid answer onto a different offer. The
inner `daemon_pk` **MUST** match the outer BEP44 signer.

TXT TTL for both records is 30 seconds (ephemeral per-handshake).

**Encoder constraint (eviction).** The main `_openhost` record + all
`_answer-*` entries MUST fit in the BEP44 1000-byte limit. When an
answer would overflow, the daemon evicts the oldest entries (lowest
creation timestamp first). Compression (v2 tag) reduces the common
case to something that fits; high-entropy SDPs (those dominated by
DTLS fingerprints + ICE credentials) still approach the cap.
Splitting an answer across multiple records — allowing arbitrarily
large SDPs plus ICE trickle — is tracked as post-v0.1 work.

## 4. HTTP-over-DataChannel framing (ABNF)

Frames on an openhost data channel are binary, length-prefixed, and typed.

```text
; ABNF per RFC 5234, with extensions from RFC 7405.
; `uint8`, `uint32` denote network-byte-order unsigned integers.

frame          = type length payload
type           = uint8
length         = uint32                 ; number of octets in payload; 0 <= length <= 2^24-1
payload        = *OCTET                 ; exactly `length` octets

; Frame types carried within an HTTP-over-DataChannel session:
;
;   0x01  REQUEST_HEAD     UTF-8 HTTP/1.1 request line and headers, CRLF-separated,
;                          terminated by a blank line.
;   0x02  REQUEST_BODY     Opaque bytes; one chunk of the request body.
;   0x03  REQUEST_END      Empty payload; marks end of request body.
;
;   0x11  RESPONSE_HEAD    UTF-8 HTTP/1.1 status line and headers, CRLF-separated,
;                          terminated by a blank line.
;   0x12  RESPONSE_BODY    Opaque bytes; one chunk of the response body.
;   0x13  RESPONSE_END     Empty payload; marks end of response body.
;
;   0x20  WS_UPGRADE       UTF-8 RFC 6455 upgrade handshake. Only accepted when the
;                          daemon configuration explicitly permits WebSocket upgrades
;                          for the target path.
;   0x21  WS_FRAME         Transparent RFC 6455 frame after a successful 0x20 exchange.
;
;   0x30  AUTH_NONCE       Daemon → Client. 32 random bytes. Sent once per data
;                          channel, immediately after DTLS Connected (§3 step 9).
;   0x31  AUTH_CLIENT      Client → Daemon. 32-byte Ed25519 client_pk || 64-byte
;                          Ed25519 sig_client(auth_bytes(host_pk, client_pk, nonce)).
;   0x32  AUTH_HOST        Daemon → Client. 64-byte Ed25519
;                          sig_host(auth_bytes(host_pk, client_pk, nonce)).
;
;   0xFE  PING             Empty payload; keepalive request.
;   0xFF  PONG             Empty payload; keepalive response.
;
;   0xF0  ERROR            UTF-8 diagnostic string describing an application-layer error
;                          (e.g. "upstream-unreachable", "framing-violation").
;
; All other type codes are reserved and MUST be rejected with a 0xF0 ERROR frame
; and connection teardown.
```

Each HTTP transaction **SHOULD** use a dedicated data channel (or a multiplexed stream on a shared data channel where the underlying implementation exposes SCTP streams). Framing is otherwise oblivious to multiplexing: a channel carries one transaction from `REQUEST_HEAD` through `RESPONSE_END`.

### 4.1 Header rules at the daemon

When forwarding a request to the loopback HTTP service, the daemon **MUST**:

- Strip hop-by-hop headers as defined in RFC 7230 §6.1 (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`).
- Strip `X-Forwarded-For`, `Forwarded`, and similar client-supplied provenance headers from the request; the daemon **MAY** set `X-Forwarded-For` to a value derived from the client's pubkey hash if operator configuration permits, but **MUST NOT** pass through an attacker-controlled value.
- Set the `Host` header to the value configured for the target service.
- Reject requests whose framing violates the ABNF above (respond with a 0xF0 ERROR frame and tear down the channel).

## 5. Error handling

A recipient that cannot decode a frame, or that receives a frame type it does not implement, **MUST** send a 0xF0 ERROR frame with a short diagnostic string and then tear down the data channel.

A client that receives an `ERROR` frame **MUST** propagate an HTTP-level 502 Bad Gateway to the application layer and surface the diagnostic string (truncated to a safe length) in a way that does not allow the daemon to inject content into the client UI — i.e., as an inert text blob, not as HTML.

## 6. Test vectors

Test vectors for identity encoding, Pkarr record signing and verification, sealed-box ICE encryption, channel binding, and frame encoding/decoding live in [`test-vectors/`](test-vectors/). These vectors will be populated at the end of M1, and every implementation **MUST** pass all of them to claim conformance.
