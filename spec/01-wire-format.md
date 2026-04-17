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
- **Public key:** 32 bytes, encoded for display and URLs in [z-base-32](https://philzimmermann.com/docs/human-oriented-base-32-encoding.txt) (no padding). A 32-byte key produces a 52-character z-base-32 string.

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

| Record name | Type | Contents |
|---|---|---|
| `@` | TXT | `v=openhost1; ts=<unix>; fp=sha256:<hex>; roles=server` |
| `_ice._<clienthash>` | TXT | `encrypted:<base64 ciphertext>` — ICE candidates encrypted per-client |
| `_allow` | TXT | `h1=<base64>; h2=<base64>; ...` — hashed client pubkeys |
| `_disc` | TXT | `dht=1; relay=<csv>` — informational list of substrates |

**Constraints:**

- The total signed packet **MUST** fit in 1000 bytes (the BEP44 limit).
- `ts` is the publication time in seconds since the Unix epoch. Clients **MUST** reject records where `|now - ts| > 7200` (two hours).
- `fp` is the SHA-256 fingerprint of the daemon's DTLS certificate, encoded as lowercase hex. The daemon **SHOULD** rotate this certificate daily or on restart.
- Each `<clienthash>` is 16 bytes of HMAC-SHA256 keyed by a per-host salt (published within `@` record as `salt=<hex>`), applied to the client's public key. Unpaired observers see only the existence of ICE records, not which client they belong to.
- The `_allow` record contains the same hashed client keys for the daemon's own dedupe and for clients to verify they are on the allowlist before attempting a connection.
- `_disc` is informational; clients **MUST** try all substrates they know about regardless of the record's contents.

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
  │      nonce    : 32 random bytes                          │
  │      sig_host : Ed25519_sign(host_sk,                    │
  │                              auth_bytes(host_pk,         │
  │                                         client_pk,       │
  │                                         nonce))          │
  │                                                          │
  │    Client → Daemon:                                      │
  │      sig_client : Ed25519_sign(client_sk,                │
  │                                auth_bytes(host_pk,       │
  │                                           client_pk,     │
  │                                           nonce))        │
  │                                                          │
  │    where                                                 │
  │      auth_bytes(h, c, n) =                               │
  │        HKDF-SHA256(                                      │
  │          salt = "openhost-auth-v1",                      │
  │          ikm  = tls_exporter(                            │
  │                   label = "EXPORTER-openhost-auth-v1",   │
  │                   context = h || c || n,                 │
  │                   length = 32),                          │
  │          info = "openhost-auth-v1",                      │
  │          length = 32)                                    │
  │                                                          │
  │    Both parties verify the counterparty's signature.     │
  │    On any failure, the connection MUST be torn down.     │
  │                                                          │
  │ 10. HTTP-over-DataChannel framing begins (§4).           │
```

### 3.1 DTLS role

The daemon **MUST** assert `a=setup:passive` in its SDP. The client **MUST** assert `a=setup:active`. Receivers **MUST** reject SDP that does not match these assignments.

### 3.2 Fingerprint pinning

The `fp` value in the host's Pkarr record pins the expected DTLS certificate fingerprint. A client **MUST** abort the connection if the fingerprint negotiated during the DTLS handshake does not exactly equal `fp`. This prevents unknown-key-share attacks even in the presence of a malicious Pkarr relay (see [`04-security.md`](04-security.md)).

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
