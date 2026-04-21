---
title: Wire Format
---

# Wire Format

**Status:** Draft (M0).

This document specifies the openhost wire format: identity encoding, the Pkarr record schema, the connection-establishment sequence, and the HTTP-over-DataChannel framing. It is normative for v2 (`openhost2`).

**v1 → v2 schema change (PR #22):** the main `_openhost` record no longer carries `allow` or `ice` fields in its canonical signing bytes. The host's allowlist is now private state (enforced inside the daemon on the offer-poll path); per-client ICE ciphertext will be published as separate records when that path is wired up. The `version` byte in the canonical bytes distinguishes v1 (`0x01`) from v2 (`0x02`) records; decoders **MUST** reject records whose `version` does not match their own implementation.

The 9-byte domain separator `"openhost1"` is retained unchanged in v2 — it acts as an eternal "this is an openhost record" marker rather than a schema selector, which is the `version` byte's job. Future schema bumps (v3, v4, …) will keep `"openhost1"` and advance the `version` byte instead of renaming the prefix, so a decoder that does not recognise the record schema can still confirm it IS an openhost record before rejecting.

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

`canonical_bytes` is the output of [`OpenhostRecord::canonical_signing_bytes`](../crates/openhost-core/src/pkarr_record/mod.rs), a deterministic, domain-separated encoding that carries every semantic field of the record — protocol version, Unix-seconds timestamp `ts`, DTLS fingerprint `dtls_fp`, declared `roles`, per-host allowlist `salt`, and the informational `disc` hints string. Its exact layout is fixed in the openhost-core crate and reproduced verbatim in [`test-vectors/pkarr_record.json`](test-vectors/pkarr_record.json).

The v1 schema additionally carried an `allow` list of 16-byte truncated HMAC entries and a per-paired-client `ice` list immediately before `disc`. v2 removes both fields from the canonical bytes; the underlying facilities they represented now live elsewhere (see the bullet list below).

**v3 schema (PR #42.1).** A v3 record appends one 2-byte big-endian unsigned integer after the `disc` bytes: `turn_port`. A v3 record's `version` byte is `0x03` and `turn_port` **MUST** be non-zero. `turn_port` advertises the UDP port on the daemon's public IP where its embedded TURN server listens; clients read the field and add `turn:<daemon-ip>:<turn_port>` to their ICE configuration before dialling, enabling relay fallback under symmetric NATs that defeat direct hole-punching. Deployments without an embedded TURN server continue to publish v2 records (version byte `0x02`, no trailer); decoders **MUST** accept both. v1 is unsupported.

The base64url encoding uses the RFC 4648 §5 URL-safe alphabet without padding. If the encoded string exceeds 255 bytes, it **MUST** be split across multiple DNS character strings within the same TXT RDATA (per RFC 1035 §3.3.14); decoders reconstruct the payload by concatenating the character strings in the order they appear.

Two signatures bind the record:

- The **inner Ed25519 signature** (the 64-byte signature prefix of the `_openhost` TXT value) covers `canonical_bytes` and is produced by the host's Ed25519 identity key. Verifiers **MUST** re-check this signature against the host's public key before trusting the record.
- The **outer BEP44 signature** on the Pkarr packet itself is also produced by the same Ed25519 identity key — no separate keypair is used — and covers the bencoded DNS packet plus the BEP44 `seq` field. The `seq` field is set to the publication time in seconds since the Unix epoch (equal to `ts` inside the record).

**Constraints:**

- The encoded DNS packet (the BEP44 `v` value) **MUST** fit in 1000 bytes (the BEP44 mutable-item limit).
- `ts` is the publication time in seconds since the Unix epoch. Verifiers **MUST** reject records where `|now - ts| > 7200` (two hours).
- `dtls_fp` is the SHA-256 fingerprint of the daemon's DTLS certificate, 32 raw bytes inside `canonical_bytes`. The daemon **SHOULD** rotate this certificate daily or on restart.
- The host's allowlist (truncated HMAC-SHA256 of paired client pubkeys, keyed by `salt`) is **private state** in v2 — the daemon consults it on the offer-poll path (`is_client_allowed`) but does not publish it. Clients cannot preemptively verify pairing; they discover a mismatch by the absence of a returned answer record.
- Per-client ICE ciphertext, when the feature ships, will be published as separate TXT records alongside the main `_openhost` entry (analogous to `_answer-<client-hash>-<idx>` fragments in §3.3). The sealed-box envelope is still a libsodium `crypto_box_seal` (anonymous X25519 ephemeral sender to the recipient client's X25519 public key, XSalsa20-Poly1305 AEAD); only its location in the packet changes.
- The client's X25519 public key is derived from its Ed25519 identity via the Edwards-to-Montgomery conversion (libsodium's `crypto_sign_ed25519_pk_to_curve25519`), so clients and hosts maintain only one keypair.
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

  body =
    // Choose ONE of the three shapes below based on the leading domain
    // separator. v3 (compact-offer-blob PR) replaces the full SDP with
    // a ~130-byte binary blob so Chrome-generated SDPs (~1100 bytes
    // raw) fit alongside DNS + pkarr overhead under BEP44's 1000-byte
    // packet cap. Symmetric to the v2 answer-blob on the answer side.

    v1 legacy shape (pre-PR-28.3; decode-only):
         "openhost-offer-inner1"      (21 bytes)
       || client_pk                   (32 bytes)
       || sdp_len                     (u32 big-endian)
       || offer_sdp_utf8              (sdp_len bytes)

    v2 legacy shape (PR #28.3 through pre-compact-offer-blob;
                     decode-only in post-rollout daemons/clients):
         "openhost-offer-inner2"      (21 bytes)
       || client_pk                   (32 bytes)
       || sdp_len                     (u32 big-endian)
       || offer_sdp_utf8              (sdp_len bytes)
       || binding_mode                (u8; see §7.6 for semantics)

    v3 shape (compact-offer-blob PR; all new encoders MUST emit this):
         "openhost-offer-inner3"      (21 bytes)
       || client_pk                   (32 bytes)
       || blob_len                    (u16 big-endian; ≤ 512)
       || offer_blob                  (blob_len bytes; structure below)
```

The `offer_blob` carries only the fields the daemon cannot derive
from protocol invariants. The daemon reconstructs a syntactically
complete SDP at consumption time using a fixed template plus these
fields:

```
  offer_blob =
      version         : u8 (0x01)
      flags           : u8
                         bits 0-1: setup_role (0=Active, 1=Passive, 2=Actpass; 3 reserved)
                         bit   2 : binding_mode (0=Exporter, 1=CertFp)
                         bits 3-7: reserved, MUST be 0
      ufrag_len       : u8 (4..=32 per RFC 8445 §5.3)
      ufrag           : <ufrag_len> ASCII bytes
      pwd_len         : u8 (22..=32 per RFC 8445 §5.3)
      pwd             : <pwd_len> ASCII bytes
      client_dtls_fp  : 32 bytes (SHA-256 of client DTLS cert DER)
      cand_count      : u8 (0..=8)
      candidates[]    : cand_count entries of:
                          typ    : u8  (0=host, 1=srflx, 2=prflx, 3=relay)
                          family : u8  (4=IPv4, 6=IPv6)
                          addr   : 4 or 16 bytes
                          port   : u16 big-endian
```

Setup-role `Passive` in an offer is rejected on both encode and
decode — it would flip the DTLS roles against §3.1. IPv4-only is
enforced on the emitter today (mirrors the PR #31 candidate-hygiene
filters on the answer side).

**Binding mode byte (v2) / binding_mode flag bit (v3).** One of:

- `0x01 / bit=0 = Exporter` — client will drive channel binding via
  the RFC 5705 DTLS exporter. The original CLI-to-CLI path.
- `0x02 / bit=1 = CertFp` — client will drive channel binding via
  SHA-256 over the **host's** DTLS certificate DER. Mandatory when
  the client is a browser (browsers do not expose the RFC 5705
  exporter on `RTCDtlsTransport`). See `spec/04-security.md §7.6`.
- v2: other byte values MUST be rejected as malformed.

v1 bodies carry no explicit binding byte and decode as if
`binding_mode = Exporter`. This preserves the pre-PR-28.3
CLI-to-CLI semantics verbatim.

**Client DTLS fingerprint carriage (v3).** Unlike the answer side
(where the host's DTLS fingerprint is pinned under the outer BEP44
signature on the main `_openhost` record), clients have no persistent
pkarr record to pin their fingerprint to. The v3 offer blob therefore
carries a 32-byte `client_dtls_fp` directly. Integrity is provided by
the sealed-box ciphertext to the daemon plus the client's Ed25519
signature on the enclosing BEP44 packet.

v0.1+ encoders **MUST** emit `compression_tag = 0x02`. v0.1+ decoders
**MUST** accept both `0x01` and `0x02` for backward compatibility
with pre-v0.1 blobs. Future codecs can claim new tag values without
invalidating existing implementations.

The inner `client_pk` **MUST** match the outer BEP44 signer pubkey.
The daemon verifies this on decode and rejects a mismatch.

**Offer-poll watch list (operator-facing).** A daemon knows WHICH
clients to poll via two sources, merged as a union at every poll
tick:

1. Explicit config: `pkarr.offer_poll.watched_clients` — zbase32
   pubkey strings.
2. The pair DB (`allow.toml`, managed by `openhostd pair add`/`remove`
   and PR #17's pair-watcher).

Daemons MAY consume either source alone, or both. A client added via
`openhostd pair add <pk>` becomes reachable on the next poll tick
(no config edit, no restart). Pair-DB read errors (missing file,
parse failure, permission denied) degrade gracefully — that tick
contributes no auto-watched pubkeys, the config list still applies.

**Answer (daemon → client).** The daemon publishes answer records as
**extra** TXT entries inside its existing `_openhost` `SignedPacket`.
Each answer is split into one or more **fragments**, each emitted as
its own TXT record at the single-label name

```
_answer-<client-hash-label>-<idx>
```

where `client-hash-label = z_base_32(allowlist_hash(daemon_salt, client_pk))`
— reusing the same HMAC construction `_allow` uses (see §2) — and
`idx` is the 0-based fragment index written as decimal digits (no
leading zeros). Putting answer fragments inside the same packet as
`_openhost` is required because BEP44 permits only one mutable item
per pubkey.

Each TXT value is `base64url_nopad(fragment_envelope)` where
`fragment_envelope` is:

```
  fragment_envelope =
      version        : u8   (0x01)
      chunk_idx      : u8   (0-based; MUST equal the numeric suffix on the DNS label)
      chunk_total    : u8   (1..=255; identical across every fragment of one answer)
      payload_len    : u16  big-endian; ≤ 180
      payload        : payload_len bytes; a slice of the sealed ciphertext
```

Concatenating the `payload` fields of every fragment addressed to one
client (in `chunk_idx` order) yields `sealed_ct`, the libsodium
sealed-box (`crypto_box_seal`) of the answer plaintext below,
addressed to `public_key_to_x25519(client_pk)`.

The answer plaintext carries the same `compression_tag || body`
framing as the offer. Post–compact-answer-blob PR, the daemon emits
the **v2** shape; the v1 shape remains decode-only for clients
resolving legacy daemons during rollout.

**v2 body (`openhost-answer-inner2`, current encoder output):**

```
  body =  "openhost-answer-inner2"   (22 bytes)
       || daemon_pk                   (32 bytes)
       || offer_sdp_hash              (32 bytes, SHA-256 of the UTF-8
                                       offer SDP being answered)
       || blob_len                    (u16 big-endian; ≤ 512)
       || answer_blob                 (blob_len bytes; structure below)
```

The `answer_blob` is:

```
  answer_blob =
      version      : u8   (0x01)
      flags        : u8   (bit 0 = setup_role: 0=active, 1=passive;
                            bits 1..7 reserved, MUST be 0)
      ufrag_len    : u8   (4..=32 per RFC 8445 §5.3)
      ufrag        : ufrag_len bytes, ASCII ice-ufrag
      pwd_len      : u8   (22..=32 per RFC 8445 §5.3)
      pwd          : pwd_len bytes, ASCII ice-pwd
      cand_count   : u8   (0..=8)
      candidates[] : cand_count entries of:
                        typ    : u8  (0=host, 1=srflx, 2=prflx, 3=relay)
                        family : u8  (4=IPv4, 6=IPv6)
                        addr   : 4 or 16 bytes depending on family
                        port   : u16 big-endian
```

Clients reconstruct a complete answer SDP at consumption time from
the blob plus the host's DTLS fingerprint (pinned under the outer
BEP44 signature on the `_openhost` record). A reference
reconstruction template:

```
  v=0
  o=- 1 1 IN IP4 0.0.0.0
  s=-
  t=0 0
  a=group:BUNDLE 0
  m=application 9 UDP/DTLS/SCTP webrtc-datachannel
  c=IN IP4 0.0.0.0
  a=mid:0
  a=rtcp-mux
  a=ice-ufrag:<blob.ufrag>
  a=ice-pwd:<blob.pwd>
  a=fingerprint:sha-256 <colon-hex(record.dtls_fp)>
  a=setup:<active|passive from blob.flags bit 0>
  a=sctp-port:5000
  a=candidate:1 1 udp 1 <addr> <port> typ <host|srflx|prflx|relay> generation 0  (×cand_count)
  a=end-of-candidates
```

The blob does **NOT** duplicate the DTLS fingerprint. Integrity of
the fingerprint is already provided by the outer BEP44 signature
over the main `_openhost` record that carries `dtls_fp`.

**v1 body (`openhost-answer-inner1`, decode-only):**

```
  body =  "openhost-answer-inner1"   (22 bytes)
       || daemon_pk                   (32 bytes)
       || offer_sdp_hash              (32 bytes, SHA-256 of the UTF-8
                                       offer SDP being answered)
       || sdp_len                     (u32 big-endian)
       || answer_sdp_utf8             (sdp_len bytes)
```

Decoders pick v1 vs v2 on the 22-byte domain-separator prefix.
Encoders **MUST** emit v2.

`offer_sdp_hash` binds the answer to a specific offer; a racing
adversary cannot splice a valid answer onto a different offer. The
inner `daemon_pk` **MUST** match the outer BEP44 signer.

TXT TTL for both records is 30 seconds (ephemeral per-handshake).

**Reassembly.** A client looks up `_answer-<client-hash-label>-0`
first. Missing fragment zero ⇒ the daemon has not yet queued an
answer. Otherwise the client reads `chunk_total` from fragment zero
and fetches fragments `1..chunk_total - 1`. It MUST reject the
reassembly as malformed on any of: inconsistent `chunk_total` across
fragments, a fragment whose numeric label suffix disagrees with its
envelope `chunk_idx`, a missing or duplicated index, `chunk_total == 0`,
`chunk_idx >= chunk_total`, or `payload_len > 180`. Only after
successful reassembly does the client run sealed-box open on the
concatenated payload.

**Encoder constraint (whole-answer eviction).** The main `_openhost`
record + every fragment of every answer MUST fit in the BEP44
1000-byte limit. When adding an answer would overflow, the daemon
evicts the whole answer (all of its fragments) — never a single
fragment, which would yield an un-reassemblable partial at the
client. Eviction order is oldest-first by `created_at`. A `warn!` is
logged per eviction so operators notice shedding. The daemon may
further reduce the main record size (e.g., by moving fields it
publishes outside the packet) to leave more room for answers, but
that is an implementation concern rather than a wire-format one.

## 4. HTTP-over-DataChannel framing (ABNF)

Frames on an openhost data channel are binary, length-prefixed, and typed.
Two on-wire shapes are recognised. **Post-PR-#40 encoders MUST emit
v2.** Decoders MUST accept both; the leading byte unambiguously
selects the shape (`0x00` = v2, any valid `FrameType` = v1 legacy).

```text
; ABNF per RFC 5234, with extensions from RFC 7405.

; --- Legacy v1 shape (decode-only post-PR-#40) ---
frame_v1       = type length_le payload
type           = uint8
length_le      = 4 OCTET                ; u32 little-endian
                                         ; 0 <= length <= 2^24-1
payload        = *OCTET                 ; exactly `length` octets

; --- v2 shape (emit + decode) ---
frame_v2       = version type request_id length_be payload
version        = %x00                   ; fixed discriminator
request_id     = 4 OCTET                ; u32 big-endian
length_be      = 4 OCTET                ; u32 big-endian
                                         ; 0 <= length <= 2^24-1

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

**Multiplexing (v2).** The `request_id` field demultiplexes multiple concurrent HTTP transactions over a single data channel. `REQUEST_*` / `RESPONSE_*` / `WS_FRAME` frames carry the id of their owning transaction; session-scoped frames (`AUTH_NONCE` / `AUTH_CLIENT` / `AUTH_HOST`, `PING` / `PONG`, connection-level `ERROR`) carry `request_id = 0`. Peers MAY choose to still use one data channel per transaction (wire-compatible — each channel just uses `request_id = 0` or a stable nonzero id throughout), or run multiple transactions concurrently over one channel. The browser extension's Service Worker proxy (`extension/src/background.js`) takes the latter approach so that loading a single HTML page — which fires many concurrent subresource fetches for CSS, JS, images, and video range requests — only dials one WebRTC session.

**Legacy v1 (pre-PR-#40).** v1 frames carry no `request_id`. Decoders MUST synthesise `request_id = 0` when a v1 frame is received. Emitters MUST NOT produce v1 after PR #40 rollout; the shape is retained only so a post-rollout peer can still consume records (e.g. test fixtures) written by pre-rollout tooling.

### 4.1 Header rules at the daemon

When forwarding a request to the loopback HTTP service, the daemon **MUST**:

- Strip hop-by-hop headers as defined in RFC 7230 §6.1 (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`).
- Strip `X-Forwarded-For`, `Forwarded`, and similar client-supplied provenance headers from the request; the daemon **MAY** set `X-Forwarded-For` to a value derived from the client's pubkey hash if operator configuration permits, but **MUST NOT** pass through an attacker-controlled value.
- Set the `Host` header to the value configured for the target service.
- Reject requests whose framing violates the ABNF above (respond with a 0xF0 ERROR frame and tear down the channel).

### 4.2 WebSocket tunnel

Daemons **MAY** be configured to tunnel RFC 6455 WebSocket upgrades for a finite set of upstream paths. The policy surface is the `[forward.websockets]` TOML section:

```toml
[forward.websockets]
# Exact path matches (byte-identical before any query string) OR the
# single-entry wildcard "*". Omitting this section entirely disables
# WebSocket tunneling — the forwarder rejects every `Upgrade: websocket`
# request, preserving the pre-v0.2 behaviour.
allowed_paths = ["/api/websocket", "/live"]
```

Conformance requirements for the daemon:

- If no `[forward.websockets]` section is configured, **any** `Upgrade: websocket` request **MUST** be rejected at the forwarder boundary (the daemon replies with an application-layer 502 surfaced through the openhost frame codec).
- If a section is configured but `allowed_paths` is empty, the daemon **MUST** reject the configuration at load time.
- If a request's path (stripped of its query string) is not on `allowed_paths`, the request **MUST** be rejected exactly as above.
- The wildcard `"*"` matches every path; operators **SHOULD** enumerate paths explicitly in production.

#### Tunnel protocol (PR #26)

When an allow-listed `Upgrade: websocket` request arrives, the daemon forwards it (preserving `Upgrade`, `Connection`, and every `Sec-WebSocket-*` header) to the upstream and awaits the response:

- **Upstream returns `101 Switching Protocols`.** The daemon emits the 101 head + headers as a `RESPONSE_HEAD` frame so the openhost client can verify `Sec-WebSocket-Accept` using the same RFC 6455 rules it would against any other WS server. The daemon then transitions the data channel into **WebSocket mode**: every inbound `0x21 WS_FRAME` on the DC has its payload copied verbatim to the upstream TCP socket, and every read from the upstream is wrapped in `WS_FRAME` and emitted on the DC. Either side closing terminates both halves.
- **Upstream returns anything else.** The daemon treats it as a failed upgrade and surfaces an application-layer 502 through the normal response path.

Frame types during a WebSocket tunnel:

- `0x21 WS_FRAME` — the only per-direction frame type accepted once the DC is in WebSocket mode. Payload is passthrough bytes; the RFC 6455 framing is opaque to the tunnel.
- `0x30/0x31/0x32 AUTH_*` — already completed before the upgrade; re-arrival is a protocol violation.
- `0xFE/0xFF PING/PONG` — remain valid for keepalive.
- `0xF0 ERROR` — remains valid for teardown.
- Any `REQUEST_*` / `RESPONSE_*` / `0x20 WS_UPGRADE` after a successful 101 is a protocol violation and **MUST** trigger teardown.

Note that `0x20 WS_UPGRADE` is reserved for future use (explicit client-initiated upgrade semantics); in the current implementation the upgrade handshake rides the existing `REQUEST_HEAD` frame.

## 5. Error handling

A recipient that cannot decode a frame, or that receives a frame type it does not implement, **MUST** send a 0xF0 ERROR frame with a short diagnostic string and then tear down the data channel.

A client that receives an `ERROR` frame **MUST** propagate an HTTP-level 502 Bad Gateway to the application layer and surface the diagnostic string (truncated to a safe length) in a way that does not allow the daemon to inject content into the client UI — i.e., as an inert text blob, not as HTML.

## 6. Test vectors

Test vectors for identity encoding, Pkarr record signing and verification, sealed-box ICE encryption, channel binding, and frame encoding/decoding live in [`test-vectors/`](test-vectors/). These vectors will be populated at the end of M1, and every implementation **MUST** pass all of them to claim conformance.
