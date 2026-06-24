---
title: TURN Credentials and Quota Tokens
---

# TURN Credentials and Quota Tokens

**Status:** Draft (v0.3). This document is normative for TURN-relay fallback behavior in openhost implementations.

TURN is only reached when direct ICE (host + srflx candidates, optionally with STUN help) fails — see [`04-security.md`](04-security.md) §3 row 7.5 and the business-plan target of keeping the relayed-byte ratio ≤ 12%. When TURN is used it MUST remain cryptographically opaque to the relay: the DTLS session between client and daemon is never broken, terminated, or observed by any TURN server.

## 1. Invariants

Every TURN-aware openhost implementation MUST preserve these invariants. They are additions to, not replacements for, the invariants in `04-security.md §1`.

1. **The TURN server never observes plaintext.** The relay sees only ChaCha20-Poly1305-sealed DTLS records. An implementation MUST fail closed rather than downgrade to an unencrypted relay.
2. **TURN credentials are authenticated to a specific subject.** A valid credential identifies *which* Ed25519 pubkey is authorised to use it; a third party intercepting a credential on the wire gains no ability to reuse it against a well-configured relay (coturn `use-auth-secret` + IP pinning).
3. **A TURN credential has an explicit expiry.** Implementations MUST reject credentials whose `expires_at` is in the past or more than `MAX_CREDENTIAL_LIFETIME_SECS` beyond `issued_at`.
4. **A quota token has an explicit window and cap.** An implementation MUST NOT allow relayed traffic to exceed the cap; it MUST be able to prove (via local counters) how many bytes it has relayed within the window.
5. **Credentials and quota tokens are Ed25519-signed by a trusted issuer.** Clients and daemons configure the issuer pubkey out-of-band (daemon config or environment). Unsigned, expired, or mis-signed artifacts MUST be rejected.

## 2. When TURN is used

A TURN server appears in the `ice_servers` list handed to `webrtc-rs`'s `RTCConfiguration` only when one of the following holds:

1. The client has been configured with **static TURN servers** (long-lived, operator-managed coturn accounts) via `[turn.static_servers]` in daemon config or `DialerBuilder::static_turn_servers`.
2. The client has been configured with a **trusted issuer pubkey** and has obtained a fresh, signed `TurnCredential` for its own pubkey from that issuer.

In both cases the TURN entries are *added to*, not substituted for, the STUN entries already present. ICE continues to prefer direct paths; TURN candidates are used only when no direct path is viable.

## 3. `TurnServer`

A `TurnServer` is the concrete `ice_servers` entry fed into the peer connection.

```text
struct TurnServer {
    urls:        Vec<String>   // RFC 7065 URIs, e.g. "turn:relay.example:3478?transport=udp"
    username:    String        // RFC 8489 long-term credential username, ≤ 512 bytes
    credential:  String        // RFC 8489 long-term credential password, ≤ 512 bytes
}
```

The three fields map 1:1 to `webrtc::ice_transport::ice_server::RTCIceServer { urls, username, credential, .. }`.

### 3.1 URL rules

Every URL in `urls` MUST begin with `turn:` or `turns:`. Plain `stun:` URLs are carried by a separate config knob (they have no credential and never participate in quota). `turns:` (TURN-over-TLS) is the recommended transport on networks where UDP 3478 is blocked; implementations MUST NOT reject `turns:` URLs on the grounds that STUN allocation over TLS is slower — the user's network may have no faster path.

## 4. `TurnCredential`

A `TurnCredential` is an issuer-signed bundle naming the subject pubkey, the TURN servers the subject may use, and a tight expiry.

```text
struct TurnCredential {
    subject:     PublicKey      // 32 bytes, Ed25519 — the pubkey authorised to use these servers
    servers:     Vec<TurnServer>
    issued_at:   u64            // Unix seconds
    expires_at:  u64            // Unix seconds, ≥ issued_at, ≤ issued_at + MAX_CREDENTIAL_LIFETIME_SECS
    issuer:      PublicKey      // 32 bytes, Ed25519 — pubkey of the issuer
    signature:   [u8; 64]       // Ed25519 signature by `issuer` over canonical_signing_bytes()
}
```

- `MAX_CREDENTIAL_LIFETIME_SECS = 3_600` (one hour). Issuers typically mint credentials valid for ≤ 300 s; the one-hour ceiling is a hard cap for verifiers.
- A credential with `servers.is_empty()` is invalid; reject with `InvalidTurnCredential("empty server list")`.

### 4.1 Canonical signing bytes

```text
canonical = 0x02                                 // encoding tag for TURN artifacts (distinct from pkarr_record's 0x01)
         || "openhost-turn-credential-v1"        // 27 ASCII bytes, domain separator
         || subject    (32 bytes)
         || issuer     (32 bytes)
         || issued_at  (8 bytes, u64 BE)
         || expires_at (8 bytes, u64 BE)
         || server_count (2 bytes u16 BE)
         || for each server, in list order:
              url_count (1 byte)
              for each URL: url_len (2 bytes u16 BE) || url_bytes
              username_len (2 bytes u16 BE) || username_bytes
              credential_len (2 bytes u16 BE) || credential_bytes
```

Rationale for the layout: length-prefixed and explicit so canonical bytes are stable across any serde representation and across implementations. The domain separator differs from pkarr-record's `"openhost1"` so a signature lifted from one context cannot be replayed into the other.

### 4.2 Verification procedure

Given a `TurnCredential` and the verifier's trusted issuer pubkey set:

1. Reject if `issuer` ∉ trusted set.
2. Reject if `expires_at < now_ts` (expired).
3. Reject if `expires_at > issued_at + MAX_CREDENTIAL_LIFETIME_SECS` (over-long).
4. Reject if `servers.is_empty()`.
5. Reject if any server URL does not begin with `turn:` or `turns:`.
6. Compute `canonical = canonical_signing_bytes(&credential)`; verify `Ed25519.verify(issuer, canonical, signature)` with strict canonicalization.
7. Reject if `subject` does not match the verifier's own pubkey (clients MUST refuse to use a credential issued to someone else).

## 5. `QuotaToken`

A quota token is an issuer-signed assertion of how much relayed traffic a subject pubkey may consume within a fixed window. It is carried alongside (not inside) a `TurnCredential` and is refreshed independently.

```text
struct QuotaToken {
    subject:         PublicKey      // 32 bytes
    window_start:    u64            // Unix seconds, start of the quota window
    window_secs:     u64            // window duration; MUST be ≤ 31 * 86_400
    cap_bytes:       u64            // maximum relayed bytes permitted in the window
    consumed_bytes:  u64            // bytes already relayed at issuance time, ≤ cap_bytes
    issued_at:       u64
    expires_at:      u64            // ≤ issued_at + MAX_QUOTA_TOKEN_LIFETIME_SECS
    issuer:          PublicKey
    signature:       [u8; 64]
}
```

- `MAX_QUOTA_TOKEN_LIFETIME_SECS = 900` (15 minutes). Quota tokens are refreshed frequently so the issuer can adjust `consumed_bytes` as traffic accrues.
- `consumed_bytes` at verification time is a floor, not a ceiling: the client MAY have relayed additional bytes since the token was issued, and is obligated to track them locally. Clients MUST stop relaying new bytes when `local_counter + consumed_bytes ≥ cap_bytes`.

### 5.1 Canonical signing bytes

```text
canonical = 0x02
         || "openhost-turn-quota-v1"              // 22 ASCII bytes
         || subject        (32 bytes)
         || issuer         (32 bytes)
         || window_start   (8 bytes u64 BE)
         || window_secs    (8 bytes u64 BE)
         || cap_bytes      (8 bytes u64 BE)
         || consumed_bytes (8 bytes u64 BE)
         || issued_at      (8 bytes u64 BE)
         || expires_at     (8 bytes u64 BE)
```

### 5.2 Verification procedure

1. Reject if `issuer` ∉ trusted set.
2. Reject if `expires_at < now_ts` or `expires_at > issued_at + MAX_QUOTA_TOKEN_LIFETIME_SECS`.
3. Reject if `consumed_bytes > cap_bytes`.
4. Reject if `window_secs == 0` or `window_secs > 31 * 86_400`.
5. Reject if `subject` ≠ verifier's own pubkey.
6. Verify Ed25519 signature as in §4.2 step 6.

## 6. Relayed-byte accounting

Implementations MUST maintain a per-session atomic counter of bytes relayed through TURN. "Relayed" means "traversed a TURN server as a `send` / `data` indication" — not "sent across the WebRTC data channel" (direct-path bytes are not relayed).

Whether a session's bytes are relayed is determined from the ICE candidate pair actually in use. webrtc-rs exposes this via `RTCPeerConnection::get_stats()`; implementations SHOULD sample the selected candidate pair on `iceconnectionstatechange` and again on session teardown, and MUST count bytes towards the relayed counter only while the selected pair's local candidate type is `relay`.

An implementation that cannot distinguish relayed from direct bytes MUST conservatively count all bytes as relayed when a TURN server is configured — over-counting is safer than under-counting for quota enforcement.

## 7. Transport of credentials and tokens

Credentials and quota tokens are transported as UTF-8 JSON when moving between issuer and subject (HTTPS POST to the issuer's REST endpoint in the production deployment; arbitrary out-of-band transport in self-hosted deployments):

```json
{
  "subject":    "<z-base-32 pubkey, 52 chars>",
  "servers": [
    {
      "urls": ["turn:relay.example:3478?transport=udp"],
      "username": "1700000000:47pjoycn…",
      "credential": "base64-HMAC-SHA1-over-username"
    }
  ],
  "issued_at":  1700000000,
  "expires_at": 1700000300,
  "issuer":     "<z-base-32 pubkey, 52 chars>",
  "signature":  "<base64url-no-pad, 64 bytes raw Ed25519 signature>"
}
```

Pubkeys use z-base-32 (identity.md §1). Signatures use base64url-no-pad (same encoding as the sealed-offer TXT in `03-pkarr-records.md §3.3`). An implementation MUST reject JSON with unknown fields (`deny_unknown_fields`) to keep the signed payload and the parsed payload in lockstep.

## 8. Security considerations

### 8.1 Issuer compromise

Every credential and token is gated on a single issuer pubkey. Compromise of the issuer's signing key lets an attacker mint credentials for any subject. Mitigations:

- **Short-lived credentials** (≤ 1 hour) cap the post-compromise damage window.
- **Ed25519 key pinning** in client and daemon config — an attacker must also compromise the config supply chain to redirect to a new issuer.
- **Issuer key rotation** is a planned follow-up; v0.3 does not specify a rotation envelope. Until rotation ships, operators MUST rotate by pushing a new config pinning a new issuer pubkey and revoking the old one at the trust boundary.

### 8.2 Credential reuse

A stolen credential is reusable against the TURN relay up to `expires_at`. The subject pubkey field is advisory — coturn's long-term credential mechanism has no knowledge of Ed25519. Relay-side defenses:

- **IP pinning** in coturn (`allowed-peer-ip` + issuance-time client-IP lock) closes the steal-and-reuse window in most cases.
- **Per-subject quota tokens** cap the damage a stolen credential can inflict regardless of relay-side pinning.

### 8.3 Quota token replay

A quota token with `consumed_bytes = 0` is more valuable than one with `consumed_bytes = 4_000_000_000` — an attacker who captures a fresh token and keeps it alive beyond `expires_at` would get unbounded free bytes until expiry. Mitigations:

- `MAX_QUOTA_TOKEN_LIFETIME_SECS = 900` bounds the attack window.
- Issuers SHOULD serve tokens over TLS only; an on-path attacker who cannot read TLS cannot replay tokens.

### 8.4 No plaintext observation by the relay

The DTLS session rides *inside* the TURN `ChannelData` or `SEND`/`DATA` indications. coturn sees only ChaCha20-Poly1305 ciphertext. A conformance test in `openhost-core/tests/turn_opacity.rs` MUST assert that a relay-side observer captures no plaintext payload bytes.

### 8.5 TURN-server authentication substrate

This document is deliberately agnostic about whether the `TurnServer::credential` is derived via coturn's `use-auth-secret` REST flow or issued as static long-lived user/password pairs. Both are valid; the choice is an operator decision and is reflected in how the issuer (if any) mints credentials. Clients consume credentials by reference; they do not implement the TURN auth substrate themselves — that work happens on the relay.

## 9. Test vectors

See [`test-vectors/turn_credentials.json`](test-vectors/turn_credentials.json). The fixtures cover:

- A well-formed credential that verifies under its issuer pubkey.
- A well-formed quota token that verifies under its issuer pubkey.
- Negative vectors: expired, over-long-lived, wrong-subject, tampered-server, tampered-signature, unknown issuer.

Every openhost implementation MUST pass the positive vectors and MUST reject every negative vector. Implementations MAY regenerate signatures when the Ed25519 seed is held deterministic, but MUST NOT accept negative vectors after any regeneration.

## 10. Out of scope for v0.3

- **The issuer REST API surface.** The HTTP shape (`POST /v1/turn-credential`, request body, rate-limiting headers) is defined in a follow-up document (`05.1-turn-issuer-api.md`) shipped with the `openhost-turn-issuer` crate.
- **Prometheus exposition format.** `RelayedByteCounter` is the underlying primitive; the Prometheus adapter is a follow-up.
- **Per-session TLS pinning from client to issuer.** TLS via the system trust store is sufficient for v0.3; pinning is a hardening follow-up.
- **Issuer key rotation envelope.** See §8.1.
