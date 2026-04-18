# openhost-client

Client-side library for reading openhost host records. Consumed by the
browser extension (compiled to WASM), the native apps (via
`openhost-ffi`), and the `openhost-resolve` debug CLI bundled here.

**PR #4 / M4.1 is read-only.** The library resolves an `oh://…` URL to a
validated [`SignedRecord`](../openhost-core/src/pkarr_record/mod.rs) by
racing the configured Pkarr relays + the Mainline DHT. WebRTC offerer,
ICE candidate decryption, and channel binding are PR #8 work.

## Library

```rust
use openhost_client::Client;
use std::time::Duration;

let client = Client::builder()
    // Empty falls back to the bundled default relay list + the Mainline DHT.
    .relays(["https://pkarr.pubky.app"])
    // Duration::ZERO skips the spec §3 rule 5 grace window for snappy dials.
    .grace_window(Duration::from_millis(1500))
    .build()?;

let record = client
    .resolve_url("oh://<52-char-zbase32>/", None)
    .await?;

println!("DTLS fp: {}", hex::encode(record.record.dtls_fp));
```

On the test side, `Client::builder().build_with_resolve(Arc<dyn Resolve>)`
accepts any fake implementing [`openhost_pkarr::Resolve`] so consumers
can drive the full parse + validate + grace-window flow without touching
the network.

## `openhost-resolve` CLI

Behind the `cli` feature:

```bash
cargo run -p openhost-client --features cli --bin openhost-resolve -- <oh-url>
```

Flags:

| Flag | Effect |
|---|---|
| `--relay <URL>` | Override the relay list. Repeatable. |
| `--fast` | Skip the 1.5 s grace window (spec §3 rule 5). |
| `--json` | Emit a machine-readable JSON object instead of the pretty block. |
| `--help` / `--version` | As usual. |

Example against the `openhostd` from PR #2:

```bash
# Start the daemon in one terminal
cargo run -p openhost-daemon -- run --config examples/daemon.toml &

# Resolve it in another (after ~5 s for the first publish to propagate)
PUBKEY=$(cargo run -q -p openhost-daemon -- identity show --config examples/daemon.toml | head -1 | sed 's|oh://||; s|/$||')
cargo run -p openhost-client --features cli --bin openhost-resolve -- "oh://$PUBKEY/"
```

Expected output (roughly):

```
oh_url:    oh://<zbase32>/
version:   1
ts:        1713403200 (unix seconds)
dtls_fp:   6ff9e2f4...
roles:     server
salt:      <32 bytes hex>
allow:     0 entries
ice:       0 blob(s)
disc:      (empty)
signature: <128 hex chars> (64 bytes Ed25519)
```

Exit codes: `0` on success, `2` on URL parse error, `1` on any resolve
error (NotFound, signature invalid, freshness window, etc.).
