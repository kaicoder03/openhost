# openhost-client

Client-side library for resolving openhost host records AND dialing
authenticated WebRTC sessions to them. Consumed by the browser
extension (compiled to WASM), the native apps (via `openhost-ffi`),
and the `openhost-resolve` debug CLI bundled here.

## Dialer (PR #8)

```rust,no_run
use openhost_client::{Dialer, OpenhostUrl, SigningKey};
use bytes::Bytes;
use std::sync::Arc;

# async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
let identity = Arc::new(SigningKey::generate_os_rng());
let url = OpenhostUrl::parse("oh://<52-char-zbase32>/")?;

let mut dialer = Dialer::builder()
    .identity(identity)
    .host_url(url)
    // Defaults to DEFAULT_RELAYS + the Mainline DHT.
    .relays(["https://pkarr.pubky.app"])
    .build()?;

let session = dialer.dial().await?;
let response = session
    .request(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Bytes::new())
    .await?;
println!("{}", std::str::from_utf8(&response.head_bytes)?);
session.close().await;
# Ok(()) }
```

`dial()` resolves the host's Pkarr record, generates + publishes a
sealed offer under the client's own Pkarr zone, polls the host zone
for the answer, completes the RFC 5705 DTLS exporter + RFC 8844
channel binding (spec §7.1), and returns an authenticated
`OpenhostSession` backed by one WebRTC data channel.

**Known constraint.** Today the daemon's answer SDP with full ICE
candidates doesn't fit the BEP44 1000-byte `v` cap when folded into
the daemon's main pkarr packet. The integration test in
`tests/end_to_end.rs` asserts against the daemon's `SharedState`
answer queue rather than the on-wire packet. Splitting ICE trickle
into separate pkarr records is the planned v0.1-freeze fix.

## Read-only resolver

Still exported as-is for callers that only need the host record:

```rust,no_run
use openhost_client::Client;
use std::time::Duration;

# async fn _ex() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::builder()
    .relays(["https://pkarr.pubky.app"])
    .grace_window(Duration::from_millis(1500))
    .build()?;

let record = client
    .resolve_url("oh://<52-char-zbase32>/", None)
    .await?;

println!("DTLS fp: {}", hex::encode(record.record.dtls_fp));
# Ok(()) }
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
