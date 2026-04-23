//! `oh send` — run an ephemeral openhost daemon that serves one file.
//!
//! Flow:
//! 1. Generate a [`PairingCode`] and derive [`Roles`] (sender /
//!    receiver keys).
//! 2. Write the sender's Ed25519 seed to a mode-0600 tempfile (the
//!    daemon's `FsKeyStore` loads it from there).
//! 3. Spawn a hyper HTTP server on `127.0.0.1:<random>` that streams
//!    the file on `GET /` with `Content-Disposition`,
//!    `Content-Length`, and the sha256 hash.
//! 4. Build a [`Config`] with:
//!    - the sender's ephemeral identity,
//!    - `forward.target = http://127.0.0.1:<port>`,
//!    - `watched_clients = [<receiver_pubkey_zbase32>]`,
//!    - `enforce_allowlist = false` (any peer with the pairing code
//!      can dial).
//! 5. Build + start [`openhost_daemon::App`], print the pairing code
//!    to stderr, and hold the daemon up until either the file
//!    server signals "served OK" (then exit a few seconds later to
//!    flush frames) or the user Ctrl-Cs.

use anyhow::{Context, Result};
use openhost_daemon::config::{
    BindingModeConfig, Config, DtlsConfig, ForwardConfig, IdentityConfig, IdentityStore, LogConfig,
    OfferPollConfig, PairingConfig, PkarrConfig, TurnConfig,
};
use openhost_daemon::App;
use openhost_peer::{PairingCode, Roles};
use std::net::{Ipv4Addr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

/// Default forwarder cap: 1 GiB. `oh send` buffers the upstream
/// response in RAM, so this caps the largest single file we can
/// transfer in one call.
const SEND_MAX_BODY_BYTES: usize = 1024 * 1024 * 1024;

/// Time to linger after the file server reports "served" before we
/// shut the daemon down. Gives the listener a chance to flush the
/// final RESPONSE_END frame over the data channel. Overly generous
/// — the receiver-side shows progress meanwhile.
const POST_SERVE_GRACE: Duration = Duration::from_secs(3);

/// How long to wait for the initial pkarr publish before we print
/// the pairing code. If publishing takes longer the CLI proceeds
/// anyway; the background publisher will keep retrying.
const INITIAL_PUBLISH_WAIT: Duration = Duration::from_secs(5);

/// List of public pkarr relays `oh` uses for rendezvous.
///
/// Order matters for resolution: pkarr's `resolve_most_recent` races
/// every substrate in this list on each `GET`, so every extra relay
/// is extra per-IP rate-limit consumption. We keep the list tight
/// (one, currently) to stay well inside the typical 10 req/min
/// public-relay budget during the O(40)-poll answer wait window.
///
/// The chosen relay must support BEP44 PUT + GET; `relay.pkarr.org`
/// is the community default and is operated by the pkarr team.
///
/// Override with `OH_RELAYS=url1,url2,…` if you need a different
/// mix (self-hosted relay, enterprise deployment, etc.).
/// Discover the primary outbound IPv4 address of this host. Uses
/// the classic "UDP connect-to-nothing" trick: we don't actually
/// send a packet — the OS just picks the interface it would route
/// via 8.8.8.8 and returns that interface's source IP. Works on
/// Mac / Linux / Windows without enumerating interfaces.
///
/// Returns `None` when no routable IPv4 address is available
/// (purely-IPv6 host, offline, etc.).
fn discover_lan_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(v) if !v.is_loopback() => Some(v),
        _ => None,
    }
}

/// Build the sender's embedded TURN relay config. On the sender
/// side ICE host candidates from Chrome arrive as `.local` mDNS
/// hostnames which webrtc-rs doesn't resolve reliably; a LAN-
/// reachable TURN relay gives ICE a guaranteed pair to land on
/// for both same-machine and same-subnet dials.
///
/// Env-var overrides:
/// - `OH_TURN_DISABLE=1` — fall back to the no-TURN behaviour.
/// - `OH_TURN_PUBLIC_IP=<ipv4>` — force the advertised public IP
///   (default: the LAN IP discovered via the outbound-route trick).
/// - `OH_TURN_PUBLIC_PORT=<port>` — force the advertised port
///   (default: the bind port). Set when you've port-forwarded
///   the daemon to a different external port.
fn build_turn_config() -> TurnConfig {
    if std::env::var("OH_TURN_DISABLE").ok().as_deref() == Some("1") {
        return TurnConfig::default();
    }
    let public_ip = std::env::var("OH_TURN_PUBLIC_IP")
        .ok()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .or_else(discover_lan_ipv4);
    let Some(ip) = public_ip else {
        // No LAN IP — stay disabled rather than binding to a
        // useless loopback-only relay.
        return TurnConfig::default();
    };
    let public_port = std::env::var("OH_TURN_PUBLIC_PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());
    TurnConfig {
        enabled: true,
        // Bind an OS-assigned port on all interfaces. The daemon
        // picks the port at start-up and we advertise the same
        // number unless OH_TURN_PUBLIC_PORT overrides it.
        bind_addr: "0.0.0.0:0".to_string(),
        public_ip: Some(ip),
        public_port,
    }
}

pub(crate) fn default_peer_relays() -> Vec<String> {
    if let Ok(s) = std::env::var("OH_RELAYS") {
        let out: Vec<String> = s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !out.is_empty() {
            return out;
        }
    }
    // Match the web app's baked-in relay (`web/recv.html`
    // meta[name=oh-relay]`) so CLI senders and browser receivers
    // publish + read from the same pkarr substrate by default.
    vec!["https://pkarr.pubky.app".to_owned()]
}

/// Run `oh send`. Returns after the transfer completes (server
/// reported "served" + grace period) or after Ctrl-C.
pub async fn run(file: PathBuf) -> Result<()> {
    // Canonicalise + existence-check up front — better to fail
    // before we spawn the daemon if the path is bogus.
    let file = tokio::fs::canonicalize(&file)
        .await
        .with_context(|| format!("file not found: {}", file.display()))?;
    let meta = tokio::fs::metadata(&file).await?;
    if !meta.is_file() {
        anyhow::bail!("{} is not a regular file", file.display());
    }

    let code = PairingCode::generate();
    let roles = Roles::derive(&code);

    // Directory holding the identity seed + DTLS cert lives as long
    // as this command; dropped on exit.
    let state_dir = TempDir::new().context("create ephemeral state dir")?;
    let identity_path = state_dir.path().join("identity.key");
    let cert_path = state_dir.path().join("dtls.pem");
    // Keep the daemon's pair DB inside the ephemeral dir so we do
    // NOT touch the user's real ~/.config/openhost/allow.toml.
    let pair_db_path = state_dir.path().join("allow.toml");

    write_seed(&identity_path, roles.sender_seed()).await?;

    let (server, served_rx) = crate::file_server::FileServer::spawn(&file)
        .await
        .context("spawn local file server")?;

    let receiver_pk_zbase32 = openhost_core::identity::PublicKey::from_bytes(
        &roles.receiver().verifying_key().to_bytes(),
    )
    .expect("Ed25519 verifying keys are always valid PublicKey bytes")
    .to_zbase32();
    let sender_pk_zbase32 =
        openhost_core::identity::PublicKey::from_bytes(&roles.sender().verifying_key().to_bytes())
            .expect("Ed25519 verifying keys are always valid PublicKey bytes")
            .to_zbase32();

    let cfg = build_config(
        &identity_path,
        &cert_path,
        &pair_db_path,
        &receiver_pk_zbase32,
        &server.forward_url(),
    );

    eprintln!(
        "oh send: preparing transfer of {} ({} bytes)",
        file.display(),
        meta.len()
    );
    eprintln!(
        "oh send: sender_pk=oh://{}/  receiver_pk={}",
        sender_pk_zbase32, receiver_pk_zbase32,
    );
    let app = App::build(cfg).await.context("build daemon")?;
    eprintln!(
        "oh send: host published as oh://{}/ (publishing…)",
        sender_pk_zbase32
    );
    // Give the initial publish a moment before we print the pairing
    // code, so the receiver can resolve on its very first attempt.
    tokio::time::sleep(INITIAL_PUBLISH_WAIT).await;

    eprint!("{}", crate::display::format_pairing_code(&code));
    eprintln!("Waiting for the receiver to connect (Ctrl-C to cancel)…");

    tokio::select! {
        res = served_rx => {
            match res {
                Ok(()) => eprintln!("oh send: file served. Flushing…"),
                Err(_) => eprintln!("oh send: server shut down without serving"),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            eprintln!("oh send: Ctrl-C received, shutting down");
        }
    }

    // Give the data channel a few seconds to drain the last frames
    // before we close the peer connection.
    tokio::time::sleep(POST_SERVE_GRACE).await;
    app.shutdown().await;
    // Dropping `state_dir` here wipes the ephemeral key material.
    drop(server);
    Ok(())
}

async fn write_seed(path: &Path, seed: &[u8; 32]) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut f = tokio::fs::File::create(path)
        .await
        .with_context(|| format!("create identity file: {}", path.display()))?;
    f.write_all(seed).await?;
    f.flush().await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(path, perms).await?;
    }
    Ok(())
}

fn build_config(
    identity_path: &Path,
    cert_path: &Path,
    pair_db_path: &Path,
    receiver_pk_zbase32: &str,
    forward_target: &str,
) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: identity_path.to_path_buf(),
            },
        },
        pkarr: PkarrConfig {
            // Publish to a broad relay list so a single flaky or
            // rate-limiting relay doesn't break the rendezvous.
            // These are superset of openhost-pkarr's DEFAULT_RELAYS
            // plus the public pkarr-org relays.
            relays: default_peer_relays(),
            republish_secs: 60,
            offer_poll: OfferPollConfig {
                // 3 s is slow enough to stay inside the public
                // pkarr relays' per-IP rate limits (typically
                // 10 req/min) yet fast enough that the receiver's
                // offer is picked up in ≤ one poll cycle after
                // they run `oh recv`. Each tick fans out across
                // the configured relays, so this is the knob that
                // dominates the sender's RPM.
                poll_secs: 3,
                watched_clients: vec![receiver_pk_zbase32.to_owned()],
                per_client_throttle_secs: 1,
                enforce_allowlist: false,
                rate_limit_burst: 30,
                rate_limit_refill_secs: 0.5,
            },
        },
        dtls: DtlsConfig {
            cert_path: cert_path.to_path_buf(),
            // For a one-shot transfer the rotation interval is
            // meaningless. Set it far out so the daemon never
            // rotates mid-transfer.
            rotate_secs: 30 * 24 * 60 * 60,
            allowed_binding_modes: vec![BindingModeConfig::Exporter, BindingModeConfig::CertFp],
        },
        forward: Some(ForwardConfig {
            target: Some(forward_target.to_owned()),
            host_override: None,
            max_body_bytes: SEND_MAX_BODY_BYTES,
            websockets: None,
        }),
        log: LogConfig::default(),
        // Point the pair DB at our ephemeral state dir so the daemon
        // does NOT touch the user's real ~/.config/openhost/allow.toml.
        // The daemon's auto-watch also adds any pubkeys present in
        // this file to the watched list — our file is empty so only
        // the explicit `watched_clients` entry counts.
        pairing: PairingConfig {
            db_path: Some(pair_db_path.to_path_buf()),
            watch_debounce_ms: 250,
        },
        // TURN enabled on the sender's LAN IP. Chrome's WebRTC
        // emits `<guid>.local` mDNS host candidates that webrtc-rs's
        // resolver doesn't pick up reliably across the pkarr round-
        // trip, so relying on host↔host pairs fails for
        // browser↔CLI dials on the same machine. Putting a TURN
        // server on the LAN IP means both peers always have a
        // guaranteed-reachable `relay` candidate and ICE always
        // finds a working pair — same machine OR same subnet.
        //
        // For cross-internet (browser behind a different NAT),
        // the LAN IP isn't reachable; set OH_TURN_PUBLIC_IP to
        // an externally reachable address + open the UDP port
        // for that scenario. No-op disable (OH_TURN_DISABLE=1)
        // bails out to the prior no-TURN behavior.
        turn: build_turn_config(),
    }
}
