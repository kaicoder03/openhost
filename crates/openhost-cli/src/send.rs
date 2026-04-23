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
    vec!["https://relay.pkarr.org".to_owned()]
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
        // TURN disabled: a laptop behind NAT can't usefully run a
        // TURN relay for internet peers (the bind port would need
        // to be reachable from outside). Same-LAN transfers work
        // via ICE host candidates; internet transfers hole-punch
        // via STUN srflx candidates. If both peers are stuck
        // behind symmetric NATs, the receiver's daemon (if it
        // has a public IP, e.g. a cloud VM) is the one that
        // should run TURN.
        turn: TurnConfig::default(),
    }
}
