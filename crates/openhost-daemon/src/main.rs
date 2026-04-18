//! `openhostd` — host-side openhost daemon.
//!
//! Subcommands:
//!
//! - `run` — load identity, generate DTLS cert, publish pkarr record, block.
//! - `identity show` — print the host's `oh://…` URL and z-base-32 pubkey.
//! - `identity rotate` — regenerate the DTLS cert (keeps the Ed25519
//!   identity); prints the new fingerprint.
//!
//! The binary is a thin shim over [`openhost_daemon::App`]. Every side
//! effect lives in the library; `main` owns only argument parsing and the
//! tokio runtime.

use clap::{Parser, Subcommand};
use openhost_daemon::config::{self, Config};
use openhost_daemon::identity_store::{load_or_create, FsKeyStore, KeyStore};
use openhost_daemon::{dtls_cert, init_tracing, App};
use std::path::PathBuf;
use std::process::ExitCode;

/// `openhostd` — the openhost host daemon.
#[derive(Debug, Parser)]
#[command(name = "openhostd", version, about, long_about = None)]
struct Cli {
    /// Path to the config TOML. Defaults to the platform's config dir.
    #[arg(long, short = 'c', global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the daemon and block until SIGINT / SIGTERM.
    Run,

    /// Identity management.
    #[command(subcommand)]
    Identity(IdentityCmd),
}

#[derive(Debug, Subcommand)]
enum IdentityCmd {
    /// Print the `oh://…` URL and z-base-32 public key.
    Show,

    /// Regenerate the DTLS certificate (keeps the Ed25519 identity).
    Rotate,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("openhostd: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = rt.block_on(async move { run(cli).await });

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("openhostd: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let cfg = load_config(&cli).await?;

    match cli.command {
        Command::Run => {
            // Only the long-running subcommand needs structured logs —
            // installing a subscriber for `identity show` / `rotate` would
            // interleave their stdout with any `info!`-level lines an
            // internal dep might emit during identity load.
            init_tracing(&cfg.log.level);
            let app = App::build(cfg).await?;
            app.run().await?;
        }
        Command::Identity(IdentityCmd::Show) => {
            let identity = match &cfg.identity.store {
                config::IdentityStore::Fs { path } => {
                    let store = FsKeyStore::new(path.clone());
                    load_or_create(&store as &dyn KeyStore).await?
                }
            };
            let pubkey = identity.public_key();
            println!("oh://{pubkey}/");
            println!("pubkey_zbase32: {pubkey}");
        }
        Command::Identity(IdentityCmd::Rotate) => {
            let cert = dtls_cert::force_rotate(&cfg.dtls.cert_path).await?;
            println!("dtls_fp: {}", cert.fingerprint_colon_hex());
            eprintln!(
                "openhostd: DTLS cert rotated. Restart the daemon (or trigger a republish) \
                so the new fingerprint lands in the next signed record."
            );
        }
    }

    Ok(())
}

async fn load_config(cli: &Cli) -> anyhow::Result<Config> {
    let path = cli.config.clone().unwrap_or_else(config::default_path);

    if path.exists() {
        Ok(Config::load(&path)?)
    } else {
        // Seed a default config rooted at the parent of the resolved path.
        let data_dir = path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        let cfg = config::seed_config(&data_dir);
        eprintln!(
            "openhostd: no config found at {}; using defaults (identity at {})",
            path.display(),
            match &cfg.identity.store {
                config::IdentityStore::Fs { path } => path.display().to_string(),
            },
        );
        Ok(cfg)
    }
}
