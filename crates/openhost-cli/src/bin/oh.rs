//! `oh` — openhost peer-to-peer file transfer CLI.
//!
//! Usage:
//! ```text
//! oh send <file>
//! oh recv <code-or-uri> [--out <path>]
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Peer-to-peer file transfer over openhost.
#[derive(Parser, Debug)]
#[command(name = "oh", version, about, long_about = None)]
struct Cli {
    /// Log level filter (RUST_LOG-compatible). Also honors the
    /// RUST_LOG environment variable.
    #[arg(long, default_value = "warn", global = true)]
    log_level: String,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Send a file — prints a pairing code, waits for the receiver
    /// to connect, then transfers.
    Send {
        /// Path to the file to send.
        file: PathBuf,
    },

    /// Receive a file — accepts 12 BIP-39 words or a `oh+pair://`
    /// URI as the pairing code.
    Recv {
        /// Pairing code (12 words) OR a `oh+pair://...` URI. If the
        /// code is multi-word, quote the whole argument.
        code: String,

        /// Where to write the downloaded file. When omitted, the
        /// filename comes from the server's `Content-Disposition`
        /// header (falling back to `openhost-transfer.bin` in the
        /// current directory).
        #[arg(long, short)]
        out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    match cli.cmd {
        Cmd::Send { file } => openhost_cli::send::run(file).await,
        Cmd::Recv { code, out } => {
            if let Some(p) = out.as_ref() {
                openhost_cli::recv::ensure_parent_dir(p).await?;
            }
            openhost_cli::recv::run(&code, out).await
        }
    }
}

fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
