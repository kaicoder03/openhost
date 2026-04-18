//! `openhost-resolve` — debug CLI that dumps a host's decoded pkarr record.
//!
//! Usage:
//! ```text
//! openhost-resolve <oh-url> [--relay URL]... [--fast] [--json]
//! ```
//!
//! Gated behind the `cli` feature of `openhost-client` so WASM / FFI
//! consumers of the library don't pull clap, tracing-subscriber, and
//! serde_json transitively.

use clap::Parser;
use openhost_client::{Client, ClientError};
use openhost_core::pkarr_record::SignedRecord;
use serde_json::json;
use std::process::ExitCode;
use std::time::Duration;

/// Resolve an openhost `oh://…` URL and print the decoded host record.
#[derive(Debug, Parser)]
#[command(name = "openhost-resolve", version, about, long_about = None)]
struct Cli {
    /// The `oh://<zbase32-pubkey>[/path]` URL to resolve.
    oh_url: String,

    /// Override the Pkarr relay list. Repeatable. Defaults to the bundled
    /// list plus the Mainline DHT.
    #[arg(long = "relay")]
    relays: Vec<String>,

    /// Skip the 1.5 s grace window (spec §3 rule 5). Use when you care
    /// about latency more than catching a higher-seq straggler.
    #[arg(long)]
    fast: bool,

    /// Emit a JSON object instead of a human-readable block.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Subtle: install a tracing subscriber only when NOT emitting JSON, so
    // `--json` output is machine-parseable without log lines mixed in.
    if !cli.json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_writer(std::io::stderr)
            .try_init();
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("openhost-resolve: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    let result = rt.block_on(run(cli));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Client(ClientError::InvalidUrl(_))) => {
            // Usage-style error — exit 2 by Unix convention.
            ExitCode::from(2)
        }
        Err(err) => {
            eprintln!("openhost-resolve: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), CliError> {
    let grace = if cli.fast {
        Duration::ZERO
    } else {
        openhost_pkarr::GRACE_WINDOW
    };

    let client = Client::builder()
        .relays(cli.relays)
        .grace_window(grace)
        .build()
        .map_err(CliError::Client)?;

    let record = client
        .resolve_url(&cli.oh_url, None)
        .await
        .map_err(CliError::Client)?;

    if cli.json {
        print_json(&record);
    } else {
        print_human(&cli.oh_url, &record);
    }
    Ok(())
}

fn print_human(oh_url: &str, signed: &SignedRecord) {
    let record = &signed.record;
    println!("oh_url:    {oh_url}");
    println!("version:   {}", record.version);
    println!("ts:        {} (unix seconds)", record.ts);
    println!("dtls_fp:   {}", hex::encode(record.dtls_fp));
    println!("roles:     {}", record.roles);
    println!("salt:      {}", hex::encode(record.salt));
    println!("allow:     {} entries", record.allow.len());
    for (i, entry) in record.allow.iter().enumerate() {
        println!("  [{i}] {}", hex::encode(entry));
    }
    println!("ice:       {} blob(s)", record.ice.len());
    for (i, blob) in record.ice.iter().enumerate() {
        println!(
            "  [{i}] client_hash={} ciphertext={} bytes",
            hex::encode(&blob.client_hash),
            blob.ciphertext.len()
        );
    }
    println!(
        "disc:      {}",
        if record.disc.is_empty() {
            "(empty)".to_string()
        } else {
            record.disc.clone()
        }
    );
    println!(
        "signature: {} (64 bytes Ed25519)",
        hex::encode(signed.signature.to_bytes())
    );
}

fn print_json(signed: &SignedRecord) {
    let r = &signed.record;
    let value = json!({
        "version": r.version,
        "ts": r.ts,
        "dtls_fp_hex": hex::encode(r.dtls_fp),
        "roles": r.roles,
        "salt_hex": hex::encode(r.salt),
        "allow_hex": r.allow.iter().map(hex::encode).collect::<Vec<_>>(),
        "ice": r.ice.iter().map(|b| json!({
            "client_hash_hex": hex::encode(&b.client_hash),
            "ciphertext_len": b.ciphertext.len(),
            "ciphertext_hex": hex::encode(&b.ciphertext),
        })).collect::<Vec<_>>(),
        "disc": r.disc,
        "signature_hex": hex::encode(signed.signature.to_bytes()),
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&value).expect("JSON encoding always succeeds")
    );
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error(transparent)]
    Client(openhost_client::ClientError),
}
