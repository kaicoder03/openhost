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

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use openhost_client::{Client, ClientError};
use openhost_core::pkarr_record::SignedRecord;
use serde_json::{json, Value as JsonValue};
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

    // Install the tracing subscriber only when stdout won't carry JSON —
    // otherwise subscriber output lands on stderr and the stdout object
    // stays pipe-safe for `jq`.
    if !cli.json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_writer(std::io::stderr)
            .try_init();
    }

    // Pre-validate relay URLs before spinning up the tokio runtime.
    // Mirrors the `https://` check config::validate does in
    // openhost-daemon. Exits 2 on bad input per Unix convention.
    if let Err(err) = validate_relays(&cli.relays) {
        eprintln!("openhost-resolve: {err}");
        return ExitCode::from(2);
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

    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // Exit 2 for usage-style errors (URL parse failures); 1 for
            // everything else. Downcasting lets us inspect the inner
            // ClientError without losing anyhow's Context chain.
            let exit = err
                .downcast_ref::<ClientError>()
                .map(|ce| matches!(ce, ClientError::UrlParse(_)))
                .unwrap_or(false);
            eprintln!("openhost-resolve: {err:#}");
            if exit {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn validate_relays(relays: &[String]) -> Result<()> {
    for url in relays {
        if !url.starts_with("https://") {
            return Err(anyhow!(
                "relay URL {url:?} must start with https://; non-HTTPS substrates are not supported"
            ));
        }
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<()> {
    let grace = if cli.fast {
        Duration::ZERO
    } else {
        openhost_pkarr::GRACE_WINDOW
    };

    let client = Client::builder()
        .relays(cli.relays)
        .grace_window(grace)
        .build()
        .context("failed to build openhost client")?;

    let record = client
        .resolve_url(&cli.oh_url, None)
        .await
        .context("failed to resolve record")?;

    if cli.json {
        let value = record_to_json(&record);
        println!(
            "{}",
            serde_json::to_string_pretty(&value).expect("JSON encoding always succeeds")
        );
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

/// Serialize a [`SignedRecord`] into the JSON shape `--json` emits.
/// Extracted so the schema can be unit-tested without spawning a
/// subprocess. v2 records dropped `allow_hex` and `ice` keys (PR #22);
/// scripts that consumed them need updating.
fn record_to_json(signed: &SignedRecord) -> JsonValue {
    let r = &signed.record;
    json!({
        "version": r.version,
        "ts": r.ts,
        "dtls_fp_hex": hex::encode(r.dtls_fp),
        "roles": r.roles,
        "salt_hex": hex::encode(r.salt),
        "disc": r.disc,
        "signature_hex": hex::encode(signed.signature.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::identity::SigningKey;
    use openhost_core::pkarr_record::{
        OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
    };

    const RFC_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn sample_signed() -> SignedRecord {
        let sk = SigningKey::from_bytes(&RFC_SEED);
        let record = OpenhostRecord {
            version: PROTOCOL_VERSION,
            ts: 1_700_000_000,
            dtls_fp: [0x42u8; DTLS_FINGERPRINT_LEN],
            roles: "server".to_string(),
            salt: [0x11u8; SALT_LEN],
            disc: "dht=1".to_string(),
            turn_port: None,
        };
        SignedRecord::sign(record, &sk).expect("sign")
    }

    #[test]
    fn json_output_has_stable_keys_and_shape() {
        // Every field name + type below is part of the CLI's public
        // contract — piping `--json` into downstream scripts breaks if
        // these change silently. The v2 shape (PR #22) dropped the
        // `allow_hex` and `ice` keys; any script that consumed them
        // needs updating.
        let value = record_to_json(&sample_signed());
        let obj = value.as_object().expect("top-level is an object");

        for key in &[
            "version",
            "ts",
            "dtls_fp_hex",
            "roles",
            "salt_hex",
            "disc",
            "signature_hex",
        ] {
            assert!(obj.contains_key(*key), "missing top-level key {key:?}");
        }

        assert!(
            !obj.contains_key("allow_hex"),
            "v2 CLI output must not carry allow_hex",
        );
        assert!(
            !obj.contains_key("ice"),
            "v2 CLI output must not carry an `ice` array",
        );

        assert_eq!(obj["version"], 2);
        assert_eq!(obj["ts"], 1_700_000_000);
        assert_eq!(obj["roles"], "server");
        assert_eq!(obj["disc"], "dht=1");
        assert_eq!(obj["dtls_fp_hex"].as_str().unwrap().len(), 64); // 32 bytes hex
        assert_eq!(obj["signature_hex"].as_str().unwrap().len(), 128); // 64 bytes hex
    }

    #[test]
    fn validate_relays_accepts_https() {
        assert!(validate_relays(&["https://pkarr.pubky.app".to_string()]).is_ok());
        assert!(validate_relays(&[]).is_ok());
    }

    #[test]
    fn validate_relays_rejects_non_https() {
        let cases = [
            "http://pkarr.example",
            "ws://pkarr.example",
            "pkarr.example",
            "",
        ];
        for case in cases {
            let err = validate_relays(&[case.to_string()]).unwrap_err();
            assert!(
                format!("{err}").contains("https://"),
                "unexpected error for {case:?}: {err}"
            );
        }
    }
}
