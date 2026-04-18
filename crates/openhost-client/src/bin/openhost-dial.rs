//! `openhost-dial` — send a single HTTP request through the openhost
//! protocol and print the response.
//!
//! Usage:
//! ```text
//! openhost-dial oh://<zbase32-pubkey>[/path] \
//!     [-X METHOD] [-H 'Key: Value']... [-d BODY] \
//!     [--relay URL]... [--timeout SECS] [--identity PATH] [--json]
//! ```
//!
//! Gated behind the `cli` feature of `openhost-client`.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use openhost_client::cli::{
    build_request_head, load_identity_from_file, parse_header_arg, parse_response, read_body_arg,
    response_to_json,
};
use openhost_client::{ClientError, Dialer, DialerConfig, OpenhostUrl, SigningKey};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// Send one HTTP request through openhost and print the response.
#[derive(Debug, Parser)]
#[command(
    name = "openhost-dial",
    version,
    about = "Send one HTTP request through openhost and print the response.",
    long_about = None
)]
struct Cli {
    /// The `oh://<zbase32-pubkey>[/path]` URL to dial.
    oh_url: String,

    /// HTTP method. Default `GET`.
    #[arg(short = 'X', long = "method", default_value = "GET")]
    method: String,

    /// Request header. Repeatable. Form: `-H 'Key: Value'` (curl-style).
    #[arg(short = 'H', long = "header")]
    headers: Vec<String>,

    /// Request body. `@path` reads a file, `-` reads stdin, otherwise
    /// the literal argument is used.
    #[arg(short = 'd', long = "data")]
    data: Option<String>,

    /// Override the Pkarr relay list. Repeatable. Defaults to the
    /// bundled list plus the Mainline DHT. HTTPS only.
    #[arg(long = "relay")]
    relays: Vec<String>,

    /// Dial timeout in seconds. Default 30.
    #[arg(long = "timeout", default_value_t = 30u64)]
    timeout_secs: u64,

    /// Load the client's Ed25519 identity (32-byte raw seed) from this
    /// file. If unspecified, generates an ephemeral keypair — useful
    /// for daemons with `enforce_allowlist = false`, but *not* for
    /// hosts that require the client's pubkey on their allowlist.
    #[arg(long = "identity")]
    identity: Option<PathBuf>,

    /// Emit the response as a JSON object to stdout. Status + headers
    /// go to stdout's JSON; no separate stderr output.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if !cli.json {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
            )
            .with_writer(std::io::stderr)
            .try_init();
    }

    // Pre-validate relays before allocating a tokio runtime.
    if let Err(err) = validate_relays(&cli.relays) {
        eprintln!("openhost-dial: {err}");
        return ExitCode::from(2);
    }

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("openhost-dial: failed to build tokio runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let is_usage = err
                .downcast_ref::<ClientError>()
                .map(|ce| matches!(ce, ClientError::UrlParse(_)))
                .unwrap_or(false)
                || err
                    .chain()
                    .any(|e| e.to_string().contains("identity seed at"));
            eprintln!("openhost-dial: {err:#}");
            if is_usage {
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
    // 1. Parse URL + load/generate identity.
    let parsed_url: OpenhostUrl = cli
        .oh_url
        .parse()
        .map_err(ClientError::from)
        .with_context(|| format!("failed to parse oh-url {:?}", cli.oh_url))?;
    let identity = match cli.identity.as_deref() {
        Some(path) => load_identity_from_file(path)?,
        None => SigningKey::generate_os_rng(),
    };
    let client_pk = identity.public_key();

    // 2. Resolve user-supplied headers + body.
    let mut headers: Vec<(String, String)> = Vec::with_capacity(cli.headers.len());
    for raw in &cli.headers {
        headers.push(parse_header_arg(raw)?);
    }
    let body = match cli.data.as_deref() {
        Some(arg) => read_body_arg(arg)?,
        None => bytes::Bytes::new(),
    };
    let method = cli.method.to_ascii_uppercase();
    let path = if parsed_url.path.is_empty() {
        "/".to_string()
    } else {
        parsed_url.path.clone()
    };
    let default_host = format!("{}.openhost", parsed_url.pubkey);
    let head_bytes = build_request_head(&method, &path, &default_host, &headers, body.len());

    // 3. Build the dialer and dial.
    let mut dialer = Dialer::builder()
        .identity(Arc::new(identity))
        .host_url(parsed_url)
        .relays(cli.relays)
        .config(DialerConfig {
            dial_timeout: Duration::from_secs(cli.timeout_secs),
            answer_poll_interval: Duration::from_millis(500),
            webrtc_connect_timeout: Duration::from_secs(cli.timeout_secs.min(30)),
            binding_timeout: Duration::from_secs(10),
        })
        .build()
        .context("failed to build openhost dialer")?;

    if !cli.json {
        eprintln!("openhost-dial: client_pk={client_pk} dialing {method}");
    }

    let session = dialer.dial().await.context("failed to dial host")?;

    // 4. Send the request.
    let response = session
        .request(&head_bytes, body)
        .await
        .context("failed to round-trip request")?;
    let parsed = parse_response(&response).context("failed to parse response head")?;

    // 5. Emit output. Order: close → release WebRTC resources → print.
    session.close().await;
    emit_response(cli.json, &parsed)?;
    Ok(())
}

fn emit_response(json: bool, parsed: &openhost_client::cli::ParsedResponse) -> Result<()> {
    if json {
        let value = response_to_json(parsed);
        let pretty = serde_json::to_string_pretty(&value).expect("JSON encoding always succeeds");
        println!("{pretty}");
    } else {
        eprintln!("{}", parsed.status_line);
        for (k, v) in &parsed.headers {
            eprintln!("{k}: {v}");
        }
        eprintln!();
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(&parsed.body)
            .context("failed to write response body to stdout")?;
        stdout.flush().ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_relays_accepts_https() {
        assert!(validate_relays(&["https://pkarr.pubky.app".to_string()]).is_ok());
        assert!(validate_relays(&[]).is_ok());
    }

    #[test]
    fn validate_relays_rejects_non_https() {
        for case in ["http://x", "ws://x", "x", ""] {
            assert!(validate_relays(&[case.to_string()]).is_err());
        }
    }
}
