//! `openhostd` configuration (TOML-backed).
//!
//! The binary loads a single [`Config`] at startup; every other module
//! consumes immutable slices of it. Fields that later PRs will need are
//! already spelled out in the schema so ops docs and sample files don't
//! churn when those PRs land.

use crate::error::{ConfigError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default republish interval (seconds) written into a freshly-generated
/// config file. Matches `openhost-pkarr::REPUBLISH_INTERVAL`.
pub const DEFAULT_REPUBLISH_SECS: u64 = 30 * 60;

/// Default DTLS cert rotation interval. One day per `spec/01-wire-format.md §2`.
pub const DEFAULT_ROTATE_SECS: u64 = 24 * 60 * 60;

/// Top-level `openhostd` configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Where the Ed25519 identity lives.
    pub identity: IdentityConfig,
    /// Pkarr publisher configuration.
    pub pkarr: PkarrConfig,
    /// DTLS certificate configuration.
    pub dtls: DtlsConfig,
    /// Localhost-forward configuration. Reserved for PR #6; unused in this
    /// release but present in the schema to stabilise the surface.
    #[serde(default)]
    pub forward: Option<ForwardConfig>,
    /// Logging.
    #[serde(default)]
    pub log: LogConfig,
}

/// Identity keystore configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Which keystore backend to use.
    pub store: IdentityStore,
}

/// Supported identity backends. Only filesystem-backed storage ships in
/// this PR; keychain is a PR #10 follow-up.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdentityStore {
    /// Plain file at `path`, stored with mode 0600 on Unix.
    Fs {
        /// Absolute or `~/...`-style path to the identity file.
        path: PathBuf,
    },
}

/// Pkarr publisher configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PkarrConfig {
    /// HTTPS relay URLs the daemon publishes to. Empty falls back to the
    /// bundled list in `openhost_pkarr::DEFAULT_RELAYS`.
    #[serde(default)]
    pub relays: Vec<String>,

    /// Seconds between scheduled republishes. Defaults to
    /// [`DEFAULT_REPUBLISH_SECS`].
    #[serde(default = "default_republish_secs")]
    pub republish_secs: u64,
}

/// DTLS certificate configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DtlsConfig {
    /// Where the PEM bundle (private key + self-signed cert) lives on disk.
    pub cert_path: PathBuf,
    /// Seconds between rotations. Defaults to [`DEFAULT_ROTATE_SECS`].
    #[serde(default = "default_rotate_secs")]
    pub rotate_secs: u64,
}

/// Reserved — wired up in PR #6.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    /// Upstream target, e.g. `http://127.0.0.1:8080`.
    #[serde(default)]
    pub target: Option<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Log level filter, e.g. `"info"`, `"openhost_daemon=debug,info"`.
    /// Honours the `RUST_LOG` environment variable at runtime.
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

fn default_republish_secs() -> u64 {
    DEFAULT_REPUBLISH_SECS
}

fn default_rotate_secs() -> u64 {
    DEFAULT_ROTATE_SECS
}

impl Config {
    /// Load and validate a TOML config file.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let cfg: Config = toml::from_str(&bytes).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Per-field sanity checks. Called by [`Config::load`]; exposed for
    /// unit tests that build a [`Config`] in memory.
    pub fn validate(&self) -> Result<()> {
        if self.pkarr.republish_secs == 0 {
            return Err(ConfigError::Invalid("pkarr.republish_secs must be > 0").into());
        }
        if self.dtls.rotate_secs == 0 {
            return Err(ConfigError::Invalid("dtls.rotate_secs must be > 0").into());
        }
        for url in &self.pkarr.relays {
            if !url.starts_with("https://") {
                return Err(ConfigError::InvalidRelayUrl { url: url.clone() }.into());
            }
        }
        Ok(())
    }

    /// Republish interval as a `Duration`.
    pub fn republish_interval(&self) -> Duration {
        Duration::from_secs(self.pkarr.republish_secs)
    }

    /// Rotation interval as a `Duration`.
    pub fn rotate_interval(&self) -> Duration {
        Duration::from_secs(self.dtls.rotate_secs)
    }
}

/// Canonical path for the config file — `~/.config/openhost/config.toml`
/// on Linux; the platform equivalent on macOS / Windows. Intended for
/// the CLI's default when `--config` is omitted.
///
/// The empty qualifier + empty organisation in [`directories::ProjectDirs`]
/// is an explicit choice: openhost has no backing company / TLD / reverse-DNS
/// identifier, so a bare `"openhost"` top-level directory on every platform
/// keeps paths predictable and greppable. This is a **stable** convention —
/// changing it silently orphans every user's existing identity + cert files,
/// so treat it as a protocol-visible value and bump a major version before
/// touching.
pub fn default_path() -> PathBuf {
    directories::ProjectDirs::from("", "", "openhost")
        .map(|dirs| dirs.config_dir().join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("openhost/config.toml"))
}

/// Default content for a freshly-seeded `config.toml`. Useful for the
/// `identity show` / `identity rotate` subcommands when the user hasn't
/// written one yet.
pub fn seed_config(data_dir: &Path) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: data_dir.join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: Vec::new(),
            republish_secs: DEFAULT_REPUBLISH_SECS,
        },
        dtls: DtlsConfig {
            cert_path: data_dir.join("dtls.pem"),
            rotate_secs: DEFAULT_ROTATE_SECS,
        },
        forward: None,
        log: LogConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_toml(dir: &TempDir, body: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn loads_minimal_valid_config() {
        let tmp = TempDir::new().unwrap();
        let body = r#"
            [identity]
            store = { kind = "fs", path = "/tmp/id.key" }

            [pkarr]
            relays = ["https://pkarr.pubky.app"]

            [dtls]
            cert_path = "/tmp/dtls.pem"
        "#;
        let path = write_toml(&tmp, body);
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.pkarr.relays.len(), 1);
        assert_eq!(cfg.pkarr.republish_secs, DEFAULT_REPUBLISH_SECS);
        assert_eq!(cfg.dtls.rotate_secs, DEFAULT_ROTATE_SECS);
        assert_eq!(cfg.log.level, "info");
    }

    #[test]
    fn rejects_unknown_fields() {
        let tmp = TempDir::new().unwrap();
        let body = r#"
            [identity]
            store = { kind = "fs", path = "/tmp/id.key" }

            [pkarr]
            relays = []
            unexpected = true

            [dtls]
            cert_path = "/tmp/dtls.pem"
        "#;
        let path = write_toml(&tmp, body);
        let err = Config::load(&path).unwrap_err();
        assert!(
            format!("{err}").contains("unexpected"),
            "expected parse error to mention the unknown field, got: {err}"
        );
    }

    #[test]
    fn rejects_non_https_relay() {
        let tmp = TempDir::new().unwrap();
        let body = r#"
            [identity]
            store = { kind = "fs", path = "/tmp/id.key" }

            [pkarr]
            relays = ["http://insecure.example"]

            [dtls]
            cert_path = "/tmp/dtls.pem"
        "#;
        let path = write_toml(&tmp, body);
        let err = Config::load(&path).unwrap_err();
        assert!(format!("{err}").contains("https://"));
    }

    #[test]
    fn rejects_zero_intervals() {
        let mut cfg = seed_config(Path::new("/tmp"));
        cfg.pkarr.republish_secs = 0;
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("republish_secs"));

        let mut cfg = seed_config(Path::new("/tmp"));
        cfg.dtls.rotate_secs = 0;
        let err = cfg.validate().unwrap_err();
        assert!(format!("{err}").contains("rotate_secs"));
    }

    #[test]
    fn seed_config_round_trips_through_toml() {
        let cfg = seed_config(Path::new("/tmp/openhost"));
        let serialised = toml::to_string(&cfg).unwrap();
        let parsed: Config = toml::from_str(&serialised).unwrap();
        parsed.validate().unwrap();
    }

    #[test]
    fn default_path_is_noncommittal() {
        // Just make sure the function returns *something* plausible on every
        // platform; the exact path is OS-dependent.
        let path = default_path();
        assert!(path.to_string_lossy().contains("openhost"));
    }
}
