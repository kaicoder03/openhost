//! Pairing database — the operator's allowlist of authorized clients.
//!
//! Format: TOML at `~/.config/openhost/allow.toml` (overridable via
//! `Config.pairing.db_path`). One `[[pair]]` array entry per paired
//! client. Each entry carries the client's z-base-32 pubkey and an
//! optional human-readable nickname.
//!
//! ```toml
//! [[pair]]
//! pubkey = "yRyanemyt4kh9s51tt51mbe8zf88w73fnoh4q4zz7zs68x6d3a9o"
//! nickname = "my laptop"
//! added_at = 1_700_000_000
//! ```
//!
//! Mutations: `openhostd pair add <pubkey> [--nickname <str>]` /
//! `openhostd pair remove <pubkey>` write the file atomically and then
//! send SIGHUP to the running daemon so it reloads without a restart.
//! Missing file is treated as an empty list, not an error — first-run
//! ergonomics matter.
//!
//! Permissions: 0600 on Unix (same atomic write-tmp-then-rename pattern
//! as `identity_store`). On Windows the file inherits the default ACL
//! from its parent directory.

use openhost_core::crypto::allowlist_hash;
use openhost_core::identity::PublicKey;
use openhost_core::pkarr_record::SALT_LEN;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// One paired client.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairEntry {
    /// z-base-32 Ed25519 pubkey.
    pub pubkey: String,
    /// Operator-chosen nickname. Never leaves the local file; never
    /// enters the published `_openhost` zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    /// Unix seconds when the entry was added. Informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added_at: Option<u64>,
}

/// The on-disk pairing database.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct PairingDb {
    /// Ordered list of paired clients. Order is preservation-only; the
    /// file is rewritten on every mutation so operators can hand-edit.
    #[serde(default, rename = "pair")]
    pub pairs: Vec<PairEntry>,
}

impl PairingDb {
    /// Parsed entries as `(PublicKey, Option<nickname>)`. Invalid
    /// z-base-32 entries are rejected up-front by [`load`]; this method
    /// cannot fail when the DB was produced by [`load`].
    ///
    /// # Panics
    ///
    /// Panics if any `pubkey` fails `PublicKey::from_zbase32`. `load`
    /// enforces the invariant; because `PairingDb` is `Deserialize`,
    /// callers who bypass `load` (e.g. `toml::from_str` directly)
    /// must re-validate before using `parsed` / `compute_hashes`.
    /// `pub(crate)` to keep the panic-boundary narrow.
    #[must_use]
    pub(crate) fn parsed(&self) -> Vec<(PublicKey, Option<String>)> {
        self.pairs
            .iter()
            .map(|p| {
                let pk = PublicKey::from_zbase32(&p.pubkey)
                    .expect("PairingDb invariant: every stored pubkey parses");
                (pk, p.nickname.clone())
            })
            .collect()
    }

    /// Compute the set of `_allow` hashes this DB projects into the
    /// published `_openhost` record under `salt`.
    #[must_use]
    pub fn compute_hashes(&self, salt: &[u8; SALT_LEN]) -> Vec<[u8; 16]> {
        self.parsed()
            .into_iter()
            .map(|(pk, _)| allowlist_hash(salt, &pk.to_bytes()))
            .collect()
    }

    /// Whether the DB contains the given pubkey.
    #[must_use]
    pub fn contains(&self, pk: &PublicKey) -> bool {
        self.pairs.iter().any(|p| {
            PublicKey::from_zbase32(&p.pubkey)
                .map(|k| &k == pk)
                .unwrap_or(false)
        })
    }
}

/// Pairing-DB error surface.
#[derive(Debug, Error)]
pub enum PairingError {
    /// I/O failure reading or writing the DB file.
    #[error("pairing db io error: {0}")]
    Io(#[from] std::io::Error),

    /// TOML parse failure.
    #[error("pairing db parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// TOML serialisation failure. In practice only fires on
    /// implementation bugs; retained for completeness.
    #[error("pairing db serialise error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    /// A stored `pubkey` is not a valid z-base-32 Ed25519 key.
    #[error("pairing db contains invalid pubkey entry: {pubkey:?}")]
    InvalidPubkey {
        /// The offending entry.
        pubkey: String,
    },

    /// Duplicate pubkey in the loaded file.
    #[error("pairing db contains duplicate pubkey: {0}")]
    Duplicate(String),

    /// `add` called for a pubkey that's already present.
    #[error("pubkey already paired: {0}")]
    AlreadyPresent(String),

    /// `remove` called for a pubkey that's not present.
    #[error("pubkey is not paired: {0}")]
    NotPresent(String),
}

/// Load the DB from `path`. A missing file returns `Ok(PairingDb::default())`;
/// a malformed file is a hard error.
pub fn load(path: &Path) -> Result<PairingDb, PairingError> {
    let bytes = match std::fs::read_to_string(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(PairingDb::default()),
        Err(e) => return Err(e.into()),
    };
    let db: PairingDb = toml::from_str(&bytes)?;

    // Validate every entry: z-base-32 parses + no duplicates.
    let mut seen = std::collections::HashSet::new();
    for entry in &db.pairs {
        let pk =
            PublicKey::from_zbase32(&entry.pubkey).map_err(|_| PairingError::InvalidPubkey {
                pubkey: entry.pubkey.clone(),
            })?;
        if !seen.insert(pk.to_bytes()) {
            return Err(PairingError::Duplicate(entry.pubkey.clone()));
        }
    }
    Ok(db)
}

/// Atomically overwrite the DB at `path`. On Unix the final file mode
/// is 0600; on Windows the parent directory's ACL applies.
pub fn save_atomic(path: &Path, db: &PairingDb) -> Result<(), PairingError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let body = toml::to_string_pretty(db)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, body.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
    }

    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Add a new pair entry. Errors on duplicate.
pub fn add(path: &Path, pubkey: &PublicKey, nickname: Option<String>) -> Result<(), PairingError> {
    let mut db = load(path)?;
    if db.contains(pubkey) {
        return Err(PairingError::AlreadyPresent(pubkey.to_zbase32()));
    }
    let added_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok();
    db.pairs.push(PairEntry {
        pubkey: pubkey.to_zbase32(),
        nickname,
        added_at,
    });
    save_atomic(path, &db)
}

/// Remove a pair entry. Errors if the pubkey isn't present.
pub fn remove(path: &Path, pubkey: &PublicKey) -> Result<(), PairingError> {
    let mut db = load(path)?;
    let zb = pubkey.to_zbase32();
    let before = db.pairs.len();
    db.pairs.retain(|p| {
        PublicKey::from_zbase32(&p.pubkey)
            .map(|k| k != *pubkey)
            .unwrap_or(true)
    });
    if db.pairs.len() == before {
        return Err(PairingError::NotPresent(zb));
    }
    save_atomic(path, &db)
}

/// Default DB path: `<config_dir>/openhost/allow.toml`. Matches the
/// convention used by [`crate::config::default_path`].
#[must_use]
pub fn default_db_path() -> PathBuf {
    directories::ProjectDirs::from("", "", "openhost")
        .map(|dirs| dirs.config_dir().join("allow.toml"))
        .unwrap_or_else(|| PathBuf::from("openhost/allow.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openhost_core::identity::SigningKey;
    use tempfile::TempDir;

    fn fresh_pk(seed: u8) -> PublicKey {
        SigningKey::from_bytes(&[seed; 32]).public_key()
    }

    #[test]
    fn load_missing_file_returns_empty_db() {
        let tmp = TempDir::new().unwrap();
        let db = load(&tmp.path().join("nope.toml")).unwrap();
        assert!(db.pairs.is_empty());
    }

    #[test]
    fn add_then_load_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        let pk = fresh_pk(0x11);
        add(&path, &pk, Some("nick".into())).unwrap();
        let db = load(&path).unwrap();
        assert_eq!(db.pairs.len(), 1);
        assert_eq!(db.pairs[0].pubkey, pk.to_zbase32());
        assert_eq!(db.pairs[0].nickname.as_deref(), Some("nick"));
        assert!(db.pairs[0].added_at.is_some());
    }

    #[test]
    fn add_rejects_duplicate() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        let pk = fresh_pk(0x22);
        add(&path, &pk, None).unwrap();
        let err = add(&path, &pk, None).unwrap_err();
        assert!(matches!(err, PairingError::AlreadyPresent(_)));
    }

    #[test]
    fn remove_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        let pk_a = fresh_pk(0x33);
        let pk_b = fresh_pk(0x44);
        add(&path, &pk_a, None).unwrap();
        add(&path, &pk_b, None).unwrap();
        remove(&path, &pk_a).unwrap();
        let db = load(&path).unwrap();
        assert_eq!(db.pairs.len(), 1);
        assert_eq!(db.pairs[0].pubkey, pk_b.to_zbase32());
    }

    #[test]
    fn remove_rejects_missing() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        let pk = fresh_pk(0x55);
        let err = remove(&path, &pk).unwrap_err();
        assert!(matches!(err, PairingError::NotPresent(_)));
    }

    #[test]
    fn load_rejects_invalid_pubkey() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        std::fs::write(&path, "[[pair]]\npubkey = \"not-a-real-pubkey-value\"\n").unwrap();
        let err = load(&path).unwrap_err();
        assert!(matches!(err, PairingError::InvalidPubkey { .. }));
    }

    #[test]
    fn load_rejects_duplicate() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        let pk = fresh_pk(0x66).to_zbase32();
        let body = format!("[[pair]]\npubkey = \"{pk}\"\n[[pair]]\npubkey = \"{pk}\"\n");
        std::fs::write(&path, body).unwrap();
        let err = load(&path).unwrap_err();
        assert!(matches!(err, PairingError::Duplicate(_)));
    }

    #[test]
    fn compute_hashes_matches_allowlist_hash() {
        let salt = [0x11u8; SALT_LEN];
        let pk = fresh_pk(0x77);
        let mut db = PairingDb::default();
        db.pairs.push(PairEntry {
            pubkey: pk.to_zbase32(),
            nickname: None,
            added_at: None,
        });
        let hashes = db.compute_hashes(&salt);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], allowlist_hash(&salt, &pk.to_bytes()));
    }

    #[cfg(unix)]
    #[test]
    fn saved_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("allow.toml");
        add(&path, &fresh_pk(0x88), None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
