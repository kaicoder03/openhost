//! Persistence for the host's Ed25519 [`SigningKey`].
//!
//! This PR ships a single backend — [`FsKeyStore`], a plain file on disk
//! at `~/.config/openhost/identity.key` written with mode 0600 on Unix.
//! Keychain-backed backends (macOS Keychain, Linux Secret Service) are
//! deferred to PR #10 and plug in behind the [`KeyStore`] trait.
//!
//! **The filesystem backend is not a fallback; it is first-class and
//! always supported.** Many deployment targets (headless Raspberry Pis,
//! unattended VPSes) have no session D-Bus for Secret Service, and
//! "identity file on disk with 0600" is both well-understood and
//! auditable. Keychain support exists alongside this, not in place of it.

use crate::error::{KeyStoreError, Result as DaemonResult};
use async_trait::async_trait;
use openhost_core::identity::{SigningKey, SIGNING_KEY_LEN};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Crate-local result alias for keystore operations.
pub type Result<T> = core::result::Result<T, KeyStoreError>;

/// Backend for persisting and retrieving the host's identity keypair.
///
/// `load` returns `Ok(None)` when no key is stored yet — the caller then
/// generates one and calls `store`. Mismatched or corrupted state is a
/// hard error, not `Ok(None)`, so typos or truncated writes never cause a
/// silent rotation of the host pubkey.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Read the persisted key if one exists.
    async fn load(&self) -> Result<Option<SigningKey>>;

    /// Overwrite the persisted key with `sk`.
    async fn store(&self, sk: &SigningKey) -> Result<()>;
}

/// Filesystem-backed keystore. The file contains exactly the 32 raw bytes
/// of the Ed25519 seed — no framing, no PEM, no serialisation format
/// overhead. Loading a shorter or longer file is treated as corruption.
///
/// Permissions on Unix are set to 0600 on every write; on Windows the
/// file inherits the default ACL from its parent directory (Windows ACL
/// tightening is out of scope for this PR).
pub struct FsKeyStore {
    path: PathBuf,
}

impl FsKeyStore {
    /// Build a new store pointing at `path`. Nothing is read or written
    /// until [`KeyStore::load`] or [`KeyStore::store`] is called.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file path this store reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl KeyStore for FsKeyStore {
    async fn load(&self) -> Result<Option<SigningKey>> {
        let mut bytes = match tokio::fs::read(&self.path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() != SIGNING_KEY_LEN {
            let got = bytes.len();
            bytes.zeroize();
            return Err(KeyStoreError::WrongSize { got });
        }
        let mut seed = [0u8; SIGNING_KEY_LEN];
        seed.copy_from_slice(&bytes);
        let sk = SigningKey::from_bytes(&seed);

        // Zeroize sensitive material immediately after use.
        bytes.zeroize();
        seed.zeroize();

        Ok(Some(sk))
    }

    async fn store(&self, sk: &SigningKey) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let mut seed = sk.to_bytes();
        let res = write_mode_0600(&self.path, &seed).await;
        // Zeroize sensitive material immediately after writing to disk.
        seed.zeroize();
        res?;
        Ok(())
    }
}

/// Load the persisted key if present; otherwise generate a fresh one via
/// the OS CSPRNG, persist it, and return it. Always returns a valid key.
pub async fn load_or_create(store: &dyn KeyStore) -> DaemonResult<SigningKey> {
    if let Some(sk) = store.load().await? {
        return Ok(sk);
    }
    let sk = SigningKey::generate_os_rng();
    store.store(&sk).await?;
    Ok(sk)
}

/// Writes `bytes` to `path` atomically with mode 0600 on Unix.
///
/// We write to `path.tmp`, chmod, then rename — so a crash mid-write can't
/// leave a partial identity file with permissive bits. The rename is
/// atomic on POSIX; on Windows the final mode is whatever the parent ACL
/// grants.
async fn write_mode_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    tokio::fs::write(&tmp, bytes).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        tokio::fs::set_permissions(&tmp, perms).await?;
    }

    tokio::fs::rename(&tmp, path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn load_or_create_generates_then_reloads() {
        let tmp = TempDir::new().unwrap();
        let store = FsKeyStore::new(tmp.path().join("identity.key"));

        let k1 = load_or_create(&store).await.unwrap();
        let k2 = load_or_create(&store).await.unwrap();
        assert_eq!(
            k1.to_bytes(),
            k2.to_bytes(),
            "reloading must yield the same seed"
        );
        assert_eq!(k1.public_key(), k2.public_key());
    }

    #[tokio::test]
    async fn missing_file_is_ok_none() {
        let tmp = TempDir::new().unwrap();
        let store = FsKeyStore::new(tmp.path().join("absent.key"));
        assert!(store.load().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn wrong_size_file_is_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("identity.key");
        tokio::fs::write(&path, b"not 32 bytes").await.unwrap();
        let store = FsKeyStore::new(path);
        let err = store.load().await.unwrap_err();
        assert!(matches!(err, KeyStoreError::WrongSize { got: 12 }));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stored_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let store = FsKeyStore::new(tmp.path().join("identity.key"));
        let sk = SigningKey::generate_os_rng();
        store.store(&sk).await.unwrap();

        let meta = tokio::fs::metadata(store.path()).await.unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:#o}");
    }

    #[tokio::test]
    async fn store_creates_parent_directory() {
        let tmp = TempDir::new().unwrap();
        let nested = tmp.path().join("a/b/c/identity.key");
        let store = FsKeyStore::new(&nested);
        let sk = SigningKey::generate_os_rng();
        store.store(&sk).await.unwrap();
        assert!(nested.exists());
    }
}
