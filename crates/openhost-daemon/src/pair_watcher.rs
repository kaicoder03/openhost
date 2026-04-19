//! File-system watcher that signals pairing-DB reload events.
//!
//! Wraps `notify-debouncer-mini` and bridges its blocking `std::sync`
//! channel to a tokio `mpsc` receiver the daemon's event loop awaits
//! alongside `shutdown_signal` and `reload_signal`. Each watcher-fired
//! event carries no payload; the consumer re-reads the DB from disk.
//!
//! # What gets watched
//!
//! The watcher targets the pair-DB file's **parent directory** in
//! non-recursive mode and filters events by filename inside the bridge
//! thread. Two reasons:
//!
//! 1. `pairing::save_atomic` writes a `.tmp` sibling, `fsync`s, then
//!    `rename`s it into place — a create+rename sequence at the inode
//!    level. Watching the file directly loses the watch on rename.
//!    Watching the parent catches both the tmp write and the final
//!    name appearance.
//! 2. The pair DB may not exist at daemon startup. Watching a
//!    non-existent file errors immediately on most backends; watching
//!    the parent directory succeeds and fires a `Create` event when the
//!    operator runs `openhostd pair add` for the first time.
//!
//! # Error model
//!
//! The watcher is a best-effort facility. A spawn failure (inotify
//! fd exhaustion, FSEvents permission denial, a missing parent
//! directory) emits a `warn!` at `spawn` time and returns `None`; the
//! daemon keeps running and pairing changes fall back to the SIGHUP
//! path (Unix) or a restart (Windows). Errors after spawn are logged
//! and the thread survives. A panicking bridge thread (unexpected but
//! possible if a downstream `tracing` subscriber fails) is caught and
//! logged via `tracing::error!` before the thread exits, so silent
//! failure of auto-reload is observable in the daemon's log.
//!
//! # Filesystem caveats
//!
//! The underlying `notify` crate uses inotify on Linux, FSEvents on
//! macOS, and ReadDirectoryChangesW on Windows. Events do **not** fire
//! reliably on network filesystems (NFS, SMB, FUSE-backed mounts).
//! Operators who put the pair DB on a remote filesystem should expect
//! the watcher to silently miss events and should either move the DB
//! to a local path or rely on SIGHUP (Unix) / daemon restart (Windows)
//! to apply changes. The initial spawn usually still succeeds on such
//! filesystems, so `warn!`-on-failure is not a substitute for this
//! caveat.

use crate::error::PairWatcherError;
use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode};
use std::path::Path;
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

/// Async-side handle on the file-watcher.
pub struct PairWatcher {
    rx: mpsc::UnboundedReceiver<()>,
    /// Kept alive for the lifetime of the handle; dropping it stops
    /// the debouncer's OS thread and releases inotify/FSEvents FDs.
    _debouncer: notify_debouncer_mini::Debouncer<notify_debouncer_mini::notify::RecommendedWatcher>,
    /// Join handle for the bridge thread — joined on `shutdown` so
    /// shutdown is deterministic.
    join: Option<thread::JoinHandle<()>>,
}

impl PairWatcher {
    /// Spawn a watcher that fires whenever the file at `path` is
    /// created, modified, or removed. `debounce` coalesces bursts
    /// (`pairing::save_atomic`'s `.tmp` write + rename is a two-event
    /// burst). Returns `None` — plus a `warn!` — if the watcher
    /// cannot be set up; the daemon continues without auto-reload.
    pub fn spawn(path: &Path, debounce: Duration) -> Option<Self> {
        match Self::try_spawn(path, debounce) {
            Ok(watcher) => Some(watcher),
            Err(err) => {
                tracing::warn!(
                    path = %path.display(),
                    ?err,
                    "openhostd: pair-DB file watcher could not be started; \
                     falling back to SIGHUP-only reload. Run the daemon \
                     with RUST_LOG=openhost_daemon=debug for detail.",
                );
                None
            }
        }
    }

    fn try_spawn(path: &Path, debounce: Duration) -> std::result::Result<Self, PairWatcherError> {
        let path = path.to_path_buf();
        let parent = path
            .parent()
            .ok_or(PairWatcherError::BadPath("no parent directory"))?
            .to_path_buf();
        let filename = path
            .file_name()
            .ok_or(PairWatcherError::BadPath("no file name"))?
            .to_os_string();

        // Ensure the parent directory exists. `notify::Watcher::watch`
        // returns an opaque backend error otherwise; a typed pre-check
        // here gives operators a clear message.
        if !parent.exists() {
            std::fs::create_dir_all(&parent)?;
        }

        let (sync_tx, sync_rx) = std::sync::mpsc::channel();
        let mut debouncer =
            new_debouncer(debounce, sync_tx).map_err(|e| PairWatcherError::Backend {
                path: parent.clone(),
                source: e,
            })?;
        debouncer
            .watcher()
            .watch(&parent, RecursiveMode::NonRecursive)
            .map_err(|e| PairWatcherError::Backend {
                path: parent.clone(),
                source: e,
            })?;

        let (async_tx, async_rx) = mpsc::unbounded_channel::<()>();
        let target_filename = filename;
        let target_display = path.display().to_string();
        let join = thread::Builder::new()
            .name("openhost-pair-watcher".into())
            .spawn(move || {
                // Catch unwind so a panicking event callback (e.g., a
                // `tracing` subscriber that failed half-way through) is
                // loud rather than silent. Auto-reload stops either way,
                // but an error line in the log is the difference
                // between a bug report and a mystery.
                let path = target_display.clone();
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    Self::bridge(sync_rx, async_tx, &target_filename, &target_display)
                }));
                if let Err(payload) = result {
                    let msg = panic_payload_msg(&payload);
                    tracing::error!(
                        path = %path,
                        panic = %msg,
                        "openhostd: pair-DB watcher bridge thread panicked; auto-reload disabled until daemon restart",
                    );
                }
            })
            .map_err(PairWatcherError::ThreadSpawn)?;

        tracing::info!(
            path = %path.display(),
            debounce_ms = debounce.as_millis() as u64,
            "openhostd: pair-DB file watcher armed",
        );

        Ok(Self {
            rx: async_rx,
            _debouncer: debouncer,
            join: Some(join),
        })
    }

    /// Forward sync-channel events from `notify-debouncer-mini` into
    /// the tokio `mpsc` the event loop awaits. Runs until the sync
    /// channel is closed (which happens when `Debouncer` is dropped
    /// during shutdown).
    fn bridge(
        sync_rx: std::sync::mpsc::Receiver<notify_debouncer_mini::DebounceEventResult>,
        async_tx: mpsc::UnboundedSender<()>,
        target_filename: &std::ffi::OsStr,
        target_display: &str,
    ) {
        while let Ok(result) = sync_rx.recv() {
            let events = match result {
                Ok(e) => e,
                Err(errors) => {
                    // A debouncer `Err` carries one-or-more backend
                    // errors; emit a warn but stay in the loop so a
                    // transient failure (e.g. one inotify queue
                    // overflow) doesn't silently disable auto-reload.
                    tracing::warn!(
                        path = %target_display,
                        ?errors,
                        "openhostd: pair-DB watcher backend error — retrying",
                    );
                    continue;
                }
            };

            let matches_target = events
                .iter()
                .any(|ev| ev.path.file_name() == Some(target_filename));
            if !matches_target {
                continue;
            }

            if async_tx.send(()).is_err() {
                // Receiver dropped → daemon is shutting down.
                break;
            }
        }
    }

    /// Await the next reload-trigger event. Returns `None` only if the
    /// underlying tokio channel closes, which happens during shutdown.
    pub async fn recv(&mut self) -> Option<()> {
        self.rx.recv().await
    }

    /// Stop the watcher. Drops the debouncer (terminating the backend
    /// thread) and joins the bridge thread so no dangling threads
    /// outlive `App::shutdown`.
    pub fn shutdown(mut self) {
        drop(self._debouncer);
        if let Some(join) = self.join.take() {
            // A panicking bridge thread is caught and logged before
            // the thread exits; `join` here just returns `Err(_)` if
            // the panic propagated past the catch, which we still
            // discard — shutdown should not itself panic.
            let _ = join.join();
        }
    }
}

/// Best-effort extraction of a panic payload's `&str` message.
fn panic_payload_msg(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fires_on_write() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allow.toml");
        fs::write(&path, b"pairs = []\n").unwrap();

        let mut watcher =
            PairWatcher::spawn(&path, Duration::from_millis(50)).expect("watcher spawns");

        // Give the backend a moment to start; notify-debouncer-mini's
        // first tick after `watch` is somewhat backend-dependent.
        tokio::time::sleep(Duration::from_millis(100)).await;
        fs::write(&path, b"pairs = [{ pubkey = \"abc\" }]\n").unwrap();

        tokio::time::timeout(Duration::from_secs(2), watcher.recv())
            .await
            .expect("watcher event within 2 s")
            .expect("channel stays open");
        watcher.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fires_on_initial_create() {
        // File does not exist at spawn time. Watcher targets the
        // parent directory; creating the file should fire one event.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allow.toml");

        let mut watcher =
            PairWatcher::spawn(&path, Duration::from_millis(50)).expect("watcher spawns");
        tokio::time::sleep(Duration::from_millis(100)).await;

        fs::write(&path, b"pairs = []\n").unwrap();

        tokio::time::timeout(Duration::from_secs(2), watcher.recv())
            .await
            .expect("watcher event within 2 s")
            .expect("channel stays open");
        watcher.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ignores_siblings_in_parent() {
        // A write to a DIFFERENT file in the same directory must not
        // fire the watcher — we filter by filename in the bridge.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("allow.toml");
        let sibling = tmp.path().join("other.toml");
        fs::write(&path, b"pairs = []\n").unwrap();

        let mut watcher =
            PairWatcher::spawn(&path, Duration::from_millis(50)).expect("watcher spawns");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Drain any start-up events (some backends like FSEvents may fire
        // on the initial watch set-up) so they don't spoil the assertion.
        while tokio::time::timeout(Duration::from_millis(10), watcher.recv())
            .await
            .is_ok()
        {}

        fs::write(&sibling, b"unrelated").unwrap();

        let res = tokio::time::timeout(Duration::from_millis(500), watcher.recv()).await;
        assert!(
            res.is_err(),
            "no event expected for sibling file; got {res:?}",
        );
        watcher.shutdown();
    }
}
