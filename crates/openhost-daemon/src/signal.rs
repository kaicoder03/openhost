//! Cross-platform shutdown + reload signal handling.
//!
//! `shutdown_signal` resolves on SIGINT/SIGTERM (Unix) or Ctrl-C
//! (Windows). `reload_signal` resolves on SIGHUP (Unix) and never
//! resolves on Windows — which matches the daemon's Windows posture:
//! pairing changes require a daemon restart there.

/// Await a shutdown signal. Returns as soon as one lands.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("register SIGINT handler");
        let mut sigterm = signal(SignalKind::terminate()).expect("register SIGTERM handler");
        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(windows)]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Await a reload signal (SIGHUP on Unix). On Windows the returned
/// future never resolves — pairing-DB changes require a daemon restart.
/// Callers typically drive this in a loop with `shutdown_signal` in a
/// `tokio::select!`.
pub async fn reload_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = signal(SignalKind::hangup()).expect("register SIGHUP handler");
        let _ = sighup.recv().await;
    }

    #[cfg(windows)]
    {
        std::future::pending::<()>().await;
    }
}
