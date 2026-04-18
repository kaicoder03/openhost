//! Cross-platform shutdown signal handling.
//!
//! Resolves the returned future when the daemon should begin a graceful
//! shutdown: SIGINT (Ctrl-C) or SIGTERM on Unix, Ctrl-C on Windows.

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
