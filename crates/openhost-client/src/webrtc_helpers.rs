//! webrtc-rs glue used by [`crate::dialer::Dialer`].
//!
//! Kept as a narrow `pub(crate)` surface so the Dialer body stays
//! readable.

use std::sync::{Arc, Once};
use tokio::sync::mpsc;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::RTCPeerConnection;

/// Process-global sentinel so the rustls `ring` provider is installed
/// at most once across the entire process. webrtc-dtls + reqwest
/// (transitive via pkarr) both demand a `CryptoProvider`; if neither
/// the daemon nor any other test has already installed one, the
/// client does it here. Subsequent calls observe the `Once` as done.
static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

pub(crate) fn install_crypto_provider_once() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        match rustls::crypto::ring::default_provider().install_default() {
            Ok(()) => tracing::debug!("openhost-client: installed rustls `ring` crypto provider"),
            Err(_existing) => tracing::debug!(
                "openhost-client: rustls CryptoProvider already installed; using existing"
            ),
        }
    });
}

/// Build a client-side `webrtc::API`. Uses the default `SettingEngine`
/// — the client is the offerer and webrtc-rs picks `setup:actpass` for
/// the SDP, which the daemon's pre-check at `check_setup_role_is_active`
/// accepts.
pub(crate) fn build_client_api() -> Arc<API> {
    install_crypto_provider_once();
    let engine = SettingEngine::default();
    Arc::new(APIBuilder::new().with_setting_engine(engine).build())
}

/// Install an `on_peer_connection_state_change` handler that forwards
/// every transition into an `mpsc::Receiver`. The receiver ends when
/// the PC is dropped (the handler's clone of the sender goes with it).
pub(crate) fn state_change_receiver(
    pc: &Arc<RTCPeerConnection>,
) -> mpsc::UnboundedReceiver<RTCPeerConnectionState> {
    let (tx, rx) = mpsc::unbounded_channel();
    pc.on_peer_connection_state_change(Box::new(move |state| {
        let _ = tx.send(state);
        Box::pin(async {})
    }));
    rx
}

/// Install an `on_open` handler that fires a one-shot `Notify` when
/// the data channel becomes open. Uses `notify_one` so a permit is
/// stored if `open` fires before any waiter awaits — the next
/// `notified().await` returns immediately in that case.
pub(crate) fn dc_open_signal(dc: &Arc<RTCDataChannel>) -> Arc<tokio::sync::Notify> {
    let notify = Arc::new(tokio::sync::Notify::new());
    let inner = Arc::clone(&notify);
    dc.on_open(Box::new(move || {
        let inner = Arc::clone(&inner);
        Box::pin(async move {
            inner.notify_one();
        })
    }));
    notify
}
