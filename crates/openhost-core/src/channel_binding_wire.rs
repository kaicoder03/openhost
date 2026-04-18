//! Wire-level constants for the channel-binding handshake (spec §7.1,
//! PR #5.5).
//!
//! The crypto primitives live in [`crate::crypto::channel_binding`] —
//! `auth_bytes`, `auth_bytes_bound`, `exporter_context`,
//! `AUTH_CONTEXT_LABEL`. This module holds the *wire-format* constants
//! (nonce length, payload lengths, DTLS exporter label as a `&str`,
//! default timeout) so both `openhost-daemon`'s host-side
//! [`ChannelBinder`] and `openhost-client`'s client-side binder can
//! import from one source of truth.
//!
//! [`ChannelBinder`]: ../../openhost_daemon/channel_binding/struct.ChannelBinder.html

/// Length of the daemon-chosen channel-binding nonce (spec §7.1).
pub const AUTH_NONCE_LEN: usize = 32;

/// Wire length of the `AuthClient` frame payload: 32-byte `client_pk` ||
/// 64-byte `sig_client`.
pub const AUTH_CLIENT_PAYLOAD_LEN: usize = 32 + 64;

/// Wire length of the `AuthHost` frame payload: 64-byte `sig_host`.
pub const AUTH_HOST_PAYLOAD_LEN: usize = 64;

/// Length of the RFC 5705 exporter secret openhost derives.
pub const EXPORTER_SECRET_LEN: usize = 32;

/// Exporter label openhost requests from the DTLS transport.
///
/// Held as a `&str` because webrtc-rs's exporter API is string-typed.
/// The byte contents MUST match [`crate::crypto::AUTH_CONTEXT_LABEL`];
/// a unit test pins the equality so drift is caught in CI.
pub const EXPORTER_LABEL: &str = "EXPORTER-openhost-auth-v1";

/// Default time budget for the channel-binding handshake. Past this
/// deadline the data channel is torn down (spec §7.1, "binding MUST
/// complete promptly").
pub const BINDING_TIMEOUT_SECS: u64 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exporter_label_matches_core_auth_context() {
        assert_eq!(
            EXPORTER_LABEL.as_bytes(),
            crate::crypto::AUTH_CONTEXT_LABEL,
            "wire-level EXPORTER_LABEL bytes must match the core AUTH_CONTEXT_LABEL constant",
        );
    }
}
