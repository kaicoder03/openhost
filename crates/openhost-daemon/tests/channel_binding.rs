//! Integration tests for the PR #5.5 channel-binding handshake
//! (spec §7.1 / RFC 8844 mitigation).
//!
//! The `support` module shared with `tests/listener.rs` and
//! `tests/forward.rs` has a `BindingMode` enum that can make the test
//! client misbehave in precise ways. These tests exercise the five
//! daemon-side outcomes the state machine promises:
//!
//! 1. Happy path — binding succeeds and the channel accepts REQUEST_*.
//! 2. `REQUEST_HEAD` before `AuthClient` — daemon emits ERROR + tears
//!    down.
//! 3. `AuthClient` with tampered signature — daemon emits ERROR + tears
//!    down.
//! 4. `AuthClient` with client_pk = A but sig signed by B — daemon
//!    emits ERROR + tears down (not just "wrong key", but specifically
//!    "the stated key didn't produce the signature").
//! 5. Client never sends `AuthClient` — daemon times out after
//!    `BINDING_TIMEOUT_SECS` + tears down.
//!
//! All scenarios run on real time. `tokio::time::pause` does not play
//! with webrtc-rs's internal sleeps.

mod support;

use bytes::Bytes;
use openhost_core::wire::{Frame, FrameType};
use openhost_daemon::channel_binding::BINDING_TIMEOUT_SECS;
use openhost_daemon::Result as DaemonResult;
use std::time::Duration;
use support::{
    build_noop_daemon_with_config, establish_connection, establish_connection_opts,
    test_config_noforward, BindingMode, ClientSession, EstablishOpts,
};

/// Wait until the channel is torn down OR a specific frame type arrives.
/// Returns the first frame observed after binding failure (typically
/// ERROR). If nothing arrives before `deadline`, returns `None`.
async fn wait_for_error_or_close(session: &ClientSession, timeout: Duration) -> Option<Frame> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let bytes = session.received.lock().await.clone();
        if let Ok(Some((frame, _))) = Frame::try_decode(&bytes) {
            return Some(frame);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn binding_happy_path_unblocks_request_flow() -> DaemonResult<()> {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let session = establish_connection(&app).await;

    // Binding is already done; a REQUEST_HEAD now produces the stub 502.
    let head = Frame::new(
        FrameType::RequestHead,
        b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
    )
    .unwrap();
    let end = Frame::new(FrameType::RequestEnd, vec![]).unwrap();
    let mut wire = Vec::new();
    head.encode(&mut wire);
    end.encode(&mut wire);
    session.dc.send(&Bytes::from(wire)).await.expect("send");

    let response = wait_for_error_or_close(&session, Duration::from_secs(5))
        .await
        .expect("response head arrives");
    assert_eq!(response.frame_type, FrameType::ResponseHead);
    let head_text = std::str::from_utf8(&response.payload).unwrap();
    assert!(
        head_text.starts_with("HTTP/1.1 502 "),
        "expected 502, got {head_text}"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn request_before_auth_tears_down_channel() -> DaemonResult<()> {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let session = establish_connection_opts(
        &app,
        EstablishOpts {
            binding: BindingMode::SendRequestBeforeBinding,
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("misbehaving client returns Err");

    let frame = wait_for_error_or_close(&session, Duration::from_secs(5))
        .await
        .expect("daemon emits ERROR frame");
    assert_eq!(frame.frame_type, FrameType::Error);
    let diagnostic = String::from_utf8_lossy(&frame.payload);
    assert!(
        diagnostic.to_ascii_lowercase().contains("auth")
            || diagnostic.to_ascii_lowercase().contains("binding"),
        "ERROR diagnostic should mention auth/binding; got {diagnostic:?}"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn invalid_client_sig_tears_down_channel() -> DaemonResult<()> {
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let session = establish_connection_opts(
        &app,
        EstablishOpts {
            binding: BindingMode::TamperSignature,
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("bad signature path returns Err");

    let frame = wait_for_error_or_close(&session, Duration::from_secs(5))
        .await
        .expect("daemon emits ERROR frame");
    assert_eq!(frame.frame_type, FrameType::Error);
    let diagnostic = String::from_utf8_lossy(&frame.payload);
    assert!(
        diagnostic.to_ascii_lowercase().contains("verify")
            || diagnostic.to_ascii_lowercase().contains("signature")
            || diagnostic.to_ascii_lowercase().contains("failed"),
        "ERROR diagnostic should reference the verification failure; got {diagnostic:?}"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn client_pk_mismatch_tears_down_channel() -> DaemonResult<()> {
    // client_pk = A in the payload, but the signature was made by B.
    // The daemon derives auth_bytes with A's public key and verifies
    // with A — that verification will fail because B signed it.
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;

    let session = establish_connection_opts(
        &app,
        EstablishOpts {
            binding: BindingMode::SwapPubkey,
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("mismatched pk path returns Err");

    let frame = wait_for_error_or_close(&session, Duration::from_secs(5))
        .await
        .expect("daemon emits ERROR frame");
    assert_eq!(frame.frame_type, FrameType::Error);

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn binding_timeout_tears_down_channel() -> DaemonResult<()> {
    // Real-time test: the client stays silent after receiving AuthNonce;
    // the daemon must tear down after the configured timeout. We shrink
    // the binding timeout to 1 s via `with_binding_timeout` so this test
    // doesn't burn the default 10 s on every CI run; the default is
    // still exercised implicitly by the production build.
    let tmp = tempfile::TempDir::new().unwrap();
    let cfg = test_config_noforward(&tmp);
    let (_tmp, app) = build_noop_daemon_with_config(cfg).await;
    app.listener().set_binding_timeout(1);
    // Sanity check: the default constant is still the expected value so
    // a future bump shows up in the PR diff, not silently in prod.
    assert_eq!(BINDING_TIMEOUT_SECS, 10);

    let session = establish_connection_opts(
        &app,
        EstablishOpts {
            binding: BindingMode::TimeoutByNeverAuthing,
            ..Default::default()
        },
    )
    .await
    .err()
    .expect("timeout path returns Err");

    let frame = wait_for_error_or_close(&session, Duration::from_secs(5))
        .await
        .expect("daemon emits ERROR frame on timeout");
    assert_eq!(frame.frame_type, FrameType::Error);
    let diagnostic = String::from_utf8_lossy(&frame.payload);
    assert!(
        diagnostic.to_ascii_lowercase().contains("timeout")
            || diagnostic.to_ascii_lowercase().contains("binding"),
        "ERROR diagnostic should mention timeout/binding; got {diagnostic:?}"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}
