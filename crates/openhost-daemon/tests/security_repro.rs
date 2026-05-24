mod support;

use bytes::Bytes;
use openhost_core::wire::{Frame, FrameType};
use openhost_daemon::config::{
    Config, DtlsConfig, ForwardConfig, IdentityConfig, IdentityStore, LogConfig, PkarrConfig,
};
use openhost_daemon::{App, Result as DaemonResult};
use openhost_pkarr::Transport;
use std::sync::Arc;
use std::time::Duration;
use support::{establish_connection, NoopTransport};
use tempfile::TempDir;
use webrtc::data_channel::RTCDataChannel;

fn test_config(dir: &TempDir, upstream_port: u16) -> Config {
    Config {
        identity: IdentityConfig {
            store: IdentityStore::Fs {
                path: dir.path().join("identity.key"),
            },
        },
        pkarr: PkarrConfig {
            relays: vec![],
            republish_secs: 3600,
            offer_poll: Default::default(),
        },
        dtls: DtlsConfig {
            cert_path: dir.path().join("dtls.pem"),
            rotate_secs: 3600,
            allowed_binding_modes: vec![
                openhost_daemon::config::BindingModeConfig::Exporter,
                openhost_daemon::config::BindingModeConfig::CertFp,
            ],
        },
        forward: Some(ForwardConfig {
            target: Some(format!("http://127.0.0.1:{upstream_port}")),
            host_override: None,
            max_body_bytes: 1024 * 1024,
            websockets: None,
        }),
        log: LogConfig::default(),
        pairing: Default::default(),
        turn: Default::default(),
    }
}

async fn build_daemon(upstream_port: u16) -> (TempDir, App) {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp, upstream_port);
    let app = App::build_with_transport(cfg, Arc::new(NoopTransport) as Arc<dyn Transport>)
        .await
        .expect("daemon builds");
    (tmp, app)
}

async fn send_frame_fragmented(dc: &RTCDataChannel, ty: FrameType, payload: Vec<u8>) {
    let frame = Frame::new(ty, payload).expect("frame constructs");
    let mut out = Vec::new();
    frame.encode(&mut out);

    // Split into 16KB chunks to avoid Sctp(ErrOutboundPacketTooLarge)
    for chunk in out.chunks(16384) {
        dc.send(&Bytes::copy_from_slice(chunk))
            .await
            .expect("send chunk");
    }
}

#[tokio::test]
async fn rejects_whitespace_before_colon_in_header() -> DaemonResult<()> {
    let (_tmp, app) = build_daemon(8080).await;
    let session = establish_connection(&app).await;

    // "Host : localhost" has a space before the colon.
    let head = b"GET / HTTP/1.1\r\nHost : localhost\r\n\r\n";
    send_frame_fragmented(&session.dc, FrameType::RequestHead, head.to_vec()).await;
    send_frame_fragmented(&session.dc, FrameType::RequestEnd, vec![]).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut saw_error = false;
    loop {
        let bytes = session.received.lock().await.clone();
        let mut offset = 0;
        while let Ok(Some((frame, used))) = Frame::try_decode(&bytes[offset..]) {
            offset += used;
            if frame.frame_type == FrameType::Error {
                saw_error = true;
                break;
            }
        }
        if saw_error || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        saw_error,
        "Daemon should have rejected header with whitespace before colon with an ERROR frame"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn rejects_oversized_request_head() -> DaemonResult<()> {
    let (_tmp, app) = build_daemon(8080).await;
    let session = establish_connection(&app).await;

    // Create a ~48KB header.
    let mut head = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..800 {
        head.extend_from_slice(
            format!("X-Long-Header-{:04}: {}\r\n", i, "v".repeat(40)).as_bytes(),
        );
    }
    head.extend_from_slice(b"\r\n");

    assert!(head.len() > 32 * 1024);

    send_frame_fragmented(&session.dc, FrameType::RequestHead, head).await;
    send_frame_fragmented(&session.dc, FrameType::RequestEnd, vec![]).await;

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut saw_error = false;
    loop {
        let bytes = session.received.lock().await.clone();
        let mut offset = 0;
        while let Ok(Some((frame, used))) = Frame::try_decode(&bytes[offset..]) {
            offset += used;
            if frame.frame_type == FrameType::Error {
                saw_error = true;
                break;
            }
        }
        if saw_error || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        saw_error,
        "Daemon should have rejected oversized RequestHead with an ERROR frame"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}
