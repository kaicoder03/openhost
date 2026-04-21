//! End-to-end integration test for PR #6's localhost forwarder.
//!
//! Spawns a tiny hyper test server, points the daemon at it, drives a
//! real WebRTC handshake + data channel from a client-side
//! `RTCPeerConnection` in the same process, sends `REQUEST_HEAD` +
//! `REQUEST_BODY` + `REQUEST_END` frames, and asserts the upstream's
//! response round-trips through the openhost frame codec.

mod support;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use openhost_core::wire::{Frame, FrameType};
use openhost_daemon::config::{
    Config, DtlsConfig, ForwardConfig, IdentityConfig, IdentityStore, LogConfig, PkarrConfig,
};
use openhost_daemon::{App, Result as DaemonResult};
use openhost_pkarr::Transport;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use support::{establish_connection, ClientSession, NoopTransport};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

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

/// Spawned upstream test server. Captures everything the forwarder
/// sends so tests can assert sanitisation.
#[derive(Clone, Default)]
struct UpstreamState {
    received: Arc<Mutex<UpstreamReceived>>,
    responder: Arc<UpstreamResponder>,
}

#[derive(Default, Debug)]
struct UpstreamReceived {
    method: Option<String>,
    path: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

enum UpstreamResponder {
    Static {
        status: u16,
        content_type: &'static str,
        body: &'static [u8],
    },
    EchoBody,
}

impl Default for UpstreamResponder {
    fn default() -> Self {
        Self::Static {
            status: 200,
            content_type: "text/plain",
            body: b"hello from upstream",
        }
    }
}

/// Spawn the upstream on an ephemeral port and return its port + state.
async fn spawn_upstream(responder: UpstreamResponder) -> (u16, UpstreamState) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();
    let state = UpstreamState {
        received: Arc::new(Mutex::new(UpstreamReceived::default())),
        responder: Arc::new(responder),
    };

    let accept_state = state.clone();
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let conn_state = accept_state.clone();
            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let _ = server_http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                            let state = conn_state.clone();
                            async move {
                                let mut recv = state.received.lock().await;
                                recv.method = Some(req.method().to_string());
                                recv.path = Some(
                                    req.uri()
                                        .path_and_query()
                                        .map(|p| p.to_string())
                                        .unwrap_or_default(),
                                );
                                recv.headers = req
                                    .headers()
                                    .iter()
                                    .map(|(k, v)| {
                                        (
                                            k.as_str().to_lowercase(),
                                            v.to_str().unwrap_or("").to_string(),
                                        )
                                    })
                                    .collect();
                                let collected = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .expect("collect upstream body");
                                recv.body = collected.to_bytes().to_vec();
                                drop(recv);

                                let resp = match &*state.responder {
                                    UpstreamResponder::Static {
                                        status,
                                        content_type,
                                        body,
                                    } => hyper::Response::builder()
                                        .status(*status)
                                        .header("content-type", *content_type)
                                        .body(Full::new(Bytes::from_static(body)))
                                        .unwrap(),
                                    UpstreamResponder::EchoBody => {
                                        let body = state.received.lock().await.body.clone();
                                        hyper::Response::builder()
                                            .status(200)
                                            .header("content-type", "application/octet-stream")
                                            .body(Full::new(Bytes::from(body)))
                                            .unwrap()
                                    }
                                };
                                Ok::<_, Infallible>(resp)
                            }
                        }),
                    )
                    .await;
            });
        }
    });

    (port, state)
}

async fn build_daemon(upstream_port: u16) -> (TempDir, App) {
    let tmp = TempDir::new().unwrap();
    let cfg = test_config(&tmp, upstream_port);
    let app = App::build_with_transport(cfg, Arc::new(NoopTransport) as Arc<dyn Transport>)
        .await
        .expect("daemon builds");
    (tmp, app)
}

/// Send a full request on `session` and collect the full response.
/// Returns (response_head_frame, response_body_bytes).
///
/// Polls `session.received` until a complete `RESPONSE_END` frame is
/// decoded — no fixed-sleep timing assumption. PR #6's listener now
/// sends each response frame as its own data-channel message, so the
/// receiving side must wait for multiple notifications.
async fn round_trip(session: &mut ClientSession, head: &[u8], body: &[u8]) -> (Frame, Vec<u8>) {
    let req_head = Frame::new(FrameType::RequestHead, head.to_vec()).unwrap();
    let mut wire = Vec::new();
    req_head.encode(&mut wire);
    if !body.is_empty() {
        let req_body = Frame::new(FrameType::RequestBody, body.to_vec()).unwrap();
        req_body.encode(&mut wire);
    }
    Frame::new(FrameType::RequestEnd, vec![])
        .unwrap()
        .encode(&mut wire);
    session.dc.send(&Bytes::from(wire)).await.expect("send");

    let (head_frame, body_out) = wait_for_full_response(session).await;
    (head_frame, body_out)
}

/// Wait up to 10s for a full `RESPONSE_HEAD` + `RESPONSE_BODY*` +
/// `RESPONSE_END` sequence to arrive on `session.received`. Returns
/// the head frame and the concatenated body bytes.
async fn wait_for_full_response(session: &mut ClientSession) -> (Frame, Vec<u8>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut head_frame: Option<Frame> = None;
    let mut body_out: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    let mut saw_end = false;

    loop {
        let bytes = session.received.lock().await.clone();
        while offset < bytes.len() {
            match Frame::try_decode(&bytes[offset..]) {
                Ok(Some((frame, used))) => {
                    offset += used;
                    match frame.frame_type {
                        FrameType::ResponseHead => head_frame = Some(frame),
                        FrameType::ResponseBody => body_out.extend_from_slice(&frame.payload),
                        FrameType::ResponseEnd => {
                            saw_end = true;
                            break;
                        }
                        other => panic!("unexpected response frame: {other:?}"),
                    }
                }
                Ok(None) => break, // need more bytes
                Err(e) => panic!("frame decode failed: {e:?}"),
            }
        }
        if saw_end {
            break;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for RESPONSE_END; got head={:?} body_bytes={}",
                head_frame.is_some(),
                body_out.len()
            );
        }
        // Yield — webrtc-rs event loop needs to drain its own tasks.
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    (
        head_frame.expect("RESPONSE_HEAD must arrive before RESPONSE_END"),
        body_out,
    )
}

#[tokio::test]
async fn forwarder_round_trip_returns_upstream_200() -> DaemonResult<()> {
    let (port, _state) = spawn_upstream(UpstreamResponder::default()).await;
    let (_tmp, app) = build_daemon(port).await;
    let mut session = establish_connection(&app).await;

    let head = b"GET /hello HTTP/1.1\r\nHost: some.other.host\r\nAccept: */*\r\n\r\n";
    let (resp_head, body) = round_trip(&mut session, head, b"").await;

    let head_text = std::str::from_utf8(&resp_head.payload).unwrap();
    assert!(
        head_text.starts_with("HTTP/1.1 200 "),
        "expected 200, got head: {head_text}"
    );
    assert!(head_text.to_lowercase().contains("content-length: 19"));
    assert_eq!(body, b"hello from upstream");

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn forwarder_forwards_request_body_verbatim() -> DaemonResult<()> {
    let (port, state) = spawn_upstream(UpstreamResponder::EchoBody).await;
    let (_tmp, app) = build_daemon(port).await;
    let mut session = establish_connection(&app).await;

    let head = b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\n";
    let (resp_head, body) = round_trip(&mut session, head, b"ping\n").await;
    let head_text = std::str::from_utf8(&resp_head.payload).unwrap();
    assert!(head_text.starts_with("HTTP/1.1 200 "));
    assert_eq!(body, b"ping\n");

    let recv = state.received.lock().await;
    assert_eq!(recv.method.as_deref(), Some("POST"));
    assert_eq!(recv.path.as_deref(), Some("/echo"));
    assert_eq!(recv.body, b"ping\n");

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn forwarder_strips_hop_by_hop_and_provenance_before_upstream() -> DaemonResult<()> {
    let (port, state) = spawn_upstream(UpstreamResponder::default()).await;
    let (_tmp, app) = build_daemon(port).await;
    let mut session = establish_connection(&app).await;

    let head = b"GET / HTTP/1.1\r\n\
                 Host: evil.example\r\n\
                 Connection: keep-alive\r\n\
                 Keep-Alive: timeout=5\r\n\
                 TE: trailers\r\n\
                 Trailer: X-Trailer-Smuggled\r\n\
                 Transfer-Encoding: chunked\r\n\
                 X-Forwarded-For: 10.0.0.1\r\n\
                 X-Real-IP: 10.0.0.2\r\n\
                 Forwarded: by=attacker\r\n\
                 X-Custom: retained\r\n\
                 \r\n";
    let _ = round_trip(&mut session, head, b"").await;

    let recv = state.received.lock().await;
    let keys: Vec<&str> = recv.headers.iter().map(|(k, _)| k.as_str()).collect();

    // Every banned header MUST be absent — except `connection`,
    // which the forwarder legitimately re-adds as `close` (opt-out of
    // hyper's connection pool). We verify separately that the
    // CLIENT's `keep-alive` value didn't leak through.
    let banned: &[&str] = &[
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "forwarded",
        "x-real-ip",
    ];
    for bad in banned {
        assert!(
            !keys.contains(bad),
            "banned header {bad:?} leaked through to upstream; saw headers: {keys:?}"
        );
    }
    // Daemon may set Connection: close, but MUST NOT pass through the
    // client's Connection: keep-alive value.
    if let Some((_, value)) = recv.headers.iter().find(|(k, _)| k == "connection") {
        assert_eq!(
            value.to_ascii_lowercase(),
            "close",
            "Connection header was passed through as {value:?}; daemon should only set 'close'"
        );
    }
    // Benign header survives.
    assert!(
        recv.headers
            .iter()
            .any(|(k, v)| k == "x-custom" && v == "retained"),
        "expected X-Custom to pass through; headers: {:?}",
        recv.headers
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn forwarder_pins_host_header_to_target() -> DaemonResult<()> {
    let (port, state) = spawn_upstream(UpstreamResponder::default()).await;
    let (_tmp, app) = build_daemon(port).await;
    let mut session = establish_connection(&app).await;

    let head = b"GET / HTTP/1.1\r\nHost: evil.example:1234\r\n\r\n";
    let _ = round_trip(&mut session, head, b"").await;

    let recv = state.received.lock().await;
    let host = recv
        .headers
        .iter()
        .find(|(k, _)| k == "host")
        .map(|(_, v)| v.clone())
        .expect("upstream saw a Host header");
    assert_eq!(
        host,
        format!("127.0.0.1:{port}"),
        "Host header must be pinned to configured target; got {host}"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn forwarder_upstream_unreachable_returns_502() -> DaemonResult<()> {
    // Bind and immediately drop a listener so we know the port was
    // in use recently but is now closed — connection attempts will be
    // refused by the OS.
    let lst = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = lst.local_addr().unwrap().port();
    drop(lst);

    let (_tmp, app) = build_daemon(dead_port).await;
    let mut session = establish_connection(&app).await;

    let head = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let (resp_head, body) = round_trip(&mut session, head, b"").await;
    let head_text = std::str::from_utf8(&resp_head.payload).unwrap();
    assert!(
        head_text.starts_with("HTTP/1.1 502 "),
        "expected 502 when upstream unreachable, got: {head_text}"
    );
    assert!(body.is_empty(), "502 stub body should be empty");

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn forwarder_request_body_exceeding_cap_triggers_error_frame_and_teardown() -> DaemonResult<()>
{
    // Configure a tiny 256-byte cap so the test doesn't have to allocate
    // megabytes. Any inbound body larger than the cap should trigger a
    // spec §5 ERROR frame + channel teardown — NOT a 502 response.
    let (port, _state) = spawn_upstream(UpstreamResponder::default()).await;
    let tmp = TempDir::new().unwrap();
    let mut cfg = test_config(&tmp, port);
    if let Some(forward) = cfg.forward.as_mut() {
        forward.max_body_bytes = 256;
    }
    let app = App::build_with_transport(cfg, Arc::new(NoopTransport) as Arc<dyn Transport>)
        .await
        .expect("daemon builds");
    let session = establish_connection(&app).await;

    // Send a 1 KiB body — well over the cap.
    let head = b"POST /x HTTP/1.1\r\nHost: x\r\n\r\n";
    let big_body = vec![0x41u8; 1024];
    let req_head = Frame::new(FrameType::RequestHead, head.to_vec()).unwrap();
    let req_body = Frame::new(FrameType::RequestBody, big_body).unwrap();
    let req_end = Frame::new(FrameType::RequestEnd, vec![]).unwrap();
    let mut wire = Vec::new();
    req_head.encode(&mut wire);
    req_body.encode(&mut wire);
    req_end.encode(&mut wire);
    session.dc.send(&Bytes::from(wire)).await.expect("send");

    // Wait up to 5 s for the ERROR frame. The channel will be torn down
    // after so we won't see anything else.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let err_frame = loop {
        let bytes = session.received.lock().await.clone();
        if let Ok(Some((frame, _))) = Frame::try_decode(&bytes) {
            break frame;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "no frame arrived after oversized REQUEST_BODY; received buffer has {} bytes",
                bytes.len()
            );
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(
        err_frame.frame_type,
        FrameType::Error,
        "expected spec §5 ERROR frame, got {:?}",
        err_frame.frame_type
    );
    let diagnostic = String::from_utf8_lossy(&err_frame.payload);
    assert!(
        diagnostic.contains("body"),
        "ERROR diagnostic should mention the body-cap violation; got {diagnostic:?}"
    );

    session.close().await;
    app.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn ping_frame_is_answered_with_pong() -> DaemonResult<()> {
    let (port, _state) = spawn_upstream(UpstreamResponder::default()).await;
    let (_tmp, app) = build_daemon(port).await;
    let session = establish_connection(&app).await;

    let ping = Frame::new(FrameType::Ping, vec![]).unwrap();
    let mut wire = Vec::new();
    ping.encode(&mut wire);
    session.dc.send(&Bytes::from(wire)).await.expect("send");

    // Wait for a Pong frame to arrive on the client side.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let pong = loop {
        let bytes = session.received.lock().await.clone();
        if let Ok(Some((frame, _))) = Frame::try_decode(&bytes) {
            break frame;
        }
        if std::time::Instant::now() >= deadline {
            panic!("daemon did not respond to Ping within 5 s");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(pong.frame_type, FrameType::Pong);
    assert!(pong.payload.is_empty(), "Pong payload MUST be empty");

    session.close().await;
    app.shutdown().await;
    Ok(())
}
