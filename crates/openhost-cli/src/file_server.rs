//! Ephemeral local HTTP server that streams one file.
//!
//! `oh send <path>` spawns this on 127.0.0.1:<random>. The openhost
//! daemon's forwarder reaches it at `http://127.0.0.1:<port>/` for
//! every inbound request; it replies with the file body, the
//! original filename in `Content-Disposition`, the total length in
//! `Content-Length`, and the sha256 in a custom
//! `X-Openhost-File-Sha256` header so the receiver can verify
//! integrity without a round-trip.
//!
//! Any URL other than `GET /` returns 404.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
#[cfg(test)]
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

/// Name we advertise when the caller passes a path without a
/// last-segment filename (e.g. `/`).
const FALLBACK_FILENAME: &str = "openhost-transfer.bin";

/// Custom response header carrying the sha256 of the file body in
/// hex so the receiver can integrity-check the download without a
/// second round-trip.
pub const FILE_SHA256_HEADER: &str = "X-Openhost-File-Sha256";

/// A started file server bound to an OS-assigned port. Keep it alive
/// for the duration of the transfer; its `port()` feeds the
/// daemon's forward target.
pub struct FileServer {
    port: u16,
    /// Oneshot that fires when the file has been fully written out
    /// on any GET /. `None` after the first fire.
    served: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

impl FileServer {
    /// Bind an ephemeral port, load + hash the file, and start
    /// serving `GET /` with the file body. Returns the server
    /// handle plus a receiver that fires once the first successful
    /// GET completes.
    pub async fn spawn(path: &Path) -> Result<(Self, oneshot::Receiver<()>)> {
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("read file: {}", path.display()))?;
        let file_sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            hex::encode(hasher.finalize())
        };
        let filename = path
            .file_name()
            .and_then(|s| s.to_str())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| FALLBACK_FILENAME.to_owned());

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .context("bind ephemeral file-server port")?;
        let port = listener.local_addr()?.port();

        let (served_tx, served_rx) = oneshot::channel::<()>();
        let served_slot: Arc<Mutex<Option<oneshot::Sender<()>>>> =
            Arc::new(Mutex::new(Some(served_tx)));

        tokio::spawn(accept_loop(
            listener,
            Arc::new(FileBlob {
                bytes: Bytes::from(bytes),
                sha256: file_sha256,
                filename,
                path: path.to_path_buf(),
            }),
            served_slot.clone(),
        ));

        Ok((
            Self {
                port,
                served: served_slot,
            },
            served_rx,
        ))
    }

    /// OS-assigned TCP port the server is bound to. Returns
    /// `127.0.0.1:<port>` as the forwarder target URL.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Forwarder target URL, ready to drop into
    /// `openhost_daemon::config::ForwardConfig::target`.
    pub fn forward_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Best-effort tear-down hint — the accept loop exits when this
    /// server and its senders drop, but callers that want to keep
    /// the transferred-signal alive can hold the `Arc` themselves.
    /// No-op if the oneshot already fired.
    pub async fn mark_served_for_test(&self) {
        let mut slot = self.served.lock().await;
        if let Some(tx) = slot.take() {
            let _ = tx.send(());
        }
    }
}

struct FileBlob {
    bytes: Bytes,
    sha256: String,
    filename: String,
    // Retained for logging / debug output.
    #[allow(dead_code)]
    path: PathBuf,
}

async fn accept_loop(
    listener: TcpListener,
    blob: Arc<FileBlob>,
    served: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) {
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(t) => t,
            Err(err) => {
                tracing::warn!(%err, "oh file-server: accept failed");
                break;
            }
        };
        let io = TokioIo::new(stream);
        let blob = blob.clone();
        let served = served.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req| handle(req, blob.clone(), served.clone()));
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                tracing::debug!(%err, "oh file-server: connection closed with error");
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    blob: Arc<FileBlob>,
    served: Arc<Mutex<Option<oneshot::Sender<()>>>>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != Method::GET || req.uri().path() != "/" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found")))
            .expect("static 404 builder is infallible"));
    }
    let resp = build_ok_response(&blob);
    // Notify the main task that a download was served. If the
    // daemon retries on a dropped connection we may enter `handle`
    // again; `take()` ensures exactly-one fire.
    if let Some(tx) = served.lock().await.take() {
        let _ = tx.send(());
    }
    Ok(resp)
}

fn build_ok_response(blob: &FileBlob) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(blob.bytes.clone()));
    let headers: &mut HeaderMap = resp.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&blob.bytes.len().to_string())
            .expect("numeric length is a valid header value"),
    );
    // RFC 6266 filename parameter. We ASCII-sanitise aggressively —
    // the filename is attacker-controlled in principle, and most
    // receivers will sniff Content-Disposition before writing to
    // disk.
    let safe_filename: String = blob
        .filename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    headers.insert(
        http::header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{safe_filename}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    headers.insert(
        FILE_SHA256_HEADER,
        HeaderValue::from_str(&blob.sha256).expect("hex is a valid header value"),
    );
    resp
}

/// Collect a full HTTP response body into `Bytes`. Helper for tests
/// that want to drive the server without exposing hyper internals.
#[cfg(test)]
async fn collect_body(resp: Response<Full<Bytes>>) -> Bytes {
    resp.into_body()
        .collect()
        .await
        .expect("Full never errors")
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn write_temp(payload: &[u8]) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tokio::task::block_in_place(|| tmp.as_file_mut().write_all(payload)).unwrap();
        tmp
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_file_at_root_and_fires_notify() {
        let tmp = write_temp(b"hello world").await;
        let (server, mut served) = FileServer::spawn(tmp.path()).await.unwrap();
        // Hit the server with a raw HTTP/1.1 request.
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port()))
            .await
            .unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert!(buf.windows(11).any(|w| w == b"hello world"));
        // served oneshot fires once the handler runs.
        tokio::time::timeout(std::time::Duration::from_secs(1), &mut served)
            .await
            .expect("served should fire within 1s of the GET")
            .expect("served oneshot should send");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn non_root_returns_404() {
        let tmp = write_temp(b"x").await;
        let (server, _served) = FileServer::spawn(tmp.path()).await.unwrap();
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", server.port()))
            .await
            .unwrap();
        stream
            .write_all(b"GET /elsewhere HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        assert!(buf.starts_with(b"HTTP/1.1 404"));
    }

    #[test]
    fn sanitises_unsafe_filename_chars() {
        let blob = FileBlob {
            bytes: Bytes::from_static(b""),
            sha256: String::from("0"),
            filename: "../etc/passwd; rm -rf /".to_owned(),
            path: PathBuf::new(),
        };
        let resp = build_ok_response(&blob);
        let cd = resp
            .headers()
            .get(http::header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap();
        // Extract just the filename value so the `;` separating
        // `attachment; filename=` doesn't trigger false positives.
        let filename_val = cd
            .split_once("filename=\"")
            .map(|(_, rest)| rest.trim_end_matches('"'))
            .unwrap_or("");
        assert!(!filename_val.contains('/'));
        assert!(!filename_val.contains(';'));
        assert!(!filename_val.contains(' '));
    }

    #[tokio::test]
    async fn ok_response_carries_sha256_header() {
        let blob = FileBlob {
            bytes: Bytes::from_static(b"abc"),
            sha256: String::from(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            filename: "abc.txt".to_owned(),
            path: PathBuf::new(),
        };
        let resp = build_ok_response(&blob);
        let sha = resp.headers().get(FILE_SHA256_HEADER).unwrap();
        assert_eq!(
            sha.to_str().unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        let body = collect_body(resp).await;
        assert_eq!(body.as_ref(), b"abc");
    }
}
