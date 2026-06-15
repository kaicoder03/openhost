//! Authenticated openhost session — one HTTP round-trip per instance
//! for PR #8.
//!
//! After [`crate::dialer::Dialer::dial`] succeeds, you get back an
//! [`OpenhostSession`] holding an open `RTCDataChannel` whose channel
//! binding has already completed. Call [`OpenhostSession::request`]
//! once to send a REQUEST_HEAD + REQUEST_BODY* + REQUEST_END and
//! receive a RESPONSE_HEAD + RESPONSE_BODY* + RESPONSE_END. Call
//! [`OpenhostSession::close`] when done; `Drop` is a safety net.
//!
//! Multi-request-per-session ergonomics are out of scope for PR #8 —
//! the current daemon forward path is also one-request-per-channel
//! (`emit_response` ends with RESPONSE_END and leaves the channel
//! open, but multiplexing multiple outstanding HTTP transactions on
//! one DC is not yet supported end-to-end).

use crate::error::{ClientError, Result};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use openhost_core::wire::{Frame, FrameType, MAX_PAYLOAD_LEN};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::peer_connection::RTCPeerConnection;

/// A response received over the authenticated data channel. Mirrors
/// the daemon-side `ForwardResponse`: raw HTTP/1.1 status line +
/// headers in `head_bytes`, plus the concatenated body.
#[derive(Debug, Clone)]
pub struct ClientResponse {
    /// UTF-8 HTTP/1.1 response head, CRLF-separated, terminated by a
    /// blank line.
    pub head_bytes: Vec<u8>,
    /// Body bytes (may be empty).
    pub body: Bytes,
}

/// Authenticated session over a WebRTC data channel.
pub struct OpenhostSession {
    pc: Arc<RTCPeerConnection>,
    dc: Arc<RTCDataChannel>,
    inbound: SessionInboundReader,
}

impl OpenhostSession {
    /// Constructor used by the dialer.
    pub(crate) fn new(
        pc: Arc<RTCPeerConnection>,
        dc: Arc<RTCDataChannel>,
        inbound: SessionInboundReader,
    ) -> Self {
        Self { pc, dc, inbound }
    }

    /// Issue one HTTP round-trip. `head_bytes` must be a complete
    /// HTTP/1.1 request line + headers terminated by a blank line.
    /// `body` may be empty.
    pub async fn request(&self, head_bytes: &[u8], body: Bytes) -> Result<ClientResponse> {
        // Send REQUEST_HEAD.
        let mut wire: Vec<u8> = Vec::new();
        Frame::new(FrameType::RequestHead, head_bytes.to_vec())
            .map_err(|e| ClientError::HttpRoundTrip(format!("build REQUEST_HEAD: {e}")))?
            .encode(&mut wire);
        // Chunk body into REQUEST_BODY frames at MAX_PAYLOAD_LEN.
        let mut offset = 0;
        while offset < body.len() {
            let end = (offset + MAX_PAYLOAD_LEN).min(body.len());
            let chunk = body.slice(offset..end);
            Frame::new(FrameType::RequestBody, chunk.to_vec())
                .map_err(|e| ClientError::HttpRoundTrip(format!("build REQUEST_BODY: {e}")))?
                .encode(&mut wire);
            offset = end;
        }
        Frame::new(FrameType::RequestEnd, Vec::new())
            .expect("REQUEST_END empty")
            .encode(&mut wire);
        self.dc
            .send(&Bytes::from(wire))
            .await
            .map_err(|e| ClientError::HttpRoundTrip(format!("send: {e}")))?;

        // Read until RESPONSE_END.
        let mut head_bytes_out: Option<Vec<u8>> = None;
        let mut body_out: Vec<u8> = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::HttpRoundTrip(
                    "response did not finish within 30 s".into(),
                ));
            }
            let frame = self.inbound.next_frame(remaining).await?;
            match frame.frame_type {
                FrameType::ResponseHead => {
                    if head_bytes_out.is_some() {
                        return Err(ClientError::HttpRoundTrip(
                            "multiple RESPONSE_HEAD frames".into(),
                        ));
                    }
                    head_bytes_out = Some(frame.payload);
                }
                FrameType::ResponseBody => {
                    if head_bytes_out.is_none() {
                        return Err(ClientError::HttpRoundTrip(
                            "RESPONSE_BODY before RESPONSE_HEAD".into(),
                        ));
                    }
                    body_out.extend_from_slice(&frame.payload);
                }
                FrameType::ResponseEnd => break,
                FrameType::Error => {
                    let msg = String::from_utf8_lossy(&frame.payload).into_owned();
                    return Err(ClientError::HttpRoundTrip(format!(
                        "host emitted ERROR frame: {msg}"
                    )));
                }
                other => {
                    return Err(ClientError::HttpRoundTrip(format!(
                        "unexpected frame type during response: {other:?}"
                    )));
                }
            }
        }

        Ok(ClientResponse {
            head_bytes: head_bytes_out.ok_or_else(|| {
                ClientError::HttpRoundTrip("RESPONSE_END without RESPONSE_HEAD".into())
            })?,
            body: Bytes::from(body_out),
        })
    }

    /// Close the data channel and the peer connection. Always prefer
    /// this over relying on `Drop`.
    pub async fn close(self) {
        let _ = self.dc.close().await;
        let _ = self.pc.close().await;
    }
}

impl Drop for OpenhostSession {
    fn drop(&mut self) {
        // Best-effort: spawn an async close. If the runtime is already
        // shutting down this is a no-op. Callers who care about
        // orderly tear-down should `close().await`.
        let pc = Arc::clone(&self.pc);
        let dc = Arc::clone(&self.dc);
        let _ = tokio::runtime::Handle::try_current().map(|rt| {
            rt.spawn(async move {
                let _ = dc.close().await;
                let _ = pc.close().await;
            })
        });
    }
}

/// Inbound frame reader. Wraps the DC's `on_message` buffer + a
/// `Notify` the reader awaits when it runs out of frames to decode.
pub struct SessionInboundReader {
    buffer: Arc<Mutex<BytesMut>>,
    notify: Arc<Notify>,
}

impl SessionInboundReader {
    /// Install the `on_message` handler on `dc` and return the reader.
    ///
    /// The wake-up uses `Notify::notify_one` — critical for
    /// correctness: if a message lands between `next_frame`'s buffer
    /// check and its `notified().await` call, `notify_one` stores a
    /// permit that the subsequent `notified().await` consumes
    /// immediately. `notify_waiters` (the alternative) would be
    /// lost-wakeup for exactly that race window, and the binding
    /// handshake's first frame is the common case where it fires.
    pub(crate) fn install(dc: &Arc<RTCDataChannel>) -> Self {
        let buffer: Arc<Mutex<BytesMut>> = Arc::new(Mutex::new(BytesMut::new()));
        let notify: Arc<Notify> = Arc::new(Notify::new());
        let buf_for_msg = Arc::clone(&buffer);
        let notify_for_msg = Arc::clone(&notify);
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let buf = Arc::clone(&buf_for_msg);
            let notify = Arc::clone(&notify_for_msg);
            Box::pin(async move {
                buf.lock().await.put_slice(&msg.data);
                notify.notify_one();
            })
        }));
        Self { buffer, notify }
    }

    /// Await the next decodable frame. Returns `HttpRoundTrip` errors
    /// on timeout or malformed bytes.
    pub(crate) async fn next_frame(&self, timeout: Duration) -> Result<Frame> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            // Try to decode whatever's currently buffered.
            {
                let mut buf = self.buffer.lock().await;
                match Frame::try_decode(&buf) {
                    Ok(Some((frame, consumed))) => {
                        buf.advance(consumed);
                        return Ok(frame);
                    }
                    Ok(None) => {
                        // Need more bytes. Drop the lock before awaiting
                        // the notify so the on_message handler can push.
                    }
                    Err(e) => {
                        return Err(ClientError::HttpRoundTrip(format!("malformed frame: {e}")));
                    }
                }
            }
            // Wait for more bytes.
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(ClientError::HttpRoundTrip(format!(
                    "timed out waiting for frame after {timeout:?}"
                )));
            }
            match tokio::time::timeout(remaining, self.notify.notified()).await {
                Ok(()) => continue,
                Err(_) => {
                    return Err(ClientError::HttpRoundTrip(format!(
                        "timed out waiting for frame after {timeout:?}"
                    )));
                }
            }
        }
    }
}
