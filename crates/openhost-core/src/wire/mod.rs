//! HTTP-over-DataChannel framing as specified in `spec/01-wire-format.md` §4.
//!
//! Two on-wire layouts are recognised:
//!
//! ```text
//! frame_v1 = type (1 byte) | length (4 bytes LE) | payload (N bytes)    -- legacy (decode only)
//! frame_v2 = 0x00 | type (1 byte) | request_id (4 bytes BE) | length (4 bytes BE) | payload
//! ```
//!
//! `frame_v1` is the pre-PR-#40 single-stream layout: one HTTP transaction
//! per data channel, no multiplexing. Decoders accept it for backward
//! compatibility and synthesise `request_id = 0`.
//!
//! `frame_v2` is emitted by all post-PR-#40 peers. The leading `0x00`
//! version byte is distinct from every assigned [`FrameType`]
//! discriminant (which all fall in `0x01..=0xFF`), so a decoder can
//! unambiguously pick the correct shape from the first byte. The
//! `request_id` demultiplexes multiple concurrent HTTP transactions over
//! a single data channel — browsers loading a page with CSS, JS, images
//! and video fire many concurrent fetches through one openhost session,
//! and each gets its own id. Auth frames (`AuthNonce`/`AuthClient`/`AuthHost`)
//! are session-scoped, not request-scoped, so they carry `request_id = 0`.
//!
//! A decoder may receive partial frames from the transport; [`Frame::try_decode`]
//! returns `Ok(None)` when more bytes are needed and `Ok(Some((frame, consumed)))`
//! when a complete frame is available.
//!
//! Payloads are plain `Vec<u8>`; higher-level code interprets them according to
//! [`FrameType`] (e.g. HTTP header text for [`FrameType::RequestHead`]).

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Wire header length of the legacy v1 frame: `type(1) || length(4)`.
pub const FRAME_HEADER_LEN: usize = 5;

/// Wire header length of the v2 frame:
/// `0x02 || type(1) || request_id(4 BE) || length(4 BE)` = 10 bytes.
pub const FRAME_V2_HEADER_LEN: usize = 10;

/// Leading byte that marks a v2 frame. `0x00` is never a valid
/// [`FrameType`] discriminant, so it cannot collide with v1 frames
/// even at payload boundaries. (A v1 RequestBody frame begins with
/// `0x02`, not `0x00`, so the decoder's lookahead is unambiguous.)
pub const FRAME_V2_VERSION: u8 = 0x00;

/// Maximum permitted payload length. Per the spec: `0 ≤ length ≤ 2^24 − 1`.
pub const MAX_PAYLOAD_LEN: usize = (1 << 24) - 1;

/// Request ID reserved for session-scoped frames that do NOT belong to
/// any HTTP transaction (AuthNonce/AuthClient/AuthHost, Ping/Pong,
/// connection-level Error). Also synthesised by the v1 legacy decoder.
pub const REQUEST_ID_SESSION: u32 = 0;

/// Type tag for one openhost data-channel frame.
///
/// The discriminants are wire values — do not reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum FrameType {
    /// HTTP/1.1 request line + headers, UTF-8, terminated by a blank line.
    RequestHead = 0x01,
    /// A chunk of the request body.
    RequestBody = 0x02,
    /// Marker: no more request-body bytes. Payload MUST be empty.
    RequestEnd = 0x03,

    /// HTTP/1.1 status line + headers, UTF-8, terminated by a blank line.
    ResponseHead = 0x11,
    /// A chunk of the response body.
    ResponseBody = 0x12,
    /// Marker: no more response-body bytes. Payload MUST be empty.
    ResponseEnd = 0x13,

    /// RFC 6455 WebSocket upgrade handshake payload.
    /// Only accepted when the daemon has explicitly enabled WebSocket upgrades.
    WsUpgrade = 0x20,
    /// Transparent RFC 6455 WebSocket frame, following a successful upgrade.
    WsFrame = 0x21,

    /// Channel-binding nonce sent by the daemon post-DTLS-Connected
    /// (spec §3 step 9). Payload: 32 random bytes.
    AuthNonce = 0x30,
    /// Client's channel-binding response (spec §3 step 9).
    /// Payload: 32-byte Ed25519 `client_pk` || 64-byte
    /// `sig_client(auth_bytes(host_pk, client_pk, nonce))`.
    AuthClient = 0x31,
    /// Daemon's channel-binding response (spec §3 step 9).
    /// Payload: 64-byte `sig_host(auth_bytes(host_pk, client_pk, nonce))`.
    AuthHost = 0x32,

    /// Application-layer diagnostic error. Payload is a UTF-8 string.
    Error = 0xF0,

    /// Keepalive request. Payload MUST be empty.
    Ping = 0xFE,
    /// Keepalive response. Payload MUST be empty.
    Pong = 0xFF,
}

impl FrameType {
    /// Decode from the wire type byte.
    pub fn from_u8(byte: u8) -> Result<Self> {
        Ok(match byte {
            0x01 => Self::RequestHead,
            0x02 => Self::RequestBody,
            0x03 => Self::RequestEnd,
            0x11 => Self::ResponseHead,
            0x12 => Self::ResponseBody,
            0x13 => Self::ResponseEnd,
            0x20 => Self::WsUpgrade,
            0x21 => Self::WsFrame,
            0x30 => Self::AuthNonce,
            0x31 => Self::AuthClient,
            0x32 => Self::AuthHost,
            0xF0 => Self::Error,
            0xFE => Self::Ping,
            0xFF => Self::Pong,
            _ => return Err(Error::MalformedFrame("unknown type code")),
        })
    }

    /// Wire byte for this type.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Whether the payload for this type is required to be empty.
    #[must_use]
    pub fn payload_must_be_empty(self) -> bool {
        matches!(
            self,
            Self::RequestEnd | Self::ResponseEnd | Self::Ping | Self::Pong
        )
    }
}

/// A complete, owned openhost data-channel frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame type tag.
    pub frame_type: FrameType,
    /// Per-HTTP-transaction demultiplexing id. Non-zero for
    /// REQUEST_*/RESPONSE_* + WS_FRAME frames belonging to a specific
    /// in-flight HTTP transaction; zero for session-scoped frames
    /// (AuthNonce/AuthClient/AuthHost, Ping/Pong) and for legacy v1
    /// frames (synthesised during decode).
    pub request_id: u32,
    /// Frame payload bytes (length is implicit from the `Vec`).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new session-scoped frame (request_id = 0). Preserved for
    /// call sites that never care about demultiplexing — auth frames,
    /// pings, legacy tests. Validates per-type payload constraints.
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Result<Self> {
        Self::new_with_id(frame_type, REQUEST_ID_SESSION, payload)
    }

    /// Create a new frame with an explicit request_id. HTTP-transaction
    /// frames produced by the SW proxy / client session use this.
    pub fn new_with_id(frame_type: FrameType, request_id: u32, payload: Vec<u8>) -> Result<Self> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::OversizedFrame {
                requested: payload.len(),
                limit: MAX_PAYLOAD_LEN,
            });
        }
        if frame_type.payload_must_be_empty() && !payload.is_empty() {
            return Err(Error::MalformedFrame(
                "frame type requires empty payload but got bytes",
            ));
        }
        Ok(Self {
            frame_type,
            request_id,
            payload,
        })
    }

    /// Append the wire encoding of this frame to `out`. Post-PR-#40
    /// emitters always produce v2 (10-byte header with request_id);
    /// v1 emit is available via [`Frame::encode_v1`] for backward-compat
    /// tests only.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(FRAME_V2_HEADER_LEN + self.payload.len());
        out.push(FRAME_V2_VERSION);
        out.push(self.frame_type.as_u8());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        let len = u32::try_from(self.payload.len()).expect("length fits in u32 by construction");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.payload);
    }

    /// Append the legacy v1 wire encoding. `request_id` is dropped —
    /// v1 is single-stream by design. Kept for backward-compatibility
    /// tests; production code MUST NOT emit v1.
    #[doc(hidden)]
    pub fn encode_v1(&self, out: &mut Vec<u8>) {
        out.reserve(FRAME_HEADER_LEN + self.payload.len());
        out.push(self.frame_type.as_u8());
        let len = u32::try_from(self.payload.len()).expect("length fits in u32 by construction");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.payload);
    }

    /// Encode to a fresh `Vec<u8>` using the post-PR-#40 v2 format.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_V2_HEADER_LEN + self.payload.len());
        self.encode(&mut out);
        out
    }

    /// Try to decode one frame from the front of `buf`. Accepts both v1
    /// and v2 shapes based on the leading byte:
    ///
    /// - First byte `0x00` → consume a v2 10-byte header (big-endian
    ///   fields) + payload.
    /// - Else → treat as v1 5-byte header (little-endian length) and
    ///   synthesise `request_id = REQUEST_ID_SESSION`.
    ///
    /// Returns:
    /// - `Ok(Some((frame, consumed)))` on success; `consumed` bytes were read.
    /// - `Ok(None)` if more bytes are required.
    /// - `Err(_)` if the bytes are malformed; the caller MUST tear down the channel.
    pub fn try_decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        if buf.is_empty() {
            return Ok(None);
        }
        if buf[0] == FRAME_V2_VERSION {
            Self::try_decode_v2(buf)
        } else {
            Self::try_decode_v1(buf)
        }
    }

    fn try_decode_v1(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let type_byte = buf[0];
        let len_bytes: [u8; 4] = buf[1..5].try_into().expect("5..5 slice");
        let length = u32::from_le_bytes(len_bytes) as usize;

        if length > MAX_PAYLOAD_LEN {
            return Err(Error::OversizedFrame {
                requested: length,
                limit: MAX_PAYLOAD_LEN,
            });
        }

        let frame_type = FrameType::from_u8(type_byte)?;

        if frame_type.payload_must_be_empty() && length != 0 {
            return Err(Error::MalformedFrame(
                "frame type forbids payload but length is non-zero",
            ));
        }

        let total = FRAME_HEADER_LEN + length;
        if buf.len() < total {
            return Ok(None);
        }

        let payload = buf[FRAME_HEADER_LEN..total].to_vec();
        Ok(Some((
            Self {
                frame_type,
                request_id: REQUEST_ID_SESSION,
                payload,
            },
            total,
        )))
    }

    fn try_decode_v2(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        if buf.len() < FRAME_V2_HEADER_LEN {
            return Ok(None);
        }
        // buf[0] = version (already verified by caller)
        let type_byte = buf[1];
        let id_bytes: [u8; 4] = buf[2..6].try_into().expect("2..6 slice");
        let len_bytes: [u8; 4] = buf[6..10].try_into().expect("6..10 slice");
        let request_id = u32::from_be_bytes(id_bytes);
        let length = u32::from_be_bytes(len_bytes) as usize;

        if length > MAX_PAYLOAD_LEN {
            return Err(Error::OversizedFrame {
                requested: length,
                limit: MAX_PAYLOAD_LEN,
            });
        }

        let frame_type = FrameType::from_u8(type_byte)?;

        if frame_type.payload_must_be_empty() && length != 0 {
            return Err(Error::MalformedFrame(
                "frame type forbids payload but length is non-zero",
            ));
        }

        let total = FRAME_V2_HEADER_LEN + length;
        if buf.len() < total {
            return Ok(None);
        }

        let payload = buf[FRAME_V2_HEADER_LEN..total].to_vec();
        Ok(Some((
            Self {
                frame_type,
                request_id,
                payload,
            },
            total,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_constants() {
        assert_eq!(FRAME_HEADER_LEN, 5);
        assert_eq!(FRAME_V2_HEADER_LEN, 10);
        assert_eq!(FRAME_V2_VERSION, 0x00);
        assert_eq!(MAX_PAYLOAD_LEN, 0x00FF_FFFF);
        assert_eq!(REQUEST_ID_SESSION, 0);
    }

    #[test]
    fn encode_decode_roundtrip_request_head() {
        let body = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n".to_vec();
        let frame = Frame::new_with_id(FrameType::RequestHead, 7, body.clone()).unwrap();
        let bytes = frame.encode_to_vec();
        // v2 emission: version(0x00) | type | request_id(BE) | length(BE)
        assert_eq!(bytes[0], FRAME_V2_VERSION);
        assert_eq!(bytes[1], FrameType::RequestHead.as_u8());
        assert_eq!(u32::from_be_bytes(bytes[2..6].try_into().unwrap()), 7);
        let len = u32::from_be_bytes(bytes[6..10].try_into().unwrap()) as usize;
        assert_eq!(len, body.len());
        let (decoded, consumed) = Frame::try_decode(&bytes).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(decoded.request_id, 7);
        assert_eq!(consumed, bytes.len());
    }

    #[test]
    fn frame_v2_roundtrips_preserving_request_id() {
        // Pick a request_id distinct from 0 so we catch a decoder that
        // zero-synthesises the field.
        let id: u32 = 0xdead_beef;
        let frame = Frame::new_with_id(FrameType::ResponseBody, id, b"hello".to_vec()).unwrap();
        let bytes = frame.encode_to_vec();
        let (decoded, _) = Frame::try_decode(&bytes).unwrap().unwrap();
        assert_eq!(decoded.request_id, id);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn frame_v1_legacy_decodes_with_zero_request_id() {
        // Hand-craft a v1 RequestBody frame (single-byte type + LE len).
        let payload = b"legacy-body".to_vec();
        let mut v1 = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        v1.push(FrameType::RequestBody.as_u8());
        v1.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v1.extend_from_slice(&payload);

        let (decoded, consumed) = Frame::try_decode(&v1).unwrap().unwrap();
        assert_eq!(decoded.frame_type, FrameType::RequestBody);
        assert_eq!(decoded.request_id, REQUEST_ID_SESSION);
        assert_eq!(decoded.payload, payload);
        assert_eq!(consumed, v1.len());
    }

    #[test]
    fn frame_v1_v2_interleaved_decode() {
        // A channel receiving a v1 frame followed by a v2 frame — the
        // decoder MUST disambiguate purely from the leading byte of
        // each message. (This scenario arises only during rollout
        // against a pre-PR-#40 peer, but the invariant is worth
        // pinning.)
        let mut buf = Vec::new();
        let f1 = Frame::new(FrameType::ResponseHead, b"HTTP/1.1 200\r\n\r\n".to_vec()).unwrap();
        f1.encode_v1(&mut buf);
        let f2 = Frame::new_with_id(FrameType::ResponseBody, 42, b"body".to_vec()).unwrap();
        f2.encode(&mut buf);

        let (d1, n1) = Frame::try_decode(&buf).unwrap().unwrap();
        assert_eq!(d1.frame_type, FrameType::ResponseHead);
        assert_eq!(d1.request_id, REQUEST_ID_SESSION);

        let (d2, _) = Frame::try_decode(&buf[n1..]).unwrap().unwrap();
        assert_eq!(d2.frame_type, FrameType::ResponseBody);
        assert_eq!(d2.request_id, 42);
    }

    #[test]
    fn encode_decode_empty_marker_frames() {
        for ty in [
            FrameType::RequestEnd,
            FrameType::ResponseEnd,
            FrameType::Ping,
            FrameType::Pong,
        ] {
            let f = Frame::new(ty, vec![]).unwrap();
            let enc = f.encode_to_vec();
            // v2 header = 10 bytes, payload = 0
            assert_eq!(enc.len(), FRAME_V2_HEADER_LEN);
            let (dec, _) = Frame::try_decode(&enc).unwrap().unwrap();
            assert_eq!(dec, f);
        }
    }

    #[test]
    fn constructing_empty_marker_with_body_is_rejected() {
        assert!(Frame::new(FrameType::Ping, vec![0]).is_err());
        assert!(Frame::new(FrameType::RequestEnd, vec![1, 2, 3]).is_err());
    }

    #[test]
    fn decoding_unknown_type_is_rejected() {
        // v1 path: first byte is an unknown FrameType discriminant.
        // Use 0x50 — outside all assigned FrameType ranges, and not
        // the v2 version marker.
        let bad = [0x50u8, 0, 0, 0, 0];
        let err = Frame::try_decode(&bad).unwrap_err();
        assert!(matches!(err, Error::MalformedFrame(_)));
    }

    #[test]
    fn frame_v2_rejects_unknown_frame_type() {
        // v2 header with an unassigned FrameType byte (0x50).
        let bad = [FRAME_V2_VERSION, 0x50, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = Frame::try_decode(&bad).unwrap_err();
        assert!(matches!(err, Error::MalformedFrame(_)));
    }

    #[test]
    fn decoding_insufficient_bytes_returns_none() {
        assert!(Frame::try_decode(&[]).unwrap().is_none());
        // v1 path, short header
        assert!(Frame::try_decode(&[0x01, 0, 0]).unwrap().is_none());
        // v1 header parsed but payload incomplete.
        let partial_v1 = [0x01, 10, 0, 0, 0, b'x', b'y']; // needs 10 payload, has 2
        assert!(Frame::try_decode(&partial_v1).unwrap().is_none());
        // v2: short header.
        assert!(Frame::try_decode(&[FRAME_V2_VERSION, 0x11, 0, 0])
            .unwrap()
            .is_none());
    }

    #[test]
    fn decoding_empty_marker_with_body_is_rejected() {
        // v1 Ping with length=3
        let bad_v1 = [0xFE, 3, 0, 0, 0, 0, 0, 0];
        let err = Frame::try_decode(&bad_v1).unwrap_err();
        assert!(matches!(err, Error::MalformedFrame(_)));
        // v2 Ping: version(0x00) | type(0xFE) | req_id(4 BE = 0) | len(4 BE = 3) | 3 body bytes
        let bad_v2 = [
            FRAME_V2_VERSION,
            0xFE,
            0,
            0,
            0,
            0, // request_id = 0
            0,
            0,
            0,
            3, // length = 3 (BE)
            b'x',
            b'y',
            b'z',
        ];
        let err = Frame::try_decode(&bad_v2).unwrap_err();
        assert!(matches!(err, Error::MalformedFrame(_)));
    }

    #[test]
    fn oversized_length_field_is_rejected() {
        // length = MAX_PAYLOAD_LEN + 1 (v1 header)
        let len = (MAX_PAYLOAD_LEN + 1) as u32;
        let mut header = vec![0x12u8];
        header.extend_from_slice(&len.to_le_bytes());
        let err = Frame::try_decode(&header).unwrap_err();
        assert!(matches!(err, Error::OversizedFrame { .. }));
    }

    #[test]
    fn decoding_leaves_trailing_bytes_in_buffer() {
        let f1 = Frame::new(FrameType::ResponseBody, b"abc".to_vec()).unwrap();
        let f2 = Frame::new(FrameType::ResponseEnd, vec![]).unwrap();
        let mut buf = Vec::new();
        f1.encode(&mut buf);
        f2.encode(&mut buf);
        let (d1, n1) = Frame::try_decode(&buf).unwrap().unwrap();
        assert_eq!(d1, f1);
        let (d2, n2) = Frame::try_decode(&buf[n1..]).unwrap().unwrap();
        assert_eq!(d2, f2);
        assert_eq!(n1 + n2, buf.len());
    }

    #[test]
    fn frame_type_as_u8_matches_enum() {
        assert_eq!(FrameType::RequestHead.as_u8(), 0x01);
        assert_eq!(FrameType::ResponseEnd.as_u8(), 0x13);
        assert_eq!(FrameType::WsFrame.as_u8(), 0x21);
        assert_eq!(FrameType::Error.as_u8(), 0xF0);
        assert_eq!(FrameType::Ping.as_u8(), 0xFE);
        assert_eq!(FrameType::Pong.as_u8(), 0xFF);
    }
}
