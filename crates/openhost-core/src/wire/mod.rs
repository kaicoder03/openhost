//! HTTP-over-DataChannel framing as specified in `spec/01-wire-format.md` §4.
//!
//! Frames are binary, length-prefixed, and typed:
//!
//! ```text
//! frame   = type (1 byte) | length (4 bytes LE) | payload (N bytes)
//! ```
//!
//! A decoder may receive partial frames from the transport; [`Frame::try_decode`]
//! returns `Ok(None)` when more bytes are needed and `Ok(Some((frame, consumed)))`
//! when a complete frame is available.
//!
//! Payloads are plain `Vec<u8>`; higher-level code interprets them according to
//! [`FrameType`] (e.g. HTTP header text for [`FrameType::RequestHead`]).

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

/// Fixed-size frame header: `type` (1 byte) + `length` (4 bytes LE).
pub const FRAME_HEADER_LEN: usize = 5;

/// Maximum permitted payload length. Per the spec: `0 ≤ length ≤ 2^24 − 1`.
pub const MAX_PAYLOAD_LEN: usize = (1 << 24) - 1;

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
    /// Frame payload bytes (length is implicit from the `Vec`).
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame, validating the per-type payload constraints.
    pub fn new(frame_type: FrameType, payload: Vec<u8>) -> Result<Self> {
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
            payload,
        })
    }

    /// Append the wire encoding of this frame to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.reserve(FRAME_HEADER_LEN + self.payload.len());
        out.push(self.frame_type.as_u8());
        let len = u32::try_from(self.payload.len()).expect("length fits in u32 by construction");
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.payload);
    }

    /// Encode to a fresh `Vec<u8>`.
    #[must_use]
    pub fn encode_to_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        self.encode(&mut out);
        out
    }

    /// Try to decode one frame from the front of `buf`.
    ///
    /// Returns:
    /// - `Ok(Some((frame, consumed)))` on success; `consumed` bytes were read.
    /// - `Ok(None)` if more bytes are required.
    /// - `Err(_)` if the bytes are malformed; the caller MUST tear down the channel.
    pub fn try_decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
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
        assert_eq!(MAX_PAYLOAD_LEN, 0x00FF_FFFF);
    }

    #[test]
    fn encode_decode_roundtrip_request_head() {
        let body = b"GET / HTTP/1.1\r\nHost: example\r\n\r\n".to_vec();
        let frame = Frame::new(FrameType::RequestHead, body.clone()).unwrap();
        let bytes = frame.encode_to_vec();
        assert_eq!(bytes[0], 0x01);
        let len = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as usize;
        assert_eq!(len, body.len());
        let (decoded, consumed) = Frame::try_decode(&bytes).unwrap().unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, bytes.len());
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
            assert_eq!(enc.len(), FRAME_HEADER_LEN);
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
        let bad = [0x00u8, 0, 0, 0, 0];
        let err = Frame::try_decode(&bad).unwrap_err();
        assert!(matches!(err, Error::MalformedFrame(_)));
    }

    #[test]
    fn decoding_insufficient_bytes_returns_none() {
        assert!(Frame::try_decode(&[]).unwrap().is_none());
        assert!(Frame::try_decode(&[0x01, 0, 0]).unwrap().is_none());
        // Header parsed but payload incomplete.
        let partial = [0x01, 10, 0, 0, 0, b'x', b'y']; // needs 10 payload, has 2
        assert!(Frame::try_decode(&partial).unwrap().is_none());
    }

    #[test]
    fn decoding_empty_marker_with_body_is_rejected() {
        // Ping with length=3
        let bad = [0xFE, 3, 0, 0, 0, 0, 0, 0];
        let err = Frame::try_decode(&bad).unwrap_err();
        assert!(matches!(err, Error::MalformedFrame(_)));
    }

    #[test]
    fn oversized_length_field_is_rejected() {
        // length = MAX_PAYLOAD_LEN + 1
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
