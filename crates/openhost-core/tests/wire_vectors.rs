//! Consume `spec/test-vectors/wire.json` and verify every vector matches the
//! implementation bit-for-bit.

use openhost_core::wire::{Frame, FrameType};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct VectorFile {
    encode_roundtrip: Vec<RoundtripVector>,
    reject: Vec<RejectVector>,
    partial: Vec<PartialVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct RoundtripVector {
    name: String,
    frame_type: String,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    payload_ascii: Option<String>,
    #[serde(default)]
    payload_repeat_byte: Option<String>,
    #[serde(default)]
    payload_length: Option<usize>,
    #[serde(default)]
    encoded_hex: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    encoded_header_hex: Option<String>,
    #[serde(default)]
    encoded_hex_canonical: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RejectVector {
    name: String,
    encoded_hex: String,
}

#[derive(Debug, Deserialize)]
struct PartialVector {
    name: String,
    encoded_hex: String,
}

fn load() -> VectorFile {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec/test-vectors/wire.json");
    let raw = std::fs::read_to_string(&path).expect("read wire.json");
    serde_json::from_str(&raw).expect("parse wire.json")
}

fn frame_type_from_name(name: &str) -> FrameType {
    match name {
        "REQUEST_HEAD" => FrameType::RequestHead,
        "REQUEST_BODY" => FrameType::RequestBody,
        "REQUEST_END" => FrameType::RequestEnd,
        "RESPONSE_HEAD" => FrameType::ResponseHead,
        "RESPONSE_BODY" => FrameType::ResponseBody,
        "RESPONSE_END" => FrameType::ResponseEnd,
        "WS_UPGRADE" => FrameType::WsUpgrade,
        "WS_FRAME" => FrameType::WsFrame,
        "AUTH_NONCE" => FrameType::AuthNonce,
        "AUTH_CLIENT" => FrameType::AuthClient,
        "AUTH_HOST" => FrameType::AuthHost,
        "ERROR" => FrameType::Error,
        "PING" => FrameType::Ping,
        "PONG" => FrameType::Pong,
        other => panic!("unknown frame type in vector: {other}"),
    }
}

fn payload_bytes(v: &RoundtripVector) -> Vec<u8> {
    if let Some(h) = &v.payload_hex {
        hex::decode(h).expect("payload hex")
    } else if let Some(a) = &v.payload_ascii {
        a.as_bytes().to_vec()
    } else if let (Some(byte_hex), Some(len)) = (&v.payload_repeat_byte, v.payload_length) {
        let byte = u8::from_str_radix(byte_hex, 16).expect("single byte hex");
        vec![byte; len]
    } else {
        panic!("vector {:?} has no payload description", v.name);
    }
}

#[test]
fn encode_roundtrip_vectors() {
    // Post-PR-#40: encoders always emit v2 (10-byte header, request_id
    // field). The v1 `encoded_hex` values in `wire.json` are retained
    // for legacy-decode verification (see `legacy_v1_fixture_still_decodes`
    // below); the roundtrip contract here is just "encode → decode
    // recovers the original frame", independent of on-wire version.
    for v in load().encode_roundtrip {
        let ty = frame_type_from_name(&v.frame_type);
        let payload = payload_bytes(&v);
        let frame = Frame::new(ty, payload.clone()).unwrap_or_else(|e| {
            panic!("{}: Frame::new failed: {e}", v.name);
        });
        let encoded = frame.encode_to_vec();

        let (decoded, consumed) = Frame::try_decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded, frame, "{}: decoded frame mismatch", v.name);
        assert_eq!(consumed, encoded.len(), "{}: consumed mismatch", v.name);
    }
}

/// The legacy v1 `encoded_hex` values in `wire.json` MUST still decode
/// successfully — this proves the v1→v2 upgrade is wire-backward-
/// compatible on the decode side.
#[test]
fn legacy_v1_fixture_still_decodes() {
    for v in load().encode_roundtrip {
        let Some(v1_hex) = v.encoded_hex_canonical.clone().or(v.encoded_hex.clone()) else {
            continue; // some fixtures only ship encoded_header_hex
        };
        let bytes = hex::decode(&v1_hex).unwrap_or_else(|e| panic!("{}: bad hex: {e}", v.name));
        let (decoded, _) = Frame::try_decode(&bytes)
            .unwrap_or_else(|e| panic!("{}: v1 legacy decode errored: {e}", v.name))
            .unwrap_or_else(|| panic!("{}: v1 legacy decode returned None", v.name));
        let expected_ty = frame_type_from_name(&v.frame_type);
        assert_eq!(
            decoded.frame_type, expected_ty,
            "{}: frame_type drift",
            v.name
        );
        assert_eq!(
            decoded.request_id, 0,
            "{}: v1 decode must synthesise request_id=0",
            v.name,
        );
    }
}

#[test]
fn reject_vectors() {
    for v in load().reject {
        let bytes = hex::decode(&v.encoded_hex).expect("hex");
        let err = Frame::try_decode(&bytes)
            .err()
            .unwrap_or_else(|| panic!("{}: expected error, parsed successfully", v.name));
        // Just check it's one of the expected error kinds — the exact string isn't the
        // contract, but the error type is.
        use openhost_core::Error;
        assert!(
            matches!(err, Error::MalformedFrame(_) | Error::OversizedFrame { .. }),
            "{}: unexpected error variant: {err}",
            v.name,
        );
    }
}

#[test]
fn partial_vectors_return_none() {
    for v in load().partial {
        let bytes = hex::decode(&v.encoded_hex).expect("hex");
        let res = Frame::try_decode(&bytes).unwrap_or_else(|e| {
            panic!("{}: expected Ok(None) but got error: {e}", v.name);
        });
        assert!(
            res.is_none(),
            "{}: expected need-more-bytes but got {:?}",
            v.name,
            res,
        );
    }
}
