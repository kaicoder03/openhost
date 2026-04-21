//! Host-target smoke tests for the `openhost-pkarr-wasm` shim (PR #28.2).
//!
//! These tests exercise the `core` tier directly — the `#[wasm_bindgen]`
//! wrappers at crate root can only run inside a wasm runtime. The goal
//! is "does every decode wrapper return byte-identical data to what the
//! CLI dialer would see" so any future change to the underlying
//! openhost-pkarr decode path is caught here first.

use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{
    OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
};
use openhost_pkarr::{encode, encode_with_answers, AnswerEntry, AnswerPlaintext};
use openhost_pkarr_wasm::core;

const SEED: [u8; 32] = [0x42; 32];
const CLIENT_SEED: [u8; 32] = [0x33; 32];

fn sample_signed_record(ts: u64) -> (SigningKey, SignedRecord) {
    let sk = SigningKey::from_bytes(&SEED);
    let record = OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts,
        dtls_fp: [0x11; DTLS_FINGERPRINT_LEN],
        roles: "server".to_string(),
        salt: [0x22; SALT_LEN],
        disc: String::new(),
        turn_port: None,
    };
    let signed = SignedRecord::sign(record, &sk).unwrap();
    (sk, signed)
}

fn now_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn parse_host_record_returns_fields_matching_the_source() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.to_relay_payload().to_vec();

    let pk_z = sk.public_key().to_zbase32();
    let dto = core::parse_host_record(&bytes, &pk_z).expect("decode succeeds");

    assert_eq!(dto.pubkey_zbase32, pk_z);
    assert_eq!(dto.version, PROTOCOL_VERSION);
    assert_eq!(dto.ts, ts);
    assert_eq!(dto.roles, "server");
    assert_eq!(dto.disc, "");
    assert_eq!(dto.dtls_fingerprint_hex, hex::encode([0x11u8; 32]));
    assert_eq!(dto.salt_hex, hex::encode([0x22u8; 32]));
    assert_eq!(dto.signature_hex.len(), 128);
}

#[test]
fn parse_host_record_rejects_invalid_pubkey() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.to_relay_payload().to_vec();

    let err = core::parse_host_record(&bytes, "not-a-real-pubkey").expect_err("must reject");
    let s = err.to_string();
    assert!(
        s.contains("zbase32"),
        "error message should mention zbase32, got: {s}"
    );
}

#[test]
fn decode_and_verify_accepts_good_signature() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.to_relay_payload().to_vec();

    let pk_z = sk.public_key().to_zbase32();
    let dto = core::decode_and_verify(&bytes, &pk_z, ts).expect("verify succeeds");
    assert_eq!(dto.ts, ts);
    assert_eq!(dto.version, PROTOCOL_VERSION);
}

#[test]
fn decode_and_verify_rejects_wrong_pubkey_with_verify_failed() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.to_relay_payload().to_vec();

    // Verify against a *different* pubkey — the inner Ed25519 sig is
    // over canonical bytes signed by `sk`, so the verify path must
    // surface `VerifyFailed` (not a parse error).
    let other_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let wrong_pk_z = other_sk.public_key().to_zbase32();
    let err = core::decode_and_verify(&bytes, &wrong_pk_z, ts)
        .expect_err("mismatched pubkey must fail verify");
    // Post-PR-35 framing: a mismatched pubkey may surface as either
    // `VerifyFailed` (inner Ed25519 sig mismatch) or a pkarr-layer
    // decode failure (framed pubkey disagrees with record contents).
    // Both are "decoder refused to trust this packet" — the semantic
    // the test exists to protect.
    assert!(
        matches!(err, core::Error::VerifyFailed(_) | core::Error::Pkarr(_)),
        "expected VerifyFailed or Pkarr decode error, got {err:?}",
    );
}

#[test]
fn decode_and_verify_rejects_stale_record_with_verify_failed() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.to_relay_payload().to_vec();

    let pk_z = sk.public_key().to_zbase32();
    // 3-hour skew pushes the record outside the spec's 2-hour
    // freshness window.
    let stale_now = ts + 3 * 3600;
    let err = core::decode_and_verify(&bytes, &pk_z, stale_now)
        .expect_err("stale record must fail verify");
    assert!(
        matches!(err, core::Error::VerifyFailed(_)),
        "expected VerifyFailed for stale record, got {err:?}",
    );
}

#[test]
fn decode_offer_returns_none_when_no_offer_txt_is_published() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode(&signed, &sk).unwrap();
    let bytes = packet.to_relay_payload().to_vec();

    let daemon_pk_z = sk.public_key().to_zbase32();
    let out = core::decode_offer(&bytes, &daemon_pk_z).expect("runs");
    assert!(out.is_none());
}

#[test]
fn decode_answer_fragments_returns_none_when_no_fragments_are_published() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);
    let packet = encode_with_answers(&signed, &sk, &[]).unwrap();
    // Feed the WASM shim relay-payload bytes (sig+seq+v), matching what
    // a relay HTTP response carries.
    let bytes = packet.to_relay_payload().to_vec();

    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let salt = [0x22u8; SALT_LEN];
    let client_pk_z = client_sk.public_key().to_zbase32();
    let daemon_pk_z = sk.public_key().to_zbase32();
    let out =
        core::decode_answer_fragments(&bytes, &salt, &client_pk_z, &daemon_pk_z).expect("runs");
    assert!(out.is_none());
}

#[test]
fn decode_answer_fragments_reassembles_published_fragments() {
    let ts = now_ts();
    let (sk, signed) = sample_signed_record(ts);

    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let client_pk = client_sk.public_key();
    let salt = [0x22u8; SALT_LEN];

    let blob = openhost_pkarr::AnswerBlob {
        ice_ufrag: "abcd".to_string(),
        ice_pwd: "0123456789abcdefghij!@".to_string(),
        setup: openhost_pkarr::SetupRole::Passive,
        candidates: vec![openhost_pkarr::BlobCandidate {
            typ: openhost_pkarr::CandidateType::Srflx,
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
            port: 51_820,
        }],
    };
    let plaintext = AnswerPlaintext {
        daemon_pk: sk.public_key(),
        offer_sdp_hash: openhost_pkarr::hash_offer_sdp("v=0\r\n"),
        answer: openhost_pkarr::AnswerPayload::V2Blob(blob.clone()),
    };
    let mut rng = rand::rngs::OsRng;
    let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, ts).unwrap();
    let expected_sealed = entry.sealed.clone();
    let expected_hash_hex = hex::encode(entry.client_hash);

    let packet = encode_with_answers(&signed, &sk, std::slice::from_ref(&entry)).expect("encode");
    let bytes = packet.to_relay_payload().to_vec();

    let client_pk_z = client_pk.to_zbase32();
    let daemon_pk_z = sk.public_key().to_zbase32();
    let out =
        core::decode_answer_fragments(&bytes, &salt, &client_pk_z, &daemon_pk_z).expect("runs");
    let dto = out.unwrap_or_else(|| {
        panic!(
            "fragment set for client pubkey {client_pk_z} was absent on the wire; \
             if this is repeatable, the encoder likely evicted the answer because \
             the BEP44 1000-byte cap was exceeded. Check the test's synthetic \
             answer SDP length."
        )
    });
    assert_eq!(dto.client_hash_hex, expected_hash_hex);

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let sealed_back = URL_SAFE_NO_PAD
        .decode(dto.sealed_base64url.as_bytes())
        .expect("base64url decodes");
    assert_eq!(sealed_back, expected_sealed);

    // Sanity: the reassembled ciphertext is actually openable by the
    // client identity — the shim preserved every byte, not just the
    // length.
    let rebuilt = AnswerEntry {
        client_hash: entry.client_hash,
        sealed: sealed_back,
        created_at: entry.created_at,
    };
    let opened = rebuilt.open(&client_sk).expect("sealed bytes open");
    match opened.answer {
        openhost_pkarr::AnswerPayload::V2Blob(got) => assert_eq!(got, blob),
        openhost_pkarr::AnswerPayload::V1Sdp(s) => panic!("expected V2Blob, got V1 SDP: {s}"),
    }
}

// ============================================================================
// Phase 4 browser-primitive smoke tests (PR #28.3)
// ============================================================================

/// Minimal but complete SDP offer carrying the attributes the v3
/// compact-blob codec requires (ice-ufrag/pwd, setup, fingerprint).
/// Used by the seal-offer roundtrip test below. Closer to what a
/// real browser produces than the one-line synthetic strings used by
/// pre-compact-offer tests.
const SAMPLE_COMPLETE_OFFER_SDP: &str = "\
v=0\r\n\
o=- 1 1 IN IP4 0.0.0.0\r\n\
s=-\r\n\
t=0 0\r\n\
m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=ice-ufrag:abcd\r\n\
a=ice-pwd:0123456789abcdefghij!@\r\n\
a=fingerprint:sha-256 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89\r\n\
a=setup:actpass\r\n\
a=sctp-port:5000\r\n\
a=candidate:1 1 udp 1 203.0.113.7 51820 typ srflx\r\n";

#[test]
fn seal_offer_roundtrips_via_daemon_open() {
    use openhost_pkarr::offer::OfferRecord;
    use openhost_pkarr::OfferPayload;

    let daemon_sk = SigningKey::from_bytes(&SEED);
    let daemon_pk_z = daemon_sk.public_key().to_zbase32();
    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let client_pk_z = client_sk.public_key().to_zbase32();

    let sealed = core::seal_offer(&daemon_pk_z, &client_pk_z, SAMPLE_COMPLETE_OFFER_SDP, 0x02)
        .expect("seal ok");

    // Daemon-side open path: rebuild an OfferRecord from the sealed
    // bytes and invoke the existing unseal surface.
    let record = OfferRecord { sealed };
    let plain = record.open(&daemon_sk).expect("daemon opens sealed offer");
    assert_eq!(
        plain.client_pk.to_bytes(),
        client_sk.public_key().to_bytes()
    );
    assert_eq!(plain.binding_mode, openhost_pkarr::BindingMode::CertFp);
    match plain.offer {
        OfferPayload::V3Blob(blob) => {
            assert_eq!(blob.ice_ufrag, "abcd");
            assert_eq!(blob.ice_pwd, "0123456789abcdefghij!@");
            assert_eq!(blob.setup, openhost_pkarr::SetupRole::Actpass);
            assert_eq!(blob.binding_mode, openhost_pkarr::BindingMode::CertFp);
            assert_eq!(blob.candidates.len(), 1);
        }
        OfferPayload::LegacySdp(s) => panic!("v3 seal path must produce V3Blob, got: {s}"),
    }
}

#[test]
fn seal_offer_rejects_unknown_binding_mode() {
    let daemon_pk_z = SigningKey::from_bytes(&SEED).public_key().to_zbase32();
    let client_pk_z = SigningKey::from_bytes(&CLIENT_SEED)
        .public_key()
        .to_zbase32();
    assert!(matches!(
        core::seal_offer(&daemon_pk_z, &client_pk_z, SAMPLE_COMPLETE_OFFER_SDP, 0xFF),
        Err(core::Error::Pkarr(_))
    ));
}

#[test]
fn open_answer_roundtrips_v2_blob_via_client_sk() {
    use openhost_pkarr::{
        AnswerBlob, AnswerEntry, AnswerPayload, AnswerPlaintext, BlobCandidate, CandidateType,
        SetupRole,
    };

    let daemon_sk = SigningKey::from_bytes(&SEED);
    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let client_pk = client_sk.public_key();
    let salt = [0x22u8; SALT_LEN];
    let blob = AnswerBlob {
        ice_ufrag: "abcd".to_string(),
        ice_pwd: "0123456789abcdefghij!@".to_string(),
        setup: SetupRole::Passive,
        candidates: vec![BlobCandidate {
            typ: CandidateType::Srflx,
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 7)),
            port: 51_820,
        }],
    };
    let plaintext = AnswerPlaintext {
        daemon_pk: daemon_sk.public_key(),
        offer_sdp_hash: openhost_pkarr::hash_offer_sdp("v=0"),
        answer: AnswerPayload::V2Blob(blob.clone()),
    };
    let mut rng = rand::rngs::OsRng;
    let entry = AnswerEntry::seal(&mut rng, &client_pk, &salt, &plaintext, now_ts()).expect("seal");

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let sealed_b64 = URL_SAFE_NO_PAD.encode(&entry.sealed);

    let dtls_fp = [0xAAu8; openhost_pkarr::DTLS_FP_LEN];
    let dtls_fp_hex = hex::encode(dtls_fp);
    let opened = core::open_answer(&client_sk.to_bytes(), &sealed_b64, &dtls_fp_hex).expect("open");

    // The reconstructed SDP must contain the blob's ufrag, pwd,
    // setup role, candidate, and the fingerprint we passed in.
    assert!(opened.answer_sdp.contains("a=ice-ufrag:abcd"));
    assert!(opened
        .answer_sdp
        .contains("a=ice-pwd:0123456789abcdefghij!@"));
    assert!(opened.answer_sdp.contains("a=setup:passive"));
    assert!(opened.answer_sdp.contains("203.0.113.7 51820"));
    assert!(opened
        .answer_sdp
        .contains(&openhost_pkarr::answer_blob_to_sdp(&blob, &dtls_fp)[..]));
    assert_eq!(
        opened.daemon_pk_zbase32,
        daemon_sk.public_key().to_zbase32()
    );
}

#[test]
fn cert_fp_binding_matches_sha256_hkdf_daemon_path() {
    use openhost_core::crypto::auth_bytes_bound;

    let host_sk = SigningKey::from_bytes(&SEED);
    let host_pk = host_sk.public_key();
    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);
    let client_pk = client_sk.public_key();
    let cert_der = b"-----FAKE-DTLS-CERT-DER-BYTES-----";
    let nonce = [0x77u8; 32];

    let wasm_auth = core::compute_cert_fp_binding(
        cert_der,
        &host_pk.to_zbase32(),
        &client_pk.to_zbase32(),
        &nonce,
    )
    .expect("compute");

    // Reproduce the daemon's derive_binding_secret(CertFp) path by
    // hand: SHA-256(DER) → HKDF-SHA256 with the standard bound
    // context → 32 auth bytes.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(cert_der);
    let secret: [u8; 32] = h.finalize().into();
    let expect =
        auth_bytes_bound(&secret, &host_pk.to_bytes(), &client_pk.to_bytes(), &nonce).unwrap();
    assert_eq!(wasm_auth, expect);
}

#[test]
fn sign_auth_client_and_verify_auth_host_roundtrip() {
    let host_sk = SigningKey::from_bytes(&SEED);
    let client_sk = SigningKey::from_bytes(&CLIENT_SEED);

    let auth_bytes = [0x42u8; 32];
    // Sign AUTH_CLIENT (browser path).
    let payload = core::sign_auth_client(&client_sk.to_bytes(), &auth_bytes).expect("sign");
    assert_eq!(payload.len(), 32 + 64);
    assert_eq!(&payload[..32], &client_sk.public_key().to_bytes()[..]);

    // Server signs AUTH_HOST with its own key; client verifies.
    let host_sig = host_sk.sign(&auth_bytes).to_bytes();
    let ok = core::verify_auth_host(&host_sk.public_key().to_zbase32(), &auth_bytes, &host_sig)
        .expect("verify runs");
    assert!(ok, "valid AUTH_HOST sig must verify");

    // Flip a bit → fails.
    let mut tampered = host_sig;
    tampered[0] ^= 0x01;
    let bad =
        core::verify_auth_host(&host_sk.public_key().to_zbase32(), &auth_bytes, &tampered).unwrap();
    assert!(!bad, "tampered signature must fail verify");
}

#[test]
fn encode_decode_frame_roundtrip_and_partial_buffer_is_none() {
    // Happy path: REQUEST_HEAD with a small payload.
    let req_head_type = 0x01u8;
    let payload = b"GET / HTTP/1.1\r\nHost: openhost\r\n\r\n".to_vec();
    let bytes = core::encode_frame(req_head_type, payload.clone()).expect("encode");
    // Post-PR-#40: encoders emit v2 frames with a 10-byte header
    // (version | type | request_id(4) | length(4)).
    assert_eq!(bytes.len(), 10 + payload.len());

    let decoded = core::decode_frame(&bytes).expect("decode").expect("some");
    assert_eq!(decoded.frame_type, req_head_type);
    assert_eq!(decoded.payload, payload);
    assert_eq!(decoded.consumed, bytes.len());

    // Partial header (< 10 bytes) → None.
    let partial = core::decode_frame(&bytes[..3]).expect("decode partial");
    assert!(partial.is_none());

    // Unknown frame type → Err.
    let err = core::encode_frame(0xEE, vec![]).expect_err("unknown type rejected");
    assert!(matches!(err, core::Error::Frame(_)));
}
