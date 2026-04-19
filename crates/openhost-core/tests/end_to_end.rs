//! End-to-end exercise of the spec §8 flow at the crypto/wire/record layer.
//! The DTLS handshake itself happens outside openhost-core (M3+).
//!
//! This test proves that the modules fit together coherently: identity,
//! sealed-box + signature primitives, the v2 pkarr record, channel-binding
//! auth-bytes, and the HTTP-over-DataChannel wire framing.
//!
//! Notes on the v2 record schema (PR #22): the main `_openhost` record
//! no longer carries an `allow` list or per-client `ice` blobs. Pairing
//! enforcement is host-internal (`SharedState::is_client_allowed`); ICE
//! blobs, when they're wired up, will travel in separate records under
//! the same packet (analogous to how answers were fragmented in PR #15).
//! This test consequently no longer round-trips a host-to-client ICE
//! sealed box — a separate unit test in `crypto::tests` covers that
//! primitive.

use openhost_core::crypto::{auth_bytes, sealed_box_open, sealed_box_seal, signing_key_to_x25519};
use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{
    OpenhostRecord, SignedRecord, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION, SALT_LEN,
};
use openhost_core::wire::{Frame, FrameType};

#[test]
fn host_publishes_client_resolves_signs_and_exchanges_frames() {
    let mut rng = rand::rngs::OsRng;

    // --- Identities ---------------------------------------------------------
    let host_sk = SigningKey::generate(&mut rng);
    let host_pk = host_sk.public_key();

    let client_sk = SigningKey::generate(&mut rng);
    let client_pk = client_sk.public_key();

    // --- Host publishes a v2 signed record ----------------------------------
    let salt = [0x99u8; SALT_LEN];
    let dtls_fp = {
        let mut fp = [0u8; DTLS_FINGERPRINT_LEN];
        fp.copy_from_slice(
            &<sha2::Sha256 as sha2::Digest>::digest(b"pretend DTLS cert")[..DTLS_FINGERPRINT_LEN],
        );
        fp
    };

    let ts = 1_700_000_000u64;
    let record = OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts,
        dtls_fp,
        roles: "server".into(),
        salt,
        disc: "dht=1".into(),
    };
    let signed = SignedRecord::sign(record, &host_sk).expect("sign");

    // --- Client resolves and verifies the record ----------------------------
    signed
        .verify(&host_pk, ts)
        .expect("client verifies signature + freshness");
    // Client sees the pinned DTLS fingerprint. A real client would compare
    // this against the fingerprint negotiated during the DTLS handshake.
    assert_eq!(signed.record.dtls_fp, dtls_fp);

    // --- Simulated channel binding (spec §8.3 step 9) -----------------------
    let simulated_exporter_secret = [0x37u8; 32];
    let auth = auth_bytes(&simulated_exporter_secret).expect("auth_bytes");

    let host_auth_sig = host_sk.sign(&auth);
    let client_auth_sig = client_sk.sign(&auth);

    host_pk
        .verify(&auth, &host_auth_sig)
        .expect("host self-sanity");
    client_pk
        .verify(&auth, &client_auth_sig)
        .expect("client self-sanity");

    // --- HTTP-over-DataChannel exchange -------------------------------------
    let req_head = Frame::new(
        FrameType::RequestHead,
        b"GET /library HTTP/1.1\r\nHost: home\r\n\r\n".to_vec(),
    )
    .unwrap();
    let req_end = Frame::new(FrameType::RequestEnd, vec![]).unwrap();

    let mut wire = Vec::new();
    req_head.encode(&mut wire);
    req_end.encode(&mut wire);

    let (d1, n1) = Frame::try_decode(&wire).unwrap().unwrap();
    let (d2, _) = Frame::try_decode(&wire[n1..]).unwrap().unwrap();
    assert_eq!(d1, req_head);
    assert_eq!(d2, req_end);

    let resp_head = Frame::new(
        FrameType::ResponseHead,
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".to_vec(),
    )
    .unwrap();
    let resp_body = Frame::new(FrameType::ResponseBody, b"hello".to_vec()).unwrap();
    let resp_end = Frame::new(FrameType::ResponseEnd, vec![]).unwrap();

    let mut wire = Vec::new();
    resp_head.encode(&mut wire);
    resp_body.encode(&mut wire);
    resp_end.encode(&mut wire);

    let (h, n1) = Frame::try_decode(&wire).unwrap().unwrap();
    let (b, n2) = Frame::try_decode(&wire[n1..]).unwrap().unwrap();
    let (e, _) = Frame::try_decode(&wire[n1 + n2..]).unwrap().unwrap();
    assert_eq!(h, resp_head);
    assert_eq!(b, resp_body);
    assert_eq!(e, resp_end);
}

/// Standalone sanity-check for the sealed-box primitive we use to carry
/// ICE candidates per-client once that layer ships. Lives here (rather
/// than in the pkarr-record test vectors) because it doesn't depend on
/// the wire shape — just that a ciphertext sealed to one X25519 key
/// cannot be opened by another.
#[test]
fn unpaired_client_cannot_open_ice_sealed_box() {
    use openhost_core::crypto::public_key_to_x25519;
    let mut rng = rand::rngs::OsRng;
    let paired_sk = SigningKey::generate(&mut rng);
    let unpaired_sk = SigningKey::generate(&mut rng);

    let paired_x_pk = public_key_to_x25519(&paired_sk.public_key()).unwrap();
    let unpaired_x_sk = signing_key_to_x25519(&unpaired_sk);

    let ciphertext = sealed_box_seal(&mut rng, &paired_x_pk, b"secret ICE candidates");
    assert!(sealed_box_open(&unpaired_x_sk, &ciphertext).is_err());
}
