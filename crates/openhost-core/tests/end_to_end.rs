//! End-to-end exercise of the spec §8 flow, minus the DTLS handshake itself
//! (which happens outside openhost-core in M3). Exercises identity, crypto,
//! pkarr_record, and wire together.
//!
//! This is a *protocol* test — it proves that the modules fit together
//! coherently, that a client can resolve a host's record, decrypt its own ICE
//! candidates, bind a simulated TLS session, and exchange HTTP-shaped framed
//! traffic.

use openhost_core::crypto::{
    allowlist_hash, auth_bytes, public_key_to_x25519, sealed_box_open, sealed_box_seal,
    signing_key_to_x25519,
};
use openhost_core::identity::SigningKey;
use openhost_core::pkarr_record::{
    IceBlob, OpenhostRecord, SignedRecord, CLIENT_HASH_LEN, DTLS_FINGERPRINT_LEN, PROTOCOL_VERSION,
    SALT_LEN,
};
use openhost_core::wire::{Frame, FrameType};

#[test]
fn host_publishes_client_resolves_signs_and_exchanges_frames() {
    let mut rng = rand::rngs::OsRng;

    // --- Identities ---------------------------------------------------------
    // In production, both sides generate these at first run and persist the
    // signing keys in the OS keychain. Here we use OsRng for realism.
    let host_sk = SigningKey::generate(&mut rng);
    let host_pk = host_sk.public_key();

    let client_sk = SigningKey::generate(&mut rng);
    let client_pk = client_sk.public_key();
    let client_x_sk = signing_key_to_x25519(&client_sk);

    // --- Pairing (one-time) -------------------------------------------------
    // After the out-of-band QR pairing step (M6), the host knows the client's
    // 32-byte Ed25519 public key and adds it to its paired set.
    let paired_clients: Vec<[u8; 32]> = vec![client_pk.to_bytes()];

    // --- Host prepares its signed record ------------------------------------
    let salt = [0x99u8; SALT_LEN];
    let dtls_fp = {
        // Normally: SHA-256 of the daemon's actual DTLS certificate.
        let mut fp = [0u8; DTLS_FINGERPRINT_LEN];
        fp.copy_from_slice(
            &<sha2::Sha256 as sha2::Digest>::digest(b"pretend DTLS cert")[..DTLS_FINGERPRINT_LEN],
        );
        fp
    };

    // Build per-client ICE blobs. The plaintext is candidate JSON; here we
    // just use a fixed marker string.
    let ice_plaintext = b"host:1.2.3.4:50000,relay:stun.cloudflare.com";
    let mut ice_blobs = Vec::new();
    let mut allow = Vec::new();
    for client_ed_pk in &paired_clients {
        let hash = allowlist_hash(&salt, client_ed_pk);
        allow.push(hash);
        // Recover the paired client's X25519 pubkey from its Ed25519 pubkey.
        let client_ed = openhost_core::identity::PublicKey::from_bytes(client_ed_pk).unwrap();
        let their_x_pk = public_key_to_x25519(&client_ed).unwrap();
        let ciphertext = sealed_box_seal(&mut rng, &their_x_pk, ice_plaintext);
        assert!(hash.len() == CLIENT_HASH_LEN);
        ice_blobs.push(IceBlob {
            client_hash: hash.to_vec(),
            ciphertext,
        });
    }

    let ts = 1_700_000_000u64; // fixed for determinism across the test
    let record = OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts,
        dtls_fp,
        roles: "server".into(),
        salt,
        allow,
        ice: ice_blobs,
        disc: "dht=1".into(),
    };
    let signed = SignedRecord::sign(record, &host_sk).expect("sign");

    // --- Client resolves and verifies the record ----------------------------
    signed
        .verify(&host_pk, ts)
        .expect("client verifies signature + freshness");

    // Client finds *its* client_hash in the allow list.
    let own_hash = allowlist_hash(&signed.record.salt, &client_pk.to_bytes());
    assert!(
        signed.record.allow.iter().any(|h| h[..] == own_hash[..]),
        "client hash present in allowlist"
    );

    // Client finds its ICE blob by matching on client_hash and decrypts it.
    let my_blob = signed
        .record
        .ice
        .iter()
        .find(|b| b.client_hash[..] == own_hash[..])
        .expect("ice blob for this client");
    let recovered = sealed_box_open(&client_x_sk, &my_blob.ciphertext).expect("unseal");
    assert_eq!(recovered, ice_plaintext);

    // Client sees the pinned DTLS fingerprint. In a real client it would
    // compare this against the fingerprint negotiated during the DTLS handshake.
    assert_eq!(signed.record.dtls_fp, dtls_fp);

    // --- Simulated channel binding (spec §8.3 step 9) -----------------------
    // In production the 32-byte exporter secret is pulled from the DTLS
    // session via RFC 5705. We simulate it here with a fixed value — the
    // test proves the *protocol* shape, not that the TLS exporter is wired up.
    let simulated_exporter_secret = [0x37u8; 32];
    let auth = auth_bytes(&simulated_exporter_secret).expect("auth_bytes");

    let host_auth_sig = host_sk.sign(&auth);
    let client_auth_sig = client_sk.sign(&auth);

    // Each side verifies the counterparty's signature against the pubkey it
    // already trusts (host: from the allowlist; client: from the Pkarr record).
    host_pk
        .verify(&auth, &host_auth_sig)
        .expect("host self-sanity");
    client_pk
        .verify(&auth, &client_auth_sig)
        .expect("client self-sanity");
    host_pk
        .verify(&auth, &host_auth_sig)
        .expect("client's view of host auth");
    client_pk
        .verify(&auth, &client_auth_sig)
        .expect("host's view of client auth");

    // --- HTTP-over-DataChannel exchange -------------------------------------
    // Client sends a GET.
    let req_head = Frame::new(
        FrameType::RequestHead,
        b"GET /library HTTP/1.1\r\nHost: home\r\n\r\n".to_vec(),
    )
    .unwrap();
    let req_end = Frame::new(FrameType::RequestEnd, vec![]).unwrap();

    let mut wire = Vec::new();
    req_head.encode(&mut wire);
    req_end.encode(&mut wire);

    // Daemon decodes the stream.
    let (d1, n1) = Frame::try_decode(&wire).unwrap().unwrap();
    let (d2, _) = Frame::try_decode(&wire[n1..]).unwrap().unwrap();
    assert_eq!(d1, req_head);
    assert_eq!(d2, req_end);

    // Daemon responds.
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

    // Client decodes the response.
    let (h, n1) = Frame::try_decode(&wire).unwrap().unwrap();
    let (b, n2) = Frame::try_decode(&wire[n1..]).unwrap().unwrap();
    let (e, _) = Frame::try_decode(&wire[n1 + n2..]).unwrap().unwrap();
    assert_eq!(h, resp_head);
    assert_eq!(b, resp_body);
    assert_eq!(e, resp_end);
}

#[test]
fn unpaired_client_cannot_read_ice_blobs() {
    let mut rng = rand::rngs::OsRng;
    let host_sk = SigningKey::generate(&mut rng);
    let paired_sk = SigningKey::generate(&mut rng);
    let unpaired_sk = SigningKey::generate(&mut rng);

    let paired_x_pk = public_key_to_x25519(&paired_sk.public_key()).unwrap();
    let unpaired_x_sk = signing_key_to_x25519(&unpaired_sk);

    let salt = [0xAA; SALT_LEN];
    let hash = allowlist_hash(&salt, &paired_sk.public_key().to_bytes());
    let ciphertext = sealed_box_seal(&mut rng, &paired_x_pk, b"secret ICE candidates");

    let record = OpenhostRecord {
        version: PROTOCOL_VERSION,
        ts: 1_700_000_000,
        dtls_fp: [0u8; 32],
        roles: "server".into(),
        salt,
        allow: vec![hash],
        ice: vec![IceBlob {
            client_hash: hash.to_vec(),
            ciphertext,
        }],
        disc: String::new(),
    };
    let signed = SignedRecord::sign(record, &host_sk).unwrap();

    // Signature verifies for anyone — records are public.
    signed.verify(&host_sk.public_key(), 1_700_000_000).unwrap();

    // But an unpaired client cannot open the sealed box.
    assert!(sealed_box_open(&unpaired_x_sk, &signed.record.ice[0].ciphertext).is_err());
}
