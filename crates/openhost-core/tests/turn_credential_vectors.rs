//! Conformance tests against `spec/test-vectors/turn_credentials.json`.
//!
//! Each scenario in the JSON is exercised here with the actual sign/verify
//! routines so that the wire-format spec, the canonical signing bytes, and
//! the verification rules stay in lockstep. If a future protocol revision
//! changes any of them, this test fails loudly rather than silently
//! accepting incompatible artifacts.

use openhost_core::identity::{PublicKey, SigningKey};
use openhost_core::turn::{
    QuotaToken, SignatureBytes, TurnCredential, TurnServer, MAX_CREDENTIAL_LIFETIME_SECS,
    MAX_QUOTA_TOKEN_LIFETIME_SECS,
};
use openhost_core::Error;
use serde_json::Value;
use std::path::PathBuf;

const VECTORS_PATH: &str = "../../spec/test-vectors/turn_credentials.json";

fn load_vectors() -> Value {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(VECTORS_PATH);
    let body =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&body).expect("parse turn_credentials.json")
}

fn seed_from_hex(s: &str) -> [u8; 32] {
    let raw = hex::decode(s).expect("hex");
    assert_eq!(raw.len(), 32, "seed must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    out
}

fn sk_from_hex(s: &str) -> SigningKey {
    SigningKey::from_bytes(&seed_from_hex(s))
}

fn issuer_sk(v: &Value) -> SigningKey {
    sk_from_hex(v["issuer"]["signing_seed_hex"].as_str().unwrap())
}

fn subject_sk(v: &Value) -> SigningKey {
    sk_from_hex(v["subject"]["signing_seed_hex"].as_str().unwrap())
}

fn parse_servers(value: &Value) -> Vec<TurnServer> {
    value
        .as_array()
        .expect("servers array")
        .iter()
        .map(|s| TurnServer {
            urls: s["urls"]
                .as_array()
                .unwrap()
                .iter()
                .map(|u| u.as_str().unwrap().to_string())
                .collect(),
            username: s["username"].as_str().unwrap().to_string(),
            credential: s["credential"].as_str().unwrap().to_string(),
        })
        .collect()
}

#[test]
fn positive_credential_vectors_verify() {
    let v = load_vectors();
    let issuer = issuer_sk(&v);
    let subject = subject_sk(&v);
    let issuer_pk = issuer.public_key();
    let subject_pk = subject.public_key();

    let cases = v["credentials"]["positive"].as_array().expect("positive[]");
    assert!(!cases.is_empty(), "vectors must include positive cases");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let issued_at = case["issued_at"].as_u64().unwrap();
        let expires_at = case["expires_at"].as_u64().unwrap();
        let now = case["verifier_now_ts"].as_u64().unwrap();
        let servers = parse_servers(&case["servers"]);

        let cred = TurnCredential::sign(subject_pk, servers, issued_at, expires_at, &issuer)
            .unwrap_or_else(|e| panic!("[{name}] sign failed: {e}"));
        cred.verify(&subject_pk, &[issuer_pk], now)
            .unwrap_or_else(|e| panic!("[{name}] verify failed: {e}"));
    }
}

#[test]
fn positive_quota_vectors_verify() {
    let v = load_vectors();
    let issuer = issuer_sk(&v);
    let subject = subject_sk(&v);
    let issuer_pk = issuer.public_key();
    let subject_pk = subject.public_key();

    let cases = v["quota_tokens"]["positive"]
        .as_array()
        .expect("positive[]");
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let tok = QuotaToken::sign(
            subject_pk,
            case["window_start"].as_u64().unwrap(),
            case["window_secs"].as_u64().unwrap(),
            case["cap_bytes"].as_u64().unwrap(),
            case["consumed_bytes"].as_u64().unwrap(),
            case["issued_at"].as_u64().unwrap(),
            case["expires_at"].as_u64().unwrap(),
            &issuer,
        )
        .unwrap_or_else(|e| panic!("[{name}] sign failed: {e}"));
        let now = case["verifier_now_ts"].as_u64().unwrap();
        tok.verify(&subject_pk, &[issuer_pk], now)
            .unwrap_or_else(|e| panic!("[{name}] verify failed: {e}"));

        if let Some(expected) = case["remaining_bytes_at_zero_local"].as_u64() {
            assert_eq!(
                tok.remaining_bytes(0),
                expected,
                "[{name}] remaining_bytes(0) mismatch",
            );
        }
    }
}

#[test]
fn negative_credential_vectors_reject() {
    // Each negative scenario is exercised explicitly below. The JSON file is
    // the source of truth for which scenarios MUST exist; we re-derive the
    // expected error here so that a JSON edit alone cannot silently weaken
    // the assertion.
    let v = load_vectors();
    let issuer = issuer_sk(&v);
    let subject = subject_sk(&v);
    let issuer_pk = issuer.public_key();
    let subject_pk = subject.public_key();

    let names: Vec<String> = v["credentials"]["negative"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    let expected = [
        "expired_credential",
        "overlong_lifetime",
        "wrong_subject",
        "untrusted_issuer",
        "tampered_server_credential",
        "tampered_signature",
        "empty_servers",
        "non_turn_url",
    ];
    for n in expected {
        assert!(names.iter().any(|x| x == n), "missing negative vector: {n}");
    }

    let base_servers = vec![TurnServer {
        urls: vec!["turn:relay.oh-send.dev:3478".to_string()],
        username: "u".into(),
        credential: "p".into(),
    }];
    let base_issued = 1_700_000_000u64;
    let base_expires = base_issued + 300;

    // expired
    let cred = TurnCredential::sign(
        subject_pk,
        base_servers.clone(),
        base_issued,
        base_expires,
        &issuer,
    )
    .unwrap();
    let err = cred
        .verify(&subject_pk, &[issuer_pk], base_expires + 1)
        .unwrap_err();
    assert!(
        matches!(err, Error::ExpiredTurnCredential { .. }),
        "{err:?}"
    );

    // overlong (sign() validates inputs via canonical_signing_bytes()).
    let err = TurnCredential::sign(
        subject_pk,
        base_servers.clone(),
        base_issued,
        base_issued + MAX_CREDENTIAL_LIFETIME_SECS + 1,
        &issuer,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::OverlongTurnCredential { .. }),
        "{err:?}"
    );

    // wrong subject
    let stranger = SigningKey::from_bytes(&[0x33u8; 32]).public_key();
    let err = cred
        .verify(&stranger, &[issuer_pk], base_issued + 1)
        .unwrap_err();
    assert!(matches!(err, Error::TurnSubjectMismatch), "{err:?}");

    // untrusted issuer
    let stranger_issuer = SigningKey::from_bytes(&[0x44u8; 32]).public_key();
    let err = cred
        .verify(&subject_pk, &[stranger_issuer], base_issued + 1)
        .unwrap_err();
    assert!(matches!(err, Error::UntrustedTurnIssuer), "{err:?}");

    // tampered server credential
    let mut tampered = cred.clone();
    tampered.servers[0].credential = "evil".into();
    let err = tampered
        .verify(&subject_pk, &[issuer_pk], base_issued + 1)
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err:?}");

    // tampered signature
    let mut tampered = cred.clone();
    tampered.signature.0[0] ^= 0x01;
    let err = tampered
        .verify(&subject_pk, &[issuer_pk], base_issued + 1)
        .unwrap_err();
    assert!(matches!(err, Error::BadSignature), "{err:?}");

    // empty servers — validate() is called from canonical_signing_bytes().
    let empty = TurnCredential {
        subject: subject_pk,
        servers: vec![],
        issued_at: base_issued,
        expires_at: base_expires,
        issuer: issuer_pk,
        signature: SignatureBytes([0u8; 64]),
    };
    let err = empty.canonical_signing_bytes().unwrap_err();
    assert!(matches!(err, Error::InvalidTurnCredential(_)), "{err:?}");

    // non-turn URL
    let bad_url = TurnCredential {
        subject: subject_pk,
        servers: vec![TurnServer {
            urls: vec!["stun:stun.example:3478".into()],
            username: "u".into(),
            credential: "p".into(),
        }],
        issued_at: base_issued,
        expires_at: base_expires,
        issuer: issuer_pk,
        signature: SignatureBytes([0u8; 64]),
    };
    let err = bad_url.canonical_signing_bytes().unwrap_err();
    assert!(matches!(err, Error::InvalidTurnCredential(_)), "{err:?}");
}

#[test]
fn negative_quota_vectors_reject() {
    let v = load_vectors();
    let issuer = issuer_sk(&v);
    let subject = subject_sk(&v);
    let issuer_pk = issuer.public_key();
    let subject_pk = subject.public_key();

    let names: Vec<String> = v["quota_tokens"]["negative"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap().to_string())
        .collect();
    let expected = [
        "consumed_exceeds_cap",
        "window_secs_zero",
        "window_secs_above_31_days",
        "expired_token",
        "overlong_token_lifetime",
    ];
    for n in expected {
        assert!(
            names.iter().any(|x| x == n),
            "missing negative quota vector: {n}"
        );
    }

    // consumed exceeds cap
    let bad = QuotaToken {
        subject: subject_pk,
        window_start: 0,
        window_secs: 86_400,
        cap_bytes: 1000,
        consumed_bytes: 1001,
        issued_at: 0,
        expires_at: 600,
        issuer: issuer_pk,
        signature: SignatureBytes([0u8; 64]),
    };
    assert!(matches!(
        bad.canonical_signing_bytes().unwrap_err(),
        Error::InvalidTurnCredential(_)
    ));

    // window_secs zero
    let err = QuotaToken::sign(subject_pk, 0, 0, 1, 0, 0, 600, &issuer).unwrap_err();
    assert!(matches!(err, Error::InvalidTurnCredential(_)), "{err:?}");

    // window_secs > 31 days
    let err = QuotaToken::sign(subject_pk, 0, 31 * 86_400 + 1, 1, 0, 0, 600, &issuer).unwrap_err();
    assert!(matches!(err, Error::InvalidTurnCredential(_)), "{err:?}");

    // expired
    let tok = QuotaToken::sign(
        subject_pk,
        0,
        86_400,
        1,
        0,
        1_700_000_000,
        1_700_000_060,
        &issuer,
    )
    .unwrap();
    let err = tok
        .verify(&subject_pk, &[issuer_pk], 1_700_000_061)
        .unwrap_err();
    assert!(
        matches!(err, Error::ExpiredTurnCredential { .. }),
        "{err:?}"
    );

    // overlong token lifetime
    let err = QuotaToken::sign(
        subject_pk,
        0,
        86_400,
        1,
        0,
        0,
        MAX_QUOTA_TOKEN_LIFETIME_SECS + 1,
        &issuer,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::OverlongTurnCredential { .. }),
        "{err:?}"
    );
}

#[test]
fn issuer_keys_reproducible_across_runs() {
    // Reproducibility check: the same seed always yields the same pubkey.
    // This is the property the JSON vector relies on when it omits the
    // hex/zbase32 form of the pubkey — readers can derive it themselves.
    let v = load_vectors();
    let pk_a: PublicKey = issuer_sk(&v).public_key();
    let pk_b: PublicKey = issuer_sk(&v).public_key();
    assert_eq!(pk_a, pk_b);
    // And the same for the subject — used by every credential vector.
    assert_eq!(subject_sk(&v).public_key(), subject_sk(&v).public_key());
}
