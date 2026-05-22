use bytes::Bytes;
use openhost_daemon::config::ForwardConfig;
use openhost_daemon::error::ForwardError;
use openhost_daemon::forward::Forwarder;

#[tokio::test]
async fn test_whitespace_before_colon_in_header_rejected() {
    let cfg = ForwardConfig {
        target: Some("http://127.0.0.1:8080".into()),
        host_override: None,
        max_body_bytes: 1024,
        websockets: None,
    };
    let fwd = Forwarder::from_config(&cfg).unwrap().unwrap();

    // Header with space before colon: "Host : example.com"
    let head = b"GET / HTTP/1.1\r\nHost : 127.0.0.1:8080\r\n\r\n";
    let body = Bytes::new();

    let result = fwd.forward(head, body).await;
    assert!(matches!(
        result,
        Err(ForwardError::HeadParse(
            "header field-name MUST NOT be followed by whitespace"
        ))
    ));
}

#[tokio::test]
async fn test_leading_whitespace_in_header_rejected() {
    let cfg = ForwardConfig {
        target: Some("http://127.0.0.1:8080".into()),
        host_override: None,
        max_body_bytes: 1024,
        websockets: None,
    };
    let fwd = Forwarder::from_config(&cfg).unwrap().unwrap();

    // Leading whitespace (obsolete line folding)
    let head = b"GET / HTTP/1.1\r\n Host: 127.0.0.1:8080\r\n\r\n";
    let body = Bytes::new();

    let result = fwd.forward(head, body).await;
    assert!(matches!(
        result,
        Err(ForwardError::HeadParse(
            "obsolete line folding (OBS-fold) is not supported"
        ))
    ));
}
