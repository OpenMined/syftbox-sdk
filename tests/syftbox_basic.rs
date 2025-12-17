use syftbox_sdk::{
    check_requests, send_response, Endpoint, RpcRequest, RpcResponse, SyftBoxApp, SyftURL,
};
use tempfile::TempDir;

#[test]
fn app_and_endpoint_round_trip_requests() {
    // Use plaintext backend for test isolation
    std::env::set_var("SYFTBOX_DISABLE_SYC", "1");
    // Allow checking responses in own folder for round-trip test
    std::env::set_var("SYFTBOX_INCLUDE_SELF_RESPONSES", "1");

    let tmp = TempDir::new().unwrap();
    let app = SyftBoxApp::new(tmp.path(), "user@example.com", "demo").unwrap();

    let endpoint_dir = app.register_endpoint("/message").unwrap();
    assert!(endpoint_dir.exists());
    let url = app.build_syft_url("/message");
    assert_eq!(
        url,
        "syft://user@example.com/app_data/demo/rpc/message".to_string()
    );

    let req = RpcRequest::new(
        "sender@example.com".into(),
        url.clone(),
        "POST".into(),
        b"hello".to_vec(),
    );
    let req_path = syftbox_sdk::syftbox::rpc::send_request(&app, "/message", &req).unwrap();
    assert!(req_path.exists());

    let pending = check_requests(&app, "/message").unwrap();
    assert_eq!(pending.len(), 1);
    let (found_path, found_req) = &pending[0];
    assert_eq!(found_req.decode_body().unwrap(), b"hello");

    let resp = RpcResponse::new(found_req, "user@example.com".into(), 200, b"ack".to_vec());
    send_response(&app, "/message", found_path, found_req, &resp, false).unwrap();
    assert!(!found_path.exists());

    let responses = Endpoint::new(&app, "/message")
        .unwrap()
        .check_responses()
        .unwrap();
    assert_eq!(responses.len(), 1);
}

#[test]
fn syft_url_parse_and_http_relay() {
    let syft = SyftURL::parse("syft://user@example.com/public/data/file.yaml#frag").unwrap();
    assert_eq!(syft.email, "user@example.com");
    assert_eq!(syft.path, "public/data/file.yaml");
    assert_eq!(syft.fragment.as_deref(), Some("frag"));

    let http = syft.to_http_relay_url("syftbox.net");
    assert_eq!(
        http,
        "https://syftbox.net/datasites/user@example.com/public/data/file.yaml#frag"
    );

    let round_tripped = SyftURL::from_http_relay_url(&http, "syftbox.net").unwrap();
    assert_eq!(round_tripped, syft);
}
