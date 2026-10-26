//! HTTP contract exercised through the actual Axum router and disposable issuer.
use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
};
use tower::ServiceExt;

async fn call(
    app: &Router,
    method: Method,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::HOST, "127.0.0.1:8765")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), MAX_BODY).await.unwrap()).unwrap()
}

#[tokio::test]
async fn oauth_http_discovery_and_bearer_challenges() {
    let f = crate::oauth::tests::fixture().await;
    let app = router_with_auth(Vec::new(), Some(f.oauth.clone()), 8765);
    for path in [
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
    ] {
        let r = call(&app, Method::GET, path, None, Value::Null).await;
        assert_eq!(r.status(), StatusCode::OK);
        let metadata = json_body(r).await;
        assert_eq!(metadata["resource"], "http://127.0.0.1:8765/mcp");
        assert_eq!(
            metadata["authorization_servers"],
            json!([f.oauth.config.issuer])
        );
        assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
    }
    for method in [Method::POST, Method::GET, Method::DELETE, Method::OPTIONS] {
        let r = call(&app, method, "/mcp", None, Value::Null).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        let challenge = r.headers()[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(challenge.contains(
            "resource_metadata=\"http://127.0.0.1:8765/.well-known/oauth-protected-resource/mcp\""
        ));
        assert!(challenge.contains("scope=\"mcp:read\""));
        assert!(!challenge.contains("error="));
    }
    let token = f.token(f.claims(), "key1");
    let r = call(
        &app,
        Method::POST,
        &format!("/mcp?access_token={token}"),
        None,
        Value::Null,
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = call(&app, Method::GET, "/mcp", Some("malformed"), Value::Null).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(r.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .contains("error=\"invalid_token\""));
    let mut c = f.claims();
    c["scope"] = json!("other");
    let r = call(
        &app,
        Method::POST,
        "/mcp",
        Some(&f.token(c, "key1")),
        Value::Null,
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(r.headers()[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .contains("error=\"insufficient_scope\""));
}

#[tokio::test]
async fn oauth_http_mcp_handshake_and_restricted_tools() {
    let f = crate::oauth::tests::fixture().await;
    let app = router_with_auth(Vec::new(), Some(f.oauth.clone()), 8765);
    let token = f.token(f.claims(), "key1");
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"offline-test","version":"1"}}});
    let r = call(&app, Method::POST, "/mcp", Some(&token), init).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        json_body(r).await["result"]["protocolVersion"],
        "2025-11-25"
    );
    let r = call(
        &app,
        Method::POST,
        "/mcp",
        Some(&token),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await;
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let r = call(
        &app,
        Method::POST,
        "/mcp",
        Some(&token),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let tools = json_body(r).await;
    assert!(tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "relayforge_status"));
    assert!(!tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "relayforge_local_exec"));
    let r=call(&app,Method::POST,"/mcp",Some(&token),json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"relayforge_status","arguments":{}}})).await;
    let status = json_body(r).await;
    assert!(status.get("result").is_some());
    let r=call(&app,Method::POST,"/mcp",Some(&token),json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"not-allowlisted","arguments":{}}})).await;
    assert_eq!(
        json_body(r).await["error"]["message"],
        "Tool denied by tunnel policy"
    );
    assert_eq!(
        call(&app, Method::GET, "/mcp", Some(&token), Value::Null)
            .await
            .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
    for (name, value) in [
        (header::HOST, "attacker.example"),
        (header::ORIGIN, "https://attacker.example"),
    ] {
        let request = Request::builder()
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1:8765")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let mut request = request;
        request
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
}
