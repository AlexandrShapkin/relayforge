//! Local-only authenticated Streamable HTTP MCP pilot.
//!
//! Static-token pilot and opt-in external-IdP OAuth protected resource.
//! Neither mode is a public listener, authorization server or TLS terminator.
//! Never change the bind IP from 127.0.0.1 without a security review.
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::{
    fs, io,
    net::{Ipv4Addr, SocketAddrV4},
    path::Path,
    sync::Arc,
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

const MAX_BODY: usize = 64 * 1024;
const MAX_INFLIGHT: usize = 8;
const DEFAULT_PORT: u16 = 8765;

#[derive(Clone)]
struct StateData {
    token: Arc<[u8]>,
    oauth: Option<Arc<crate::oauth::OAuth>>,
    local_authority: String,
    limiter: Arc<Semaphore>,
}

fn json_rpc_error(code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":null,
        "error":{"code":code,"message":message}})
}

fn failure(status: StatusCode, message: &'static str) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], message).into_response()
}

fn authenticated(headers: &HeaderMap, token: &[u8]) -> bool {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let bytes = value.as_bytes();
    let Some(candidate) = bytes.strip_prefix(b"Bearer ") else {
        return false;
    };
    candidate.len() == token.len() && bool::from(candidate.ct_eq(token))
}

// Axum response includes headers (including WWW-Authenticate) on failure.
#[allow(clippy::result_large_err)]
async fn check_access(headers: &HeaderMap, state: &StateData) -> Result<(), Response> {
    // Deny all browser Origin headers, including the localhost origin:
    // the pilot has no reason to permit browser requests or CORS.
    if headers.contains_key(header::ORIGIN) {
        return Err(failure(StatusCode::FORBIDDEN, "Origin not permitted"));
    }

    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if host != state.local_authority
        && host
            != format!(
                "localhost:{}",
                state.local_authority.rsplit(':').next().unwrap_or("")
            )
    {
        return Err(failure(StatusCode::FORBIDDEN, "Invalid host"));
    }
    if let Some(oauth) = &state.oauth {
        if let Err(rejection) = oauth.verify(headers).await {
            let (status, challenge) = oauth.challenge(&rejection);
            let mut response = failure(status, "OAuth authorization required or unavailable");
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, challenge);
            return Err(response);
        }
    } else if !authenticated(headers, &state.token) {
        let mut response = failure(StatusCode::UNAUTHORIZED, "Unauthorized");
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"relayforge-loopback\""),
        );
        return Err(response);
    }
    Ok(())
}

async fn protect(State(state): State<StateData>, request: Request, next: Next) -> Response {
    if let Err(response) = check_access(request.headers(), &state).await {
        return response;
    }
    next.run(request).await
}

#[allow(clippy::result_large_err)]
fn check_headers(headers: &HeaderMap) -> Result<(), Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if content_type != "application/json" && content_type != "application/json; charset=utf-8" {
        return Err(failure(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Expected application/json",
        ));
    }
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !accept.contains("application/json") || !accept.contains("text/event-stream") {
        return Err(failure(
            StatusCode::NOT_ACCEPTABLE,
            "Expected application/json and text/event-stream",
        ));
    }
    if let Some(version) = headers.get("mcp-protocol-version") {
        let version = version.to_str().unwrap_or("");
        if !["2025-03-26", "2025-06-18", "2025-11-25"].contains(&version) {
            return Err(failure(
                StatusCode::BAD_REQUEST,
                "Unsupported MCP protocol version",
            ));
        }
    }
    Ok(())
}

async fn post_mcp(State(state): State<StateData>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(result) = check_headers(&headers) {
        return result;
    }
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                [(header::CACHE_CONTROL, "no-store")],
                Json(json_rpc_error(-32700, "Parse error")),
            )
                .into_response()
        }
    };
    // The original 2024 protocol did not define Streamable HTTP. The modern
    // stateless 2026 era uses a different discovery and metadata envelope.
    if request.get("method").and_then(Value::as_str) == Some("initialize")
        && matches!(
            request
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str),
            Some("2024-11-05" | "2026-07-28")
        )
    {
        return failure(
            StatusCode::BAD_REQUEST,
            "Unsupported HTTP MCP handshake era",
        );
    }
    let Ok(permit) = state.limiter.clone().try_acquire_owned() else {
        return failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent requests",
        );
    };
    // Device/agent diagnostic calls spawn short-lived SSH processes; keep them
    // off the async executor and bound the number of concurrent operations.
    let restricted = state.oauth.is_some();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        if restricted {
            crate::stdio::handle_tunnel(&request)
        } else {
            crate::stdio::handle(&request)
        }
    });
    match tokio::time::timeout(Duration::from_secs(20), task).await {
        Ok(Ok(Some(response))) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(response),
        )
            .into_response(),
        Ok(Ok(None)) => {
            (StatusCode::ACCEPTED, [(header::CACHE_CONTROL, "no-store")]).into_response()
        }
        _ => failure(StatusCode::GATEWAY_TIMEOUT, "MCP request timed out"),
    }
}

async fn get_mcp() -> Response {
    failure(StatusCode::METHOD_NOT_ALLOWED, "SSE GET not supported")
}

async fn resource_metadata(State(state): State<StateData>) -> Response {
    match &state.oauth {
        Some(oauth) => (
            [(header::CACHE_CONTROL, "no-store")],
            Json(oauth.metadata()),
        )
            .into_response(),
        None => failure(StatusCode::NOT_FOUND, "Not found"),
    }
}

fn router_with_auth(token: Vec<u8>, oauth: Option<Arc<crate::oauth::OAuth>>, port: u16) -> Router {
    let state = StateData {
        token: Arc::from(token),
        oauth,
        local_authority: format!("127.0.0.1:{port}"),
        limiter: Arc::new(Semaphore::new(MAX_INFLIGHT)),
    };
    let protected = Router::new()
        .route("/mcp", post(post_mcp).get(get_mcp))
        .route_layer(middleware::from_fn_with_state(state.clone(), protect));
    let mut router = Router::new().merge(protected);
    if state.oauth.is_some() {
        router = router
            .route(
                "/.well-known/oauth-protected-resource",
                get(resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(resource_metadata),
            );
    }
    router
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

fn router(token: Vec<u8>, port: u16) -> Router {
    router_with_auth(token, None, port)
}

pub fn load_token(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "token path must be absolute",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "token file must be private regular file",
        ));
    }
    let bytes = fs::read(path)?;
    let token = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    // 256-bit entropy in lowercase hex, generated externally by OS CSPRNG.
    if token.len() != 64 || !token.iter().all(u8::is_ascii_hexdigit) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "token must be 64 hex characters",
        ));
    }
    Ok(token.to_vec())
}

pub async fn run_from_env() -> io::Result<()> {
    let path = std::env::var("RELAYFORGE_HTTP_TOKEN_FILE").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "RELAYFORGE_HTTP_TOKEN_FILE is required",
        )
    })?;
    let token = load_token(Path::new(&path))?;
    let port = port_from_env()?;
    serve(router(token, port), port).await
}

fn port_from_env() -> io::Result<u16> {
    let port: u16 = std::env::var("RELAYFORGE_HTTP_PORT")
        .unwrap_or_else(|_| DEFAULT_PORT.to_string())
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid RELAYFORGE_HTTP_PORT"))?;
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Zero port not allowed",
        ));
    }
    Ok(port)
}

pub async fn run_oauth_from_env() -> io::Result<()> {
    let path = std::env::var("RELAYFORGE_OAUTH_CONFIG_FILE")
        .map_err(|_| io::Error::other("RELAYFORGE_OAUTH_CONFIG_FILE is required"))?;
    // Configuration has no secrets; systemd supplies an immutable credential snapshot.
    let bytes = fs::read(path)?;
    if bytes.len() > 16384 {
        return Err(io::Error::other("OAuth config too large"));
    }
    let config =
        serde_json::from_slice(&bytes).map_err(|_| io::Error::other("Invalid OAuth config"))?;
    let port = port_from_env()?;
    let oauth = Arc::new(crate::oauth::OAuth::new(config, port).await?);
    serve(router_with_auth(Vec::new(), Some(oauth), port), port).await
}

async fn serve(app: Router, port: u16) -> io::Result<()> {
    let bind = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("RelayForge loopback MCP on http://127.0.0.1:{port}/mcp (NOT internet accessible)");
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn auth_state() -> StateData {
        StateData {
            oauth: None,
            token: Arc::from(
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_vec(),
            ),
            local_authority: "127.0.0.1:8765".into(),
            limiter: Arc::new(Semaphore::new(8)),
        }
    }
    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("127.0.0.1:8765"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static(
                "Bearer 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        );
        headers
    }
    #[tokio::test]
    async fn requires_auth_and_origin_protection() {
        let s = auth_state();
        assert!(check_access(&headers(), &s).await.is_ok());
        let mut missing = headers();
        missing.remove(header::AUTHORIZATION);
        assert!(check_access(&missing, &s).await.is_err());
        let mut wrong = headers();
        wrong.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(check_access(&wrong, &s).await.is_err());
        let mut origin = headers();
        origin.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://127.0.0.1:8765"),
        );
        assert!(check_access(&origin, &s).await.is_err());
        let mut rebinding = headers();
        rebinding.insert(header::HOST, HeaderValue::from_static("attacker.example"));
        assert!(check_access(&rebinding, &s).await.is_err());
    }
    #[test]
    fn rejects_bad_content_and_protocol_revision() {
        let mut wrong = headers();
        wrong.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert!(check_headers(&wrong).is_err());
        let mut version = headers();
        version.insert(
            "mcp-protocol-version",
            HeaderValue::from_static("2026-07-28"),
        );
        assert!(check_headers(&version).is_err());
    }
    #[test]
    fn rejects_non_private_token_paths() {
        assert!(load_token(Path::new("relative-token")).is_err());
    }
}

#[cfg(test)]
#[path = "http_oauth_tests.rs"]
mod oauth_tests;
