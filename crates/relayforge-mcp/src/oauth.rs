//! OAuth protected resource only. The external provider owns login, PKCE,
//! consent, registration, token issuance and refresh; no credentials go upstream.
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{
    io,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const KEY_TTL: Duration = Duration::from_secs(300);
const RETRY_INTERVAL: Duration = Duration::from_secs(30);
const MAX_DOCUMENT: usize = 64 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub issuer: String,
    /// Canonical client-facing MCP resource URI (the HTTPS tunnel endpoint).
    pub resource: String,
    pub scopes: Vec<String>,
    /// Immutable provider subject of the single permitted owner.
    pub subject: String,
}

fn invalid() -> io::Error {
    // Never include tokens, documents, tenant paths or reqwest diagnostics.
    io::Error::other("OAuth configuration or provider metadata unavailable/invalid")
}

fn url(value: &str, test_http: bool) -> io::Result<reqwest::Url> {
    let u = reqwest::Url::parse(value).map_err(|_| invalid())?;
    let loopback = test_http && u.scheme() == "http" && u.host_str() == Some("127.0.0.1");
    if (u.scheme() != "https" && !loopback)
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err(invalid());
    }
    Ok(u)
}

impl Config {
    fn validate(&self) -> io::Result<()> {
        url(&self.issuer, cfg!(test))?;
        url(&self.resource, false)?;
        if self.subject.is_empty()
            || self.scopes.is_empty()
            || self.scopes.iter().any(|s| {
                s.is_empty()
                    || !s
                        .bytes()
                        .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    jwks_uri: String,
}

struct Keys {
    set: JwkSet,
    fetched: Instant,
    next_attempt: Instant,
}

pub(crate) struct OAuth {
    pub config: Config,
    client: reqwest::Client,
    keys: Mutex<Keys>,
    metadata_url: String,
    local_resource: String,
}

#[derive(Debug, PartialEq)]
pub(crate) enum Rejection {
    Missing,
    Invalid,
    Scope,
    Unavailable,
}

async fn document<T: DeserializeOwned>(client: &reqwest::Client, uri: &str) -> io::Result<T> {
    let mut response = client
        .get(uri)
        .send()
        .await
        .map_err(|_| invalid())?
        .error_for_status()
        .map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
        if bytes.len() + chunk.len() > MAX_DOCUMENT {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

async fn fetch_keys(client: &reqwest::Client, config: &Config) -> io::Result<JwkSet> {
    let metadata: Metadata = document(
        client,
        &format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        ),
    )
    .await?;
    let issuer = url(&config.issuer, cfg!(test))?;
    let jwks = url(&metadata.jwks_uri, cfg!(test))?;
    if metadata.issuer != config.issuer || jwks.origin() != issuer.origin() {
        return Err(invalid());
    }
    let set: JwkSet = document(client, jwks.as_str()).await?;
    if set.keys.is_empty() {
        return Err(invalid());
    }
    Ok(set)
}

impl OAuth {
    pub async fn new(config: Config, port: u16) -> io::Result<Self> {
        config.validate()?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!cfg!(test))
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| invalid())?;
        let set = fetch_keys(&client, &config).await?;
        Ok(Self {
            config,
            client,
            keys: Mutex::new(Keys {
                set,
                fetched: Instant::now(),
                next_attempt: Instant::now() + RETRY_INTERVAL,
            }),
            local_resource: format!("http://127.0.0.1:{port}/mcp"),
            metadata_url: format!(
                "http://127.0.0.1:{port}/.well-known/oauth-protected-resource/mcp"
            ),
        })
    }

    pub fn metadata(&self) -> Value {
        json!({"resource": self.local_resource, "authorization_servers": [self.config.issuer],
            "scopes_supported": self.config.scopes, "bearer_methods_supported": ["header"]})
    }

    pub fn challenge(&self, rejection: &Rejection) -> (StatusCode, HeaderValue) {
        let (status, error) = match rejection {
            Rejection::Missing => (StatusCode::UNAUTHORIZED, ""),
            Rejection::Invalid => (StatusCode::UNAUTHORIZED, ", error=\"invalid_token\""),
            Rejection::Scope => (StatusCode::FORBIDDEN, ", error=\"insufficient_scope\""),
            Rejection::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, ""),
        };
        // Config scopes validated as RFC 6749 scope-tokens; URL is fixed loopback.
        let value = format!(
            "Bearer resource_metadata=\"{}\", scope=\"{}\"{}",
            self.metadata_url,
            self.config.scopes.join(" "),
            error
        );
        (
            status,
            HeaderValue::from_str(&value).expect("validated OAuth challenge"),
        )
    }

    pub async fn verify(&self, headers: &HeaderMap) -> Result<(), Rejection> {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let value = values.next().ok_or(Rejection::Missing)?;
        if values.next().is_some() {
            return Err(Rejection::Invalid);
        }
        let (scheme, token) = value
            .to_str()
            .map_err(|_| Rejection::Invalid)?
            .split_once(' ')
            .ok_or(Rejection::Invalid)?;
        if !scheme.eq_ignore_ascii_case("Bearer") || token.len() > 16384 || token.is_empty() {
            return Err(Rejection::Invalid);
        }
        let header = decode_header(token).map_err(|_| Rejection::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(Rejection::Invalid);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|k| !k.is_empty())
            .ok_or(Rejection::Invalid)?;
        let key = {
            let mut keys = self.keys.lock().await;
            let stale = keys.fetched.elapsed() >= KEY_TTL;
            if (stale || keys.set.find(kid).is_none()) && Instant::now() >= keys.next_attempt {
                keys.next_attempt = Instant::now() + RETRY_INTERVAL;
                match fetch_keys(&self.client, &self.config).await {
                    Ok(set) => {
                        keys.set = set;
                        keys.fetched = Instant::now();
                    }
                    Err(_) => return Err(Rejection::Unavailable),
                }
            }
            // Never keep accepting indefinitely during a provider outage.
            if keys.fetched.elapsed() >= KEY_TTL {
                return Err(Rejection::Unavailable);
            }
            let jwk = keys.set.find(kid).ok_or(Rejection::Invalid)?;
            if jwk
                .common
                .key_algorithm
                .is_some_and(|a| a != jsonwebtoken::jwk::KeyAlgorithm::RS256)
                || jwk
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|u| *u != jsonwebtoken::jwk::PublicKeyUse::Signature)
                || jwk
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|ops| !ops.contains(&jsonwebtoken::jwk::KeyOperations::Verify))
            {
                return Err(Rejection::Invalid);
            }
            DecodingKey::from_jwk(jwk).map_err(|_| Rejection::Invalid)?
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.resource]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.sub = Some(self.config.subject.clone());
        validation.validate_nbf = true;
        validation.leeway = 0;
        validation.reject_tokens_expiring_in_less_than = 1;
        #[derive(Deserialize)]
        struct Claims {
            scope: Option<String>,
            typ: String,
        }
        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|_| Rejection::Invalid)?
            .claims;
        // Keycloak access tokens carry typ=Bearer; ID/refresh tokens are refused.
        if claims.typ != "Bearer" {
            return Err(Rejection::Invalid);
        }
        let scope = claims.scope.unwrap_or_default();
        if !self
            .config
            .scopes
            .iter()
            .all(|required| scope.split(' ').any(|s| s == required))
        {
            return Err(Rejection::Scope);
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{extract::State, routing::get, Json, Router};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::io::Write;
    use std::{
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, OnceLock,
        },
    };

    // Disposable CI keypair generated in memory, never a checked-in private key.
    fn signing_key() -> &'static (EncodingKey, String) {
        static KEY: OnceLock<(EncodingKey, String)> = OnceLock::new();
        KEY.get_or_init(|| {
            let result = Command::new("openssl")
                .args([
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                ])
                .stderr(Stdio::null())
                .output()
                .unwrap();
            assert!(result.status.success());
            let mut child = Command::new("openssl")
                .args(["rsa", "-modulus", "-noout"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&result.stdout)
                .unwrap();
            let modulus = child.wait_with_output().unwrap();
            assert!(modulus.status.success());
            let hex = std::str::from_utf8(&modulus.stdout)
                .unwrap()
                .trim()
                .strip_prefix("Modulus=")
                .unwrap();
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let mut der = Command::new("openssl")
                .args(["rsa", "-traditional", "-outform", "DER"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            der.stdin.take().unwrap().write_all(&result.stdout).unwrap();
            let der = der.wait_with_output().unwrap();
            assert!(der.status.success());
            (
                EncodingKey::from_rsa_der(&der.stdout),
                URL_SAFE_NO_PAD.encode(bytes),
            )
        })
    }

    pub(crate) struct Fixture {
        pub oauth: Arc<OAuth>,
        pub offline: Arc<AtomicBool>,
        pub jwks: Arc<Mutex<Value>>,
        task: tokio::task::JoinHandle<()>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }
    impl Fixture {
        pub fn claims(&self) -> Value {
            json!({"iss":self.oauth.config.issuer,"aud":self.oauth.config.resource,
                "sub":"owner-subject", "exp":jsonwebtoken::get_current_timestamp()+300,
                "nbf":jsonwebtoken::get_current_timestamp()-1,"scope":"mcp:read other", "typ":"Bearer"})
        }
        pub fn token(&self, claims: Value, kid: &str) -> String {
            let mut h = Header::new(Algorithm::RS256);
            h.kid = Some(kid.into());
            encode(&h, &claims, &signing_key().0).unwrap()
        }
        pub fn headers(&self, claims: Value, kid: &str) -> HeaderMap {
            let mut h = HeaderMap::new();
            h.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", self.token(claims, kid))).unwrap(),
            );
            h
        }
    }
    pub(crate) async fn fixture() -> Fixture {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let jwks = Arc::new(Mutex::new(
            json!({"keys":[{"kty":"RSA","kid":"key1","use":"sig","alg":"RS256","n":signing_key().1,"e":"AQAB"}]}),
        ));
        let offline = Arc::new(AtomicBool::new(false));
        let metadata = json!({"issuer":issuer,"jwks_uri":format!("{issuer}/jwks")});
        let app = Router::new().route("/.well-known/openid-configuration",get(move || {
            let metadata = metadata.clone(); async move { Json(metadata) }
        })).route("/jwks",get(|State((jwks,offline)):State<(Arc<Mutex<Value>>,Arc<AtomicBool>)>| async move {
            if offline.load(Ordering::SeqCst) { return (StatusCode::SERVICE_UNAVAILABLE,Json(json!({}))); }
            (StatusCode::OK,Json(jwks.lock().await.clone()))
        })).with_state((jwks.clone(),offline.clone()));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = Config {
            issuer,
            resource: "https://tunnel.example/v1/mcp/test".into(),
            scopes: vec!["mcp:read".into()],
            subject: "owner-subject".into(),
        };
        let oauth = Arc::new(OAuth::new(config, 8765).await.unwrap());
        Fixture {
            oauth,
            offline,
            jwks,
            task,
        }
    }

    #[tokio::test]
    async fn oauth_signature_claims_and_scopes_fail_closed() {
        let f = fixture().await;
        assert_eq!(f.oauth.verify(&f.headers(f.claims(), "key1")).await, Ok(()));
        for (field, value) in [
            ("iss", json!("https://wrong.example")),
            ("aud", json!("https://wrong.example")),
            ("sub", json!("another-owner")),
            ("exp", json!(jsonwebtoken::get_current_timestamp() - 1)),
            ("nbf", json!(jsonwebtoken::get_current_timestamp() + 300)),
            ("typ", json!("ID")),
            ("exp", json!("not-a-time")),
        ] {
            let mut c = f.claims();
            c[field] = value;
            assert_eq!(
                f.oauth.verify(&f.headers(c, "key1")).await,
                Err(Rejection::Invalid),
                "{field}"
            );
        }
        for field in ["iss", "aud", "exp", "sub", "typ"] {
            let mut c = f.claims();
            c.as_object_mut().unwrap().remove(field);
            assert_eq!(
                f.oauth.verify(&f.headers(c, "key1")).await,
                Err(Rejection::Invalid),
                "missing {field}"
            );
        }
        for scope in [json!("mcp:reader"), json!("other"), Value::Null] {
            let mut c = f.claims();
            c["scope"] = scope;
            assert_eq!(
                f.oauth.verify(&f.headers(c, "key1")).await,
                Err(Rejection::Scope)
            );
        }
        let mut c = f.claims();
        c["aud"] = json!(["other", f.oauth.config.resource]);
        assert_eq!(f.oauth.verify(&f.headers(c, "key1")).await, Ok(()));
        let mut h = f.headers(f.claims(), "unknown");
        assert_eq!(f.oauth.verify(&h).await, Err(Rejection::Invalid));
        h.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer duplicate"),
        );
        assert_eq!(f.oauth.verify(&h).await, Err(Rejection::Invalid));
        let mut bad = Header::new(Algorithm::HS256);
        bad.kid = Some("key1".into());
        let token = encode(
            &bad,
            &f.claims(),
            &EncodingKey::from_secret(b"not-a-public-key"),
        )
        .unwrap();
        h.clear();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert_eq!(f.oauth.verify(&h).await, Err(Rejection::Invalid));
        let token = f.token(f.claims(), "key1");
        let mut parts: Vec<_> = token.split('.').map(str::to_owned).collect();
        let mut forged = f.claims();
        forged["extra"] = json!("tampered");
        parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", parts.join("."))).unwrap(),
        );
        assert_eq!(f.oauth.verify(&h).await, Err(Rejection::Invalid));
    }

    #[tokio::test]
    async fn oauth_rotation_outage_and_cache_expiry() {
        let f = fixture().await;
        f.jwks.lock().await["keys"][0]["kid"] = json!("key2");
        f.oauth.keys.lock().await.next_attempt = Instant::now();
        assert_eq!(f.oauth.verify(&f.headers(f.claims(), "key2")).await, Ok(()));
        assert_eq!(
            f.oauth.verify(&f.headers(f.claims(), "key1")).await,
            Err(Rejection::Invalid)
        );
        f.offline.store(true, Ordering::SeqCst);
        // Bounded fresh cache works without the provider; expired keys do not.
        assert_eq!(f.oauth.verify(&f.headers(f.claims(), "key2")).await, Ok(()));
        {
            let mut keys = f.oauth.keys.lock().await;
            keys.fetched = Instant::now() - KEY_TTL;
            keys.next_attempt = Instant::now();
        }
        assert_eq!(
            f.oauth.verify(&f.headers(f.claims(), "key2")).await,
            Err(Rejection::Unavailable)
        );
        assert_eq!(
            f.oauth.verify(&f.headers(f.claims(), "key2")).await,
            Err(Rejection::Unavailable)
        );
        f.offline.store(false, Ordering::SeqCst);
        f.oauth.keys.lock().await.next_attempt = Instant::now();
        assert_eq!(f.oauth.verify(&f.headers(f.claims(), "key2")).await, Ok(()));
    }

    #[tokio::test]
    async fn oauth_configuration_is_explicit_and_discovery_is_pinned() {
        let f = fixture().await;
        for issuer in [
            "http://idp.example/realm",
            "https://user:pass@idp.example/realm",
            "https://idp.example/realm?x=1",
            "https://idp.example/#fragment",
        ] {
            let mut c = f.oauth.config.clone();
            c.issuer = issuer.into();
            assert!(c.validate().is_err());
        }
        let mut c = f.oauth.config.clone();
        c.scopes = vec!["bad\"scope".into()];
        assert!(c.validate().is_err());
        let mut c = f.oauth.config.clone();
        c.subject.clear();
        assert!(c.validate().is_err());
        // A discovered document cannot redirect verification to another issuer.
        let mut c = f.oauth.config.clone();
        c.issuer.push('/');
        assert!(OAuth::new(c, 8765).await.is_err());
    }
}
