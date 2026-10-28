//! Inert, transport-neutral session router for *already authenticated* agents.
//!
//! This has no listener, transport, enrollment, credential verification,
//! forwarded actor identity or host operation executor. It cannot decide whether
//! an MCP actor is authorized to contact a device or operate on host resources.
//! Only a future verified gateway/transport adapter may call its public API.

use crate::device_auth::VerifiedDevice;
use crate::session::{SessionError, Sessions};
use relayforge_protocol::wire::{
    negotiate, Advertisement, Negotiated, RequestHeader, WireError, WireVersion,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    AlreadyConnected,
    Offline,
    Session(SessionError),
    Contract(WireError),
}

impl From<SessionError> for RouteError {
    fn from(value: SessionError) -> Self {
        Self::Session(value)
    }
}

impl From<WireError> for RouteError {
    fn from(value: WireError) -> Self {
        Self::Contract(value)
    }
}

struct ConnectedAgent {
    nonce: String,
    expires_at: Instant,
    contract: Negotiated,
}

/// Describes a validated dispatch target, not authorization to access
/// anything on that host. The agent independently checks every operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchTarget {
    device_id: String,
    request_id: String,
    wire_version: WireVersion,
    // Private binding to the authenticated connection that consumed this request ID.
    session_nonce: String,
}

impl DispatchTarget {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn wire_version(&self) -> WireVersion {
        self.wire_version
    }
}

/// In-memory, bounded routing and replay bookkeeping.
///
/// The caller must prove both ends' identities and the requester's allowed
/// **route** before calling. The router never authorizes target resources.
/// No fallback dispatch, offline queue or command replay is implemented.
pub struct SessionRouter {
    sessions: Sessions,
    agents: HashMap<String, ConnectedAgent>,
    ttl: Duration,
}

impl SessionRouter {
    pub fn new(max_agents: usize, max_requests_per_session: usize, ttl: Duration) -> Self {
        Self {
            sessions: Sessions::new(max_agents, max_requests_per_session, ttl),
            agents: HashMap::new(),
            ttl,
        }
    }

    /// Register an agent only after its owner-enrolled private key has
    /// answered a one-time challenge. Reuse the nonce that was signed;
    /// do not substitute a coordinator-generated or caller-selected nonce.
    ///
    /// The network adapter must still bind the challenge and response to
    /// the same verified TLS connection and check owner enrollment/revocation.
    /// This only proves device identity, never per-resource/actor permission.
    pub fn attach_verified(
        &mut self,
        verified: VerifiedDevice,
        coordinator: &Advertisement,
        agent: &Advertisement,
        now: Instant,
    ) -> Result<(), RouteError> {
        if now >= verified.expires_at() {
            return Err(RouteError::Session(SessionError::Expired));
        }
        self.attach_authenticated(
            verified.device_id(),
            verified.session_nonce(),
            coordinator,
            agent,
            now,
        )
    }

    /// Called only after independent cryptographic device authentication.
    /// The session nonce must be fresh CSPRNG output from the transport.
    /// Capability advertisement is not permission or proof of identity.
    fn attach_authenticated(
        &mut self,
        device_id: &str,
        nonce: &str,
        coordinator: &Advertisement,
        agent: &Advertisement,
        now: Instant,
    ) -> Result<(), RouteError> {
        let contract = negotiate(coordinator, agent)?;
        // Dead/expired connections never remain usable or block reconnection.
        self.agents
            .retain(|_, connection| now < connection.expires_at);
        if self.agents.contains_key(device_id) {
            return Err(RouteError::AlreadyConnected);
        }
        self.sessions
            .register_authenticated(device_id, nonce, now)?;
        self.agents.insert(
            device_id.to_owned(),
            ConnectedAgent {
                nonce: nonce.to_owned(),
                expires_at: now + self.ttl,
                contract,
            },
        );
        Ok(())
    }

    /// Caller must first validate the MCP actor, its scoped delegated identity,
    /// requested device access and transport binding. This method validates
    /// only the session and the negotiated request header, consuming its ID.
    /// A disconnected/expired host never stores work for later replay.
    pub fn prepare_after_gateway_authorization(
        &mut self,
        device_id: &str,
        header: &RequestHeader,
        now: Instant,
    ) -> Result<DispatchTarget, RouteError> {
        let agent = self.agents.get(device_id).ok_or(RouteError::Offline)?;
        if now >= agent.expires_at {
            return Err(RouteError::Offline);
        }
        header.validate(&agent.contract)?;
        self.sessions
            .accept_request(&agent.nonce, device_id, &header.request_id, now)?;
        Ok(DispatchTarget {
            device_id: device_id.to_owned(),
            request_id: header.request_id.clone(),
            wire_version: agent.contract.wire_version(),
            session_nonce: agent.nonce.clone(),
        })
    }

    /// Revalidate immediately before sending on the *same* authenticated transport
    /// connection identified by `connection_nonce`. A target prepared on an old
    /// session must never be sent via a newer connection for the same device.
    /// The adapter must not resolve the device ID again after this check.
    /// This is a session-binding check, not actor or resource authorization.
    pub fn validate_for_dispatch(
        &self,
        target: &DispatchTarget,
        connection_nonce: &str,
        now: Instant,
    ) -> Result<(), RouteError> {
        let agent = self
            .agents
            .get(&target.device_id)
            .ok_or(RouteError::Offline)?;
        if now >= agent.expires_at
            || agent.nonce != target.session_nonce
            || agent.nonce != connection_nonce
            || agent.contract.wire_version() != target.wire_version
        {
            return Err(RouteError::Offline);
        }
        Ok(())
    }

    /// Drops the active device route and revokes its session. It is safe for
    /// operators to call repeatedly; it does not remove device credentials.
    pub fn disconnect(&mut self, device_id: &str) {
        if let Some(agent) = self.agents.remove(device_id) {
            self.sessions.revoke(&agent.nonce);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_auth::{DeviceAuthenticator, TrustedDevice};
    use relayforge_protocol::wire::{OperationSchema, WireVersion};
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    const V1: WireVersion = WireVersion { major: 1, minor: 0 };
    const V2: WireVersion = WireVersion { major: 2, minor: 0 };
    const NONCE1: &str = "0123456789abcdef0123456789abcdef";
    const NONCE2: &str = "abcdef0123456789abcdef0123456789";

    fn advertisement(wire: WireVersion) -> Advertisement {
        Advertisement {
            versions: vec![wire],
            schemas: vec![OperationSchema {
                kind: "file".into(),
                action: "read".into(),
                version: 1,
            }],
            max_frame_bytes: 4096,
        }
    }

    fn header(id: &str) -> RequestHeader {
        RequestHeader {
            wire_version: V1,
            request_id: id.into(),
            kind: "file".into(),
            action: "read".into(),
            schema_version: 1,
            payload_bytes: 32,
            timeout_ms: 5000,
        }
    }

    fn router() -> SessionRouter {
        SessionRouter::new(2, 4, Duration::from_secs(30))
    }

    #[test]
    fn dispatch_only_for_attached_device_and_negotiated_schema() {
        let now = Instant::now();
        let mut r = router();
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        let target = r
            .prepare_after_gateway_authorization("device_a", &header("r1"), now)
            .unwrap();
        assert_eq!(target.device_id(), "device_a");
        assert_eq!(target.request_id(), "r1");
        assert_eq!(target.wire_version(), V1);
        assert_eq!(
            r.prepare_after_gateway_authorization("device_b", &header("r2"), now),
            Err(RouteError::Offline)
        );
    }

    #[test]
    fn rejected_request_does_not_consume_replay_id() {
        let now = Instant::now();
        let mut r = router();
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        let mut bad = header("r1");
        bad.action = "restart".into();
        assert_eq!(
            r.prepare_after_gateway_authorization("device_a", &bad, now),
            Err(RouteError::Contract(WireError::UnsupportedOperation))
        );
        assert!(r
            .prepare_after_gateway_authorization("device_a", &header("r1"), now)
            .is_ok());
        assert_eq!(
            r.prepare_after_gateway_authorization("device_a", &header("r1"), now),
            Err(RouteError::Session(SessionError::Replay))
        );
    }

    #[test]
    fn expired_or_disconnected_devices_cannot_receive_delayed_work() {
        let now = Instant::now();
        let mut r = router();
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        assert_eq!(
            r.prepare_after_gateway_authorization(
                "device_a",
                &header("late"),
                now + Duration::from_secs(30)
            ),
            Err(RouteError::Offline)
        );
        r.disconnect("device_a");
        assert_eq!(
            r.prepare_after_gateway_authorization("device_a", &header("r1"), now),
            Err(RouteError::Offline)
        );
    }

    #[test]
    fn no_common_protocol_never_registers_route() {
        let now = Instant::now();
        let mut r = router();
        assert_eq!(
            r.attach_authenticated(
                "device_a",
                NONCE1,
                &advertisement(V1),
                &advertisement(V2),
                now
            ),
            Err(RouteError::Contract(WireError::NoCommonVersion))
        );
        assert_eq!(
            r.prepare_after_gateway_authorization("device_a", &header("r1"), now),
            Err(RouteError::Offline)
        );
    }

    #[test]
    fn no_duplicate_route_or_nonce_replay() {
        let now = Instant::now();
        let mut r = router();
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        assert_eq!(
            r.attach_authenticated("device_a", NONCE2, &a, &a, now),
            Err(RouteError::AlreadyConnected)
        );
        assert_eq!(
            r.attach_authenticated("device_b", NONCE1, &a, &a, now),
            Err(RouteError::Session(SessionError::DuplicateNonce))
        );
        r.disconnect("device_a");
        assert_eq!(
            r.attach_authenticated("device_a", NONCE1, &a, &a, now),
            Err(RouteError::Session(SessionError::DuplicateNonce))
        );
        r.attach_authenticated("device_a", NONCE2, &a, &a, now)
            .unwrap();
    }

    #[test]
    fn reconnect_after_expiry_requires_fresh_nonce() {
        let now = Instant::now();
        let mut r = router();
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        r.attach_authenticated("device_a", NONCE2, &a, &a, now + Duration::from_secs(30))
            .unwrap();
        assert_eq!(
            r.prepare_after_gateway_authorization(
                "device_a",
                &header("r1"),
                now + Duration::from_secs(30)
            )
            .unwrap()
            .device_id(),
            "device_a"
        );
    }

    #[test]
    fn prepared_targets_cannot_cross_authenticated_reconnections_or_expiry() {
        let now = Instant::now();
        let mut r = router();
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        let old = r
            .prepare_after_gateway_authorization("device_a", &header("r1"), now)
            .unwrap();
        assert_eq!(r.validate_for_dispatch(&old, NONCE1, now), Ok(()));
        assert_eq!(
            r.validate_for_dispatch(&old, NONCE2, now),
            Err(RouteError::Offline)
        );

        r.disconnect("device_a");
        assert_eq!(
            r.validate_for_dispatch(&old, NONCE1, now),
            Err(RouteError::Offline)
        );
        r.attach_authenticated("device_a", NONCE2, &a, &a, now)
            .unwrap();
        // A previous target cannot be delivered through device_a's new session.
        assert_eq!(
            r.validate_for_dispatch(&old, NONCE2, now),
            Err(RouteError::Offline)
        );
        let current = r
            .prepare_after_gateway_authorization("device_a", &header("r1"), now)
            .unwrap();
        assert_eq!(r.validate_for_dispatch(&current, NONCE2, now), Ok(()));
        assert_eq!(
            r.validate_for_dispatch(&current, NONCE2, now + Duration::from_secs(30)),
            Err(RouteError::Offline)
        );
        // Expiry permits a fresh connection but cannot revive the old target.
        let fresh_nonce = "fedcba9876543210fedcba9876543210";
        r.attach_authenticated(
            "device_a",
            fresh_nonce,
            &a,
            &a,
            now + Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(
            r.validate_for_dispatch(&current, fresh_nonce, now + Duration::from_secs(30)),
            Err(RouteError::Offline)
        );
    }

    #[test]
    fn cryptographic_device_proof_can_bind_a_route_without_caller_nonce() {
        let now = Instant::now();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let device_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut public_key = [0; 32];
        public_key.copy_from_slice(device_key.public_key().as_ref());
        let mut verifier = DeviceAuthenticator::new(
            "relayforge.ru0",
            [TrustedDevice {
                device_id: "device_a".into(),
                public_key,
            }],
            2,
            Duration::from_secs(30),
        )
        .unwrap();
        let challenge = verifier.begin("device_a", now).unwrap();
        let signed = device_key.sign(challenge.signing_bytes());
        let verified = verifier
            .complete("device_a", challenge.nonce(), signed.as_ref(), now)
            .unwrap();
        let nonce = verified.session_nonce().to_owned();

        let mut r = router();
        let advertised = advertisement(V1);
        r.attach_verified(verified, &advertised, &advertised, now)
            .unwrap();
        let target = r
            .prepare_after_gateway_authorization("device_a", &header("r1"), now)
            .unwrap();
        assert_eq!(r.validate_for_dispatch(&target, &nonce, now), Ok(()));
        // A different connection nonce is rejected, even for the same device.
        assert_eq!(
            r.validate_for_dispatch(&target, NONCE1, now),
            Err(RouteError::Offline)
        );
    }

    #[test]
    fn old_verified_token_cannot_be_attached_after_challenge_expiry() {
        let now = Instant::now();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut public_key = [0; 32];
        public_key.copy_from_slice(pair.public_key().as_ref());
        let mut authenticator = DeviceAuthenticator::new(
            "relayforge.ru0",
            [TrustedDevice {
                device_id: "device_a".into(),
                public_key,
            }],
            2,
            Duration::from_secs(5),
        )
        .unwrap();
        let challenge = authenticator.begin("device_a", now).unwrap();
        let sig = pair.sign(challenge.signing_bytes());
        let verified = authenticator
            .complete("device_a", challenge.nonce(), sig.as_ref(), now)
            .unwrap();
        let mut r = router();
        let a = advertisement(V1);
        assert_eq!(
            r.attach_verified(verified, &a, &a, now + Duration::from_secs(5)),
            Err(RouteError::Session(SessionError::Expired))
        );
    }

    #[test]
    fn bounded_number_of_live_sessions() {
        let now = Instant::now();
        let mut r = SessionRouter::new(1, 1, Duration::from_secs(30));
        let a = advertisement(V1);
        r.attach_authenticated("device_a", NONCE1, &a, &a, now)
            .unwrap();
        assert_eq!(
            r.attach_authenticated("device_b", NONCE2, &a, &a, now),
            Err(RouteError::Session(SessionError::Capacity))
        );
    }
}
