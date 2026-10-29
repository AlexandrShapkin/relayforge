//! Coordinator-side session bookkeeping. This is NOT authentication or a network transport.
//! Only an authenticated transport may call `register_authenticated`.
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    InvalidIdentity,
    InvalidNonce,
    DuplicateNonce,
    Replay,
    Expired,
    UnknownSession,
    Capacity,
}

#[derive(Debug, Clone)]
struct Session {
    device_id: String,
    expires_at: Instant,
    seen_requests: HashSet<String>,
}

pub struct Sessions {
    sessions: HashMap<String, Session>,
    // Retired nonces are remembered only for the session TTL. This provides a
    // bounded anti-replay window without permanently exhausting capacity.
    used_nonces: HashMap<String, Instant>,
    max_sessions: usize,
    max_nonce_history: usize,
    max_requests_per_session: usize,
    ttl: Duration,
}

impl Sessions {
    pub fn new(max_sessions: usize, max_requests_per_session: usize, ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            used_nonces: HashMap::new(),
            max_sessions,
            max_nonce_history: max_sessions.saturating_mul(32),
            max_requests_per_session,
            ttl,
        }
    }

    /// Called only after independently verifying device credentials.
    /// The caller supplies a cryptographically random, unpredictable nonce.
    pub fn register_authenticated(
        &mut self,
        device_id: &str,
        nonce: &str,
        now: Instant,
    ) -> Result<(), SessionError> {
        if !valid_device_id(device_id) {
            return Err(SessionError::InvalidIdentity);
        }
        if !valid_id(nonce) || nonce.len() < 32 {
            return Err(SessionError::InvalidNonce);
        }
        // Expired active sessions no longer consume capacity. Retired nonce
        // records are retained for one TTL then released; the caller must
        // still use fresh CSPRNG nonces when creating new sessions.
        self.sessions.retain(|_, session| now < session.expires_at);
        self.used_nonces.retain(|_, expiry| now < *expiry);
        if self.used_nonces.contains_key(nonce) {
            return Err(SessionError::DuplicateNonce);
        }
        if self.sessions.len() >= self.max_sessions
            || self.used_nonces.len() >= self.max_nonce_history
        {
            return Err(SessionError::Capacity);
        }
        self.used_nonces.insert(nonce.to_owned(), now + self.ttl);
        self.sessions.insert(
            nonce.to_owned(),
            Session {
                device_id: device_id.to_owned(),
                expires_at: now + self.ttl,
                seen_requests: HashSet::new(),
            },
        );
        Ok(())
    }

    pub fn accept_request(
        &mut self,
        nonce: &str,
        device_id: &str,
        request_id: &str,
        now: Instant,
    ) -> Result<(), SessionError> {
        if !valid_id(request_id) {
            return Err(SessionError::InvalidIdentity);
        }
        let session = self
            .sessions
            .get_mut(nonce)
            .ok_or(SessionError::UnknownSession)?;
        if now >= session.expires_at {
            return Err(SessionError::Expired);
        }
        if session.device_id != device_id {
            return Err(SessionError::InvalidIdentity);
        }
        if session.seen_requests.contains(request_id) {
            return Err(SessionError::Replay);
        }
        if session.seen_requests.len() >= self.max_requests_per_session {
            return Err(SessionError::Capacity);
        }
        session.seen_requests.insert(request_id.to_owned());
        Ok(())
    }

    /// Revocation removes the active session; its nonce remains blocked
    /// until the original expiry, even when new sessions can be created.
    pub fn revoke(&mut self, nonce: &str) {
        self.sessions.remove(nonce);
    }
}

/// Canonical device identity: 1–128 ASCII letters, digits, hyphens or underscores.
pub(crate) fn valid_device_id(value: &str) -> bool {
    valid_id(value)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sessions() -> Sessions {
        Sessions::new(2, 2, Duration::from_secs(30))
    }
    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn replay_and_cross_device_denied() {
        let now = Instant::now();
        let mut s = sessions();
        s.register_authenticated("device_a", NONCE, now).unwrap();
        assert_eq!(
            s.register_authenticated("device_a", NONCE, now),
            Err(SessionError::DuplicateNonce)
        );
        assert_eq!(
            s.accept_request(NONCE, "device_b", "r1", now),
            Err(SessionError::InvalidIdentity)
        );
        s.accept_request(NONCE, "device_a", "r1", now).unwrap();
        assert_eq!(
            s.accept_request(NONCE, "device_a", "r1", now),
            Err(SessionError::Replay)
        );
        s.accept_request(NONCE, "device_a", "r2", now).unwrap();
        assert_eq!(
            s.accept_request(NONCE, "device_a", "r3", now),
            Err(SessionError::Capacity)
        );
    }

    #[test]
    fn expiration_and_revocation_are_fail_closed() {
        let now = Instant::now();
        let mut s = sessions();
        s.register_authenticated("device_a", NONCE, now).unwrap();
        assert_eq!(
            s.accept_request(NONCE, "device_a", "r", now + Duration::from_secs(30)),
            Err(SessionError::Expired)
        );
        s.revoke(NONCE);
        assert_eq!(
            s.accept_request(NONCE, "device_a", "r", now),
            Err(SessionError::UnknownSession)
        );
        assert_eq!(
            s.register_authenticated("device_a", NONCE, now),
            Err(SessionError::DuplicateNonce)
        );
    }

    #[test]
    fn reconnects_after_revocation_do_not_exhaust_active_capacity() {
        let now = Instant::now();
        let mut s = Sessions::new(1, 2, Duration::from_secs(30));
        for index in 0..8 {
            let nonce = format!("session_{index:032}");
            s.register_authenticated("device_a", &nonce, now).unwrap();
            s.accept_request(&nonce, "device_a", "r", now).unwrap();
            s.revoke(&nonce);
            assert_eq!(
                s.register_authenticated("device_a", &nonce, now),
                Err(SessionError::DuplicateNonce),
            );
        }
        let next = "fresh_reconnect_nonce_0123456789abcdef";
        s.register_authenticated("device_a", next, now).unwrap();
    }

    #[test]
    fn expired_sessions_release_slots_and_replay_cache_is_bounded() {
        let start = Instant::now();
        let mut s = Sessions::new(1, 1, Duration::from_secs(5));
        s.register_authenticated("a", NONCE, start).unwrap();
        let next = "abcdef0123456789abcdef0123456789";
        s.register_authenticated("b", next, start + Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            s.accept_request(NONCE, "a", "r", start + Duration::from_secs(5)),
            Err(SessionError::UnknownSession)
        );
        assert_eq!(
            s.register_authenticated("b", next, start + Duration::from_secs(6)),
            Err(SessionError::DuplicateNonce)
        );
        s.revoke(next);
        // After its TTL the old nonce is no longer in the bounded history.
        // In production the authentication layer MUST generate fresh nonces.
        s.register_authenticated("a", NONCE, start + Duration::from_secs(11))
            .unwrap();
    }

    #[test]
    fn nonce_history_limits_burst_reconnections_without_permanent_lockout() {
        let now = Instant::now();
        let mut s = Sessions::new(1, 1, Duration::from_secs(10));
        for index in 0..32 {
            let nonce = format!("nonce_{index:032}");
            s.register_authenticated("a", &nonce, now).unwrap();
            s.revoke(&nonce);
        }
        assert_eq!(
            s.register_authenticated("a", "fresh_nonce_0123456789012345678901", now),
            Err(SessionError::Capacity)
        );
        s.register_authenticated(
            "a",
            "fresh_nonce_0123456789012345678901",
            now + Duration::from_secs(10),
        )
        .unwrap();
    }

    #[test]
    fn malformed_identifiers_and_capacity_denied() {
        let now = Instant::now();
        let mut s = Sessions::new(1, 1, Duration::from_secs(30));
        assert_eq!(
            s.register_authenticated("bad device", NONCE, now),
            Err(SessionError::InvalidIdentity)
        );
        assert_eq!(
            s.register_authenticated("device_a", "short", now),
            Err(SessionError::InvalidNonce)
        );
        s.register_authenticated("device_a", NONCE, now).unwrap();
        assert_eq!(
            s.register_authenticated("device_b", "abcdef0123456789abcdef0123456789", now),
            Err(SessionError::Capacity)
        );
        assert_eq!(
            s.accept_request(NONCE, "device_a", "bad request", now),
            Err(SessionError::InvalidIdentity)
        );
    }
}
