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
    used_nonces: HashSet<String>,
    max_sessions: usize,
    max_requests_per_session: usize,
    ttl: Duration,
}

impl Sessions {
    pub fn new(max_sessions: usize, max_requests_per_session: usize, ttl: Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            used_nonces: HashSet::new(),
            max_sessions,
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
        if !valid_id(device_id) {
            return Err(SessionError::InvalidIdentity);
        }
        if !valid_id(nonce) || nonce.len() < 32 {
            return Err(SessionError::InvalidNonce);
        }
        if self.used_nonces.contains(nonce) {
            return Err(SessionError::DuplicateNonce);
        }
        if self.sessions.len() >= self.max_sessions || self.used_nonces.len() >= self.max_sessions {
            return Err(SessionError::Capacity);
        }
        self.used_nonces.insert(nonce.to_owned());
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

    /// Revocation removes the active session but retains its nonce to prevent reuse.
    pub fn revoke(&mut self, nonce: &str) {
        self.sessions.remove(nonce);
    }
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
