//! Cryptographic proof of an enrolled device's private key (source-only).
//!
//! This is NOT an enrollment authority, Keycloak verifier, certificate issuer,
//! durable trust store, transport listener or permission grant. The trusted key
//! inventory must come from an independently owner-approved, revocable store;
//! no untrusted network input may populate it. Only the authenticated transport
//! should deliver the fresh challenge and its response on the same connection.

use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{UnparsedPublicKey, ED25519},
};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const NONCE_LEN: usize = 32;
const MAX_DEVICES: usize = 1024;
const DOMAIN: &[u8] = b"relayforge-agent-session-proof-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceAuthError {
    InvalidConfiguration,
    InvalidDevice,
    DuplicateDevice,
    UnknownDevice,
    Revoked,
    Capacity,
    AlreadyPending,
    NotPending,
    InvalidChallenge,
    TransportMismatch,
    Expired,
    InvalidSignature,
    RandomUnavailable,
}

/// Opaque 32-byte TLS exporter output bound to a single verified connection.
///
/// The QUIC/WSS adapter must call its TLS 1.3 exporter with a dedicated
/// RelayForge exporter label and a stable context, on the *authenticated
/// connection*. Never construct this from a request body, peer header,
/// reusable key or network-supplied nonce. This type does not itself verify
/// TLS; there is no network-facing adapter in this source-only stage.
#[derive(Clone)]
pub struct TransportBinding([u8; 32]);

impl std::fmt::Debug for TransportBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportBinding([REDACTED])")
    }
}

impl PartialEq for TransportBinding {
    fn eq(&self, other: &Self) -> bool {
        matches_binding(&self.0, other)
    }
}

impl Eq for TransportBinding {}

impl TransportBinding {
    pub fn from_tls_exporter(output: [u8; 32]) -> Self {
        Self(output)
    }
}

fn matches_binding(a: &[u8; 32], b: &TransportBinding) -> bool {
    ring::constant_time::verify_slices_are_equal(a, &b.0).is_ok()
}

/// One owner-approved public key, loaded from trusted persistence.
/// Constructing this value is NOT itself permission to enroll a device.
#[derive(Debug, Clone)]
pub struct TrustedDevice {
    pub device_id: String,
    pub public_key: [u8; 32],
}

#[derive(Debug)]
struct DeviceRecord {
    public_key: [u8; 32],
    revoked: bool,
}

#[derive(Debug)]
struct PendingChallenge {
    nonce: [u8; NONCE_LEN],
    binding: TransportBinding,
    expires_at: Instant,
}

/// A challenge must be answered with an Ed25519 signature from the enrolled key.
#[derive(Debug, Clone)]
pub struct DeviceChallenge {
    device_id: String,
    nonce: [u8; NONCE_LEN],
    signing_bytes: Vec<u8>,
}

impl DeviceChallenge {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }
}

/// Successful one-time proof, scoped to the transport connection that
/// carried the challenge. This is not host-resource or actor authorization.
#[derive(PartialEq, Eq)]
pub struct VerifiedDevice {
    device_id: String,
    session_nonce: String,
    binding: TransportBinding,
    expires_at: Instant,
}

impl std::fmt::Debug for VerifiedDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedDevice")
            .field("device_id", &self.device_id)
            .field("session_nonce", &"[REDACTED]")
            .field("binding", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VerifiedDevice {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// The printable nonce derived from the signed challenge, for the
    /// coordinator's existing exact-session replay protections.
    pub fn session_nonce(&self) -> &str {
        &self.session_nonce
    }

    pub fn expires_at(&self) -> Instant {
        self.expires_at
    }

    pub fn matches_transport(&self, binding: &TransportBinding) -> bool {
        matches_binding(&self.binding.0, binding)
    }
}

fn nonce_hex(nonce: &[u8; NONCE_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(NONCE_LEN * 2);
    for byte in nonce {
        result.push(char::from(HEX[(*byte >> 4) as usize]));
        result.push(char::from(HEX[(*byte & 0x0f) as usize]));
    }
    result
}

/// In-memory proof state. Every pending challenge expires and is consumed at
/// most once. Restarting loses pending challenges (fail closed). Device
/// revocations are NOT durable here; production must reload authoritative,
/// durable revocation state and terminate existing sessions upon revocation.
pub struct DeviceAuthenticator {
    coordinator_id: String,
    devices: HashMap<String, DeviceRecord>,
    pending: HashMap<String, PendingChallenge>,
    max_pending: usize,
    challenge_ttl: Duration,
}

fn valid_id(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

fn signing_bytes(
    coordinator_id: &str,
    device_id: &str,
    nonce: &[u8; NONCE_LEN],
    binding: &TransportBinding,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + coordinator_id.len() + device_id.len() + 80);
    out.extend_from_slice(DOMAIN);
    for part in [
        coordinator_id.as_bytes(),
        device_id.as_bytes(),
        nonce.as_slice(),
        binding.0.as_slice(),
    ] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

impl DeviceAuthenticator {
    pub fn new(
        coordinator_id: &str,
        trusted: impl IntoIterator<Item = TrustedDevice>,
        max_pending: usize,
        challenge_ttl: Duration,
    ) -> Result<Self, DeviceAuthError> {
        if !valid_id(coordinator_id, 128)
            || !(1..=MAX_DEVICES).contains(&max_pending)
            || challenge_ttl.is_zero()
            || challenge_ttl > Duration::from_secs(120)
        {
            return Err(DeviceAuthError::InvalidConfiguration);
        }
        let mut devices = HashMap::new();
        for device in trusted {
            if !valid_id(&device.device_id, 128) {
                return Err(DeviceAuthError::InvalidDevice);
            }
            if devices.len() >= MAX_DEVICES {
                return Err(DeviceAuthError::Capacity);
            }
            if devices
                .insert(
                    device.device_id,
                    DeviceRecord {
                        public_key: device.public_key,
                        revoked: false,
                    },
                )
                .is_some()
            {
                return Err(DeviceAuthError::DuplicateDevice);
            }
        }
        Ok(Self {
            coordinator_id: coordinator_id.into(),
            devices,
            pending: HashMap::new(),
            max_pending,
            challenge_ttl,
        })
    }

    /// Only use with records already approved through the owner enrollment
    /// process. Challenges do not authorize a device or grant capabilities.
    pub fn begin(
        &mut self,
        device_id: &str,
        binding: &TransportBinding,
        now: Instant,
    ) -> Result<DeviceChallenge, DeviceAuthError> {
        match self.devices.get(device_id) {
            None => return Err(DeviceAuthError::UnknownDevice),
            Some(record) if record.revoked => return Err(DeviceAuthError::Revoked),
            Some(_) => {}
        }
        self.pending.retain(|_, p| now < p.expires_at);
        if self.pending.contains_key(device_id) {
            return Err(DeviceAuthError::AlreadyPending);
        }
        if self.pending.len() >= self.max_pending {
            return Err(DeviceAuthError::Capacity);
        }
        let mut nonce = [0; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| DeviceAuthError::RandomUnavailable)?;
        self.pending.insert(
            device_id.into(),
            PendingChallenge {
                nonce,
                binding: binding.clone(),
                expires_at: now + self.challenge_ttl,
            },
        );
        Ok(DeviceChallenge {
            device_id: device_id.into(),
            nonce,
            signing_bytes: signing_bytes(&self.coordinator_id, device_id, &nonce, binding),
        })
    }

    /// Consume the matching nonce before checking its signature: failed proof
    /// cannot be retried. An incorrect nonce does not consume the valid
    /// challenge, and never authenticates a device.
    pub fn complete(
        &mut self,
        device_id: &str,
        nonce: &[u8; NONCE_LEN],
        signature: &[u8],
        binding: &TransportBinding,
        now: Instant,
    ) -> Result<VerifiedDevice, DeviceAuthError> {
        let record = self
            .devices
            .get(device_id)
            .ok_or(DeviceAuthError::UnknownDevice)?;
        if record.revoked {
            return Err(DeviceAuthError::Revoked);
        }
        let pending = self
            .pending
            .get(device_id)
            .ok_or(DeviceAuthError::NotPending)?;
        if &pending.nonce != nonce {
            return Err(DeviceAuthError::InvalidChallenge);
        }
        if !matches_binding(&pending.binding.0, binding) {
            return Err(DeviceAuthError::TransportMismatch);
        }
        let pending = self
            .pending
            .remove(device_id)
            .ok_or(DeviceAuthError::NotPending)?;
        if now >= pending.expires_at {
            return Err(DeviceAuthError::Expired);
        }
        let payload = signing_bytes(&self.coordinator_id, device_id, nonce, binding);
        UnparsedPublicKey::new(&ED25519, record.public_key)
            .verify(&payload, signature)
            .map_err(|_| DeviceAuthError::InvalidSignature)?;
        Ok(VerifiedDevice {
            device_id: device_id.into(),
            session_nonce: nonce_hex(nonce),
            binding: pending.binding,
            expires_at: pending.expires_at,
        })
    }

    /// Synchronous in-memory invalidation only. Persist the revocation and
    /// disconnect currently active sessions in the future trusted adapter.
    pub fn revoke(&mut self, device_id: &str) -> Result<(), DeviceAuthError> {
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(DeviceAuthError::UnknownDevice)?;
        record.revoked = true;
        self.pending.remove(device_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn key(id: &str) -> (TrustedDevice, Ed25519KeyPair) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut public_key = [0; 32];
        public_key.copy_from_slice(pair.public_key().as_ref());
        (
            TrustedDevice {
                device_id: id.into(),
                public_key,
            },
            pair,
        )
    }

    fn binding() -> TransportBinding {
        TransportBinding::from_tls_exporter([3; 32])
    }

    fn auth(device: TrustedDevice) -> DeviceAuthenticator {
        DeviceAuthenticator::new("relayforge.ru0", [device], 2, Duration::from_secs(30)).unwrap()
    }

    #[test]
    fn genuine_one_time_proof_authenticates_only_registered_device() {
        let now = Instant::now();
        let (device, keypair) = key("thinkpad");
        let mut verifier = auth(device);
        let challenge = verifier.begin("thinkpad", &binding(), now).unwrap();
        assert_eq!(challenge.device_id(), "thinkpad");
        let sig = keypair.sign(challenge.signing_bytes());
        let verified = verifier
            .complete("thinkpad", challenge.nonce(), sig.as_ref(), &binding(), now)
            .unwrap();
        assert_eq!(verified.device_id(), "thinkpad");
        assert_eq!(verified.session_nonce(), nonce_hex(challenge.nonce()));
        assert!(matches!(
            verifier.complete("thinkpad", challenge.nonce(), sig.as_ref(), &binding(), now),
            Err(DeviceAuthError::NotPending)
        ));
    }

    #[test]
    fn unauthenticated_unknown_or_wrong_device_denied() {
        let now = Instant::now();
        let (device, keypair) = key("thinkpad");
        let mut verifier = auth(device);
        assert!(matches!(
            verifier.begin("unknown", &binding(), now),
            Err(DeviceAuthError::UnknownDevice)
        ));
        let challenge = verifier.begin("thinkpad", &binding(), now).unwrap();
        let sig = keypair.sign(challenge.signing_bytes());
        assert!(matches!(
            verifier.complete("unknown", challenge.nonce(), sig.as_ref(), &binding(), now),
            Err(DeviceAuthError::UnknownDevice)
        ));
        assert!(verifier
            .complete("thinkpad", challenge.nonce(), sig.as_ref(), &binding(), now)
            .is_ok());
    }

    #[test]
    fn wrong_key_and_cross_coordinator_replay_denied() {
        let now = Instant::now();
        let (device, owner) = key("thinkpad");
        let (_, attacker) = key("attacker");
        let mut verifier = auth(device);
        let challenge = verifier.begin("thinkpad", &binding(), now).unwrap();
        let bad = attacker.sign(challenge.signing_bytes());
        assert_eq!(
            verifier.complete("thinkpad", challenge.nonce(), bad.as_ref(), &binding(), now),
            Err(DeviceAuthError::InvalidSignature)
        );
        assert_eq!(
            verifier.complete("thinkpad", challenge.nonce(), bad.as_ref(), &binding(), now),
            Err(DeviceAuthError::NotPending)
        );
        let next = verifier.begin("thinkpad", &binding(), now).unwrap();
        let mismatched = signing_bytes("another.coordinator", "thinkpad", next.nonce(), &binding());
        let sig = owner.sign(&mismatched);
        assert_eq!(
            verifier.complete("thinkpad", next.nonce(), sig.as_ref(), &binding(), now),
            Err(DeviceAuthError::InvalidSignature)
        );
    }

    #[test]
    fn tls_exporter_is_redacted_from_debug_output() {
        let binder = TransportBinding::from_tls_exporter([0x5a; 32]);
        let display = format!("{binder:?}");
        assert_eq!(display, "TransportBinding([REDACTED])");
    }

    #[test]
    fn proof_is_bound_to_tls_exporter_and_is_not_consumed_by_other_connection() {
        let now = Instant::now();
        let (device, owner) = key("thinkpad");
        let mut verifier = auth(device);
        let original = binding();
        let other = TransportBinding::from_tls_exporter([9; 32]);
        let challenge = verifier.begin("thinkpad", &original, now).unwrap();
        let sig = owner.sign(challenge.signing_bytes());
        assert_eq!(
            verifier.complete("thinkpad", challenge.nonce(), sig.as_ref(), &other, now),
            Err(DeviceAuthError::TransportMismatch)
        );
        // The correct TLS connection can still complete exactly once.
        let verified = verifier
            .complete("thinkpad", challenge.nonce(), sig.as_ref(), &original, now)
            .unwrap();
        assert!(verified.matches_transport(&original));
        assert!(!verified.matches_transport(&other));
        assert_eq!(
            verifier.complete("thinkpad", challenge.nonce(), sig.as_ref(), &original, now),
            Err(DeviceAuthError::NotPending)
        );
    }

    #[test]
    fn expired_pending_proof_is_never_accepted() {
        let now = Instant::now();
        let (device, pair) = key("thinkpad");
        let mut verifier = auth(device);
        let challenge = verifier.begin("thinkpad", &binding(), now).unwrap();
        let sig = pair.sign(challenge.signing_bytes());
        assert_eq!(
            verifier.complete(
                "thinkpad",
                challenge.nonce(),
                sig.as_ref(),
                &binding(),
                now + Duration::from_secs(30)
            ),
            Err(DeviceAuthError::Expired)
        );
    }

    #[test]
    fn revocation_blocks_pending_and_new_proofs() {
        let now = Instant::now();
        let (device, pair) = key("thinkpad");
        let mut verifier = auth(device);
        let challenge = verifier.begin("thinkpad", &binding(), now).unwrap();
        let sig = pair.sign(challenge.signing_bytes());
        verifier.revoke("thinkpad").unwrap();
        assert_eq!(
            verifier.complete("thinkpad", challenge.nonce(), sig.as_ref(), &binding(), now),
            Err(DeviceAuthError::Revoked)
        );
        assert!(matches!(
            verifier.begin("thinkpad", &binding(), now),
            Err(DeviceAuthError::Revoked)
        ));
    }

    #[test]
    fn invalid_nonce_does_not_consume_valid_challenge() {
        let now = Instant::now();
        let (device, pair) = key("thinkpad");
        let mut verifier = auth(device);
        let challenge = verifier.begin("thinkpad", &binding(), now).unwrap();
        let sig = pair.sign(challenge.signing_bytes());
        assert_eq!(
            verifier.complete("thinkpad", &[0; NONCE_LEN], sig.as_ref(), &binding(), now),
            Err(DeviceAuthError::InvalidChallenge)
        );
        assert!(verifier
            .complete("thinkpad", challenge.nonce(), sig.as_ref(), &binding(), now)
            .is_ok());
    }

    #[test]
    fn bounded_pending_challenges_and_duplicate_device_ids() {
        let now = Instant::now();
        let (one, _) = key("one");
        let (two, _) = key("two");
        let mut verifier = DeviceAuthenticator::new(
            "relayforge.ru0",
            [one.clone(), two],
            1,
            Duration::from_secs(10),
        )
        .unwrap();
        verifier.begin("one", &binding(), now).unwrap();
        assert!(matches!(
            verifier.begin("one", &binding(), now),
            Err(DeviceAuthError::AlreadyPending)
        ));
        assert!(matches!(
            verifier.begin("two", &binding(), now),
            Err(DeviceAuthError::Capacity)
        ));
        verifier
            .begin("two", &binding(), now + Duration::from_secs(10))
            .unwrap();
        assert!(matches!(
            DeviceAuthenticator::new(
                "relayforge.ru0",
                [one.clone(), one],
                2,
                Duration::from_secs(10)
            ),
            Err(DeviceAuthError::DuplicateDevice)
        ));
    }

    #[test]
    fn identity_and_ttl_configuration_fail_closed() {
        let (device, _) = key("thinkpad");
        assert!(matches!(
            DeviceAuthenticator::new("", [device.clone()], 2, Duration::from_secs(10)),
            Err(DeviceAuthError::InvalidConfiguration)
        ));
        assert!(matches!(
            DeviceAuthenticator::new("ru0", [device.clone()], 0, Duration::from_secs(10)),
            Err(DeviceAuthError::InvalidConfiguration)
        ));
        assert!(matches!(
            DeviceAuthenticator::new("ru0", [device], 2, Duration::from_secs(121)),
            Err(DeviceAuthError::InvalidConfiguration)
        ));
    }

    #[test]
    fn key_is_bound_to_protocol_domain_and_coordinator() {
        let nonce = [7; NONCE_LEN];
        assert_ne!(
            signing_bytes("ru0", "device", &nonce, &binding()),
            signing_bytes("srv0", "device", &nonce, &binding())
        );
        assert_ne!(
            signing_bytes("ru0", "device", &nonce, &binding()),
            signing_bytes("ru0", "device2", &nonce, &binding())
        );
        assert!(signing_bytes("ru0", "device", &nonce, &binding()).starts_with(DOMAIN));
        assert_ne!(
            signing_bytes("ru0", "device", &nonce, &binding()),
            signing_bytes(
                "ru0",
                "device",
                &nonce,
                &TransportBinding::from_tls_exporter([4; 32])
            )
        );
    }
}
