//! Transport-independent negotiation for future outbound agents.
//!
//! This module is an **inert protocol model**, not an authenticated transport,
//! a serializer, a device enrollment implementation, or a permission grant.
//! The existing SSH/stdio pilot remains unchanged. In particular, the
//! legacy PROTOCOL_VERSION is not a negotiated network protocol version.

use std::collections::{BTreeMap, BTreeSet};

const MAX_PROTOCOL_VERSIONS: usize = 16;
const MAX_OPERATION_SCHEMAS: usize = 128;
pub const MAX_FRAME_BYTES: u32 = 256 * 1024;
pub const MAX_REQUEST_TIMEOUT_MS: u32 = 60_000;

/// Exact supported wire format. No implicit backwards-compatibility assumption:
/// an endpoint must advertise every version it can actually decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WireVersion {
    pub major: u16,
    pub minor: u16,
}

/// One specific, fully validated typed operation schema.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OperationSchema {
    pub kind: String,
    pub action: String,
    pub version: u16,
}

/// A peer's declared *implementation support*, not its effective permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    pub versions: Vec<WireVersion>,
    pub schemas: Vec<OperationSchema>,
    pub max_frame_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A validated common contract. Consumers can inspect it, but cannot
/// fabricate a session by constructing arbitrary negotiated capabilities.
/// This is implementation support only, **not** an authorization grant.
pub struct Negotiated {
    wire_version: WireVersion,
    schemas: Vec<OperationSchema>,
    max_frame_bytes: u32,
}

impl Negotiated {
    pub fn wire_version(&self) -> WireVersion {
        self.wire_version
    }

    pub fn schemas(&self) -> &[OperationSchema] {
        &self.schemas
    }

    pub fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    InvalidAdvertisement,
    NoCommonVersion,
    UnsupportedOperation,
    InvalidRequest,
}

fn valid_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.split('.').all(|segment| {
        let bytes = segment.as_bytes();
        !bytes.is_empty()
            && bytes[0].is_ascii_lowercase()
            && bytes[1..]
                .iter()
                .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    })
}

fn valid_request_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Advertisement {
    pub fn validate(&self) -> Result<(), WireError> {
        if self.versions.is_empty()
            || self.versions.len() > MAX_PROTOCOL_VERSIONS
            || self.schemas.len() > MAX_OPERATION_SCHEMAS
            || !(1..=MAX_FRAME_BYTES).contains(&self.max_frame_bytes)
            || self.versions.iter().any(|v| v.major == 0)
            || self
                .schemas
                .iter()
                .any(|s| s.version == 0 || !valid_name(&s.kind) || !valid_name(&s.action))
        {
            return Err(WireError::InvalidAdvertisement);
        }
        let versions: BTreeSet<_> = self.versions.iter().collect();
        let schemas: BTreeSet<_> = self.schemas.iter().collect();
        if versions.len() != self.versions.len() || schemas.len() != self.schemas.len() {
            return Err(WireError::InvalidAdvertisement);
        }
        Ok(())
    }
}

/// Select only wire versions and operation schemas explicitly advertised by
/// *both* peers. This cannot create grants: agents must separately authorize
/// every request using the authenticated device, actor and local policies.
pub fn negotiate(local: &Advertisement, remote: &Advertisement) -> Result<Negotiated, WireError> {
    local.validate()?;
    remote.validate()?;

    let wire_version = local
        .versions
        .iter()
        .copied()
        .filter(|version| remote.versions.contains(version))
        .max()
        .ok_or(WireError::NoCommonVersion)?;

    let mut common = BTreeMap::<(String, String), u16>::new();
    for schema in &local.schemas {
        if remote.schemas.contains(schema) {
            common
                .entry((schema.kind.clone(), schema.action.clone()))
                .and_modify(|version| *version = (*version).max(schema.version))
                .or_insert(schema.version);
        }
    }
    let schemas = common
        .into_iter()
        .map(|((kind, action), version)| OperationSchema {
            kind,
            action,
            version,
        })
        .collect();

    Ok(Negotiated {
        wire_version,
        schemas,
        max_frame_bytes: local.max_frame_bytes.min(remote.max_frame_bytes),
    })
}

/// A header validated against the negotiated session. Its device and actor
/// identities must come from the independently authenticated session, never
/// from untrusted request fields. The payload codec is intentionally undecided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHeader {
    pub wire_version: WireVersion,
    pub request_id: String,
    pub kind: String,
    pub action: String,
    pub schema_version: u16,
    pub payload_bytes: u32,
    pub timeout_ms: u32,
}

impl RequestHeader {
    pub fn validate(&self, session: &Negotiated) -> Result<(), WireError> {
        if self.wire_version != session.wire_version
            || !valid_request_id(&self.request_id)
            || !valid_name(&self.kind)
            || !valid_name(&self.action)
            || self.schema_version == 0
            || self.payload_bytes > session.max_frame_bytes
            || !(1..=MAX_REQUEST_TIMEOUT_MS).contains(&self.timeout_ms)
        {
            return Err(WireError::InvalidRequest);
        }
        if !session.schemas.iter().any(|schema| {
            schema.kind == self.kind
                && schema.action == self.action
                && schema.version == self.schema_version
        }) {
            return Err(WireError::UnsupportedOperation);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1_0: WireVersion = WireVersion { major: 1, minor: 0 };
    const V1_1: WireVersion = WireVersion { major: 1, minor: 1 };
    const V2_0: WireVersion = WireVersion { major: 2, minor: 0 };

    fn schema(kind: &str, action: &str, version: u16) -> OperationSchema {
        OperationSchema {
            kind: kind.into(),
            action: action.into(),
            version,
        }
    }

    fn advertise(versions: Vec<WireVersion>, schemas: Vec<OperationSchema>) -> Advertisement {
        Advertisement {
            versions,
            schemas,
            max_frame_bytes: 16 * 1024,
        }
    }

    #[test]
    fn new_coordinator_accepts_explicitly_supported_older_agent() {
        let coordinator = advertise(
            vec![V1_0, V1_1],
            vec![
                schema("file", "read", 1),
                schema("file", "read", 2),
                schema("job", "status", 1),
            ],
        );
        let old_agent = advertise(vec![V1_0], vec![schema("file", "read", 1)]);
        let agreed = negotiate(&coordinator, &old_agent).unwrap();
        assert_eq!(agreed.wire_version(), V1_0);
        assert_eq!(agreed.schemas(), &[schema("file", "read", 1)]);
    }

    #[test]
    fn older_coordinator_does_not_inherit_new_agent_capabilities() {
        let old_coordinator = advertise(vec![V1_0], vec![schema("file", "read", 1)]);
        let new_agent = advertise(
            vec![V1_0, V1_1],
            vec![schema("file", "read", 1), schema("service", "restart", 1)],
        );
        let agreed = negotiate(&old_coordinator, &new_agent).unwrap();
        assert_eq!(agreed.schemas, vec![schema("file", "read", 1)]);
    }

    #[test]
    fn highest_mutual_schema_is_chosen_only_when_explicit() {
        let a = advertise(
            vec![V1_0],
            vec![schema("file", "read", 1), schema("file", "read", 2)],
        );
        let b = advertise(
            vec![V1_0],
            vec![schema("file", "read", 1), schema("file", "read", 2)],
        );
        assert_eq!(
            negotiate(&a, &b).unwrap().schemas,
            vec![schema("file", "read", 2)]
        );
        let c = advertise(vec![V1_0], vec![schema("file", "read", 3)]);
        assert!(negotiate(&a, &c).unwrap().schemas.is_empty());
    }

    #[test]
    fn incompatible_wire_versions_fail_closed() {
        let a = advertise(vec![V1_1], vec![schema("file", "read", 1)]);
        let b = advertise(vec![V1_0], vec![schema("file", "read", 1)]);
        let c = advertise(vec![V2_0], vec![schema("file", "read", 1)]);
        assert_eq!(negotiate(&a, &b), Err(WireError::NoCommonVersion));
        assert_eq!(negotiate(&a, &c), Err(WireError::NoCommonVersion));
    }

    #[test]
    fn rejects_duplicate_unsupported_and_malformed_advertisements() {
        let mut bad = advertise(vec![V1_0, V1_0], vec![]);
        assert_eq!(bad.validate(), Err(WireError::InvalidAdvertisement));
        bad.versions = vec![V1_0];
        bad.schemas = vec![schema("service", "restart", 1); 2];
        assert_eq!(bad.validate(), Err(WireError::InvalidAdvertisement));
        bad.schemas = vec![schema("file", "..read", 1)];
        assert_eq!(bad.validate(), Err(WireError::InvalidAdvertisement));
        bad.schemas = vec![schema("file", "read", 0)];
        assert_eq!(bad.validate(), Err(WireError::InvalidAdvertisement));
        bad.schemas.clear();
        bad.max_frame_bytes = MAX_FRAME_BYTES + 1;
        assert_eq!(bad.validate(), Err(WireError::InvalidAdvertisement));
        bad.max_frame_bytes = 16 * 1024;
        bad.schemas = vec![schema("file", "read", 1); MAX_OPERATION_SCHEMAS + 1];
        assert_eq!(bad.validate(), Err(WireError::InvalidAdvertisement));
    }

    #[test]
    fn validates_request_against_exact_negotiated_operation() {
        let a = advertise(vec![V1_0], vec![schema("file", "read", 1)]);
        let session = negotiate(&a, &a).unwrap();
        let mut request = RequestHeader {
            wire_version: V1_0,
            request_id: "request_1".into(),
            kind: "file".into(),
            action: "read".into(),
            schema_version: 1,
            payload_bytes: 1024,
            timeout_ms: 5000,
        };
        assert_eq!(request.validate(&session), Ok(()));
        request.action = "write".into();
        assert_eq!(
            request.validate(&session),
            Err(WireError::UnsupportedOperation)
        );
        request.action = "read".into();
        request.schema_version = 2;
        assert_eq!(
            request.validate(&session),
            Err(WireError::UnsupportedOperation)
        );
        request.schema_version = 1;
        request.wire_version = V1_1;
        assert_eq!(request.validate(&session), Err(WireError::InvalidRequest));
    }

    #[test]
    fn rejects_oversized_invalid_or_unbounded_requests() {
        let a = advertise(vec![V1_0], vec![schema("file", "read", 1)]);
        let session = negotiate(&a, &a).unwrap();
        let mut request = RequestHeader {
            wire_version: V1_0,
            request_id: "request_1".into(),
            kind: "file".into(),
            action: "read".into(),
            schema_version: 1,
            payload_bytes: 0,
            timeout_ms: 5000,
        };
        request.payload_bytes = session.max_frame_bytes + 1;
        assert_eq!(request.validate(&session), Err(WireError::InvalidRequest));
        request.payload_bytes = 0;
        request.request_id = "bad id".into();
        assert_eq!(request.validate(&session), Err(WireError::InvalidRequest));
        request.request_id = "request_1".into();
        request.timeout_ms = 0;
        assert_eq!(request.validate(&session), Err(WireError::InvalidRequest));
        request.timeout_ms = MAX_REQUEST_TIMEOUT_MS + 1;
        assert_eq!(request.validate(&session), Err(WireError::InvalidRequest));
    }

    #[test]
    fn size_limit_is_the_minimum_of_both_peers() {
        let a = advertise(vec![V1_0], vec![]);
        let mut b = advertise(vec![V1_0], vec![]);
        b.max_frame_bytes = 4096;
        assert_eq!(negotiate(&a, &b).unwrap().max_frame_bytes(), 4096);
    }
}
