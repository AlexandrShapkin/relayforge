//! Internal resource boundary, versioned independently of MCP API revision 9.
//! Static typed slots avoid erased payloads and arbitrary command dispatch.
//! No new MCP entrypoint, network route, grant or mutation is registered here.
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RESOURCE_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Host {
    LocalWorkstation,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Workstation,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StatusView {
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadRequest<Q> {
    pub schema_version: u16,
    pub host: Host,
    pub kind: Kind,
    pub id: String,
    pub action: Action,
    pub options: Q,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusQuery {
    pub view: StatusView,
}

#[derive(Debug, Serialize)]
pub struct Observation<T> {
    pub schema_version: u16,
    pub host: Host,
    pub kind: Kind,
    pub id: &'static str,
    pub action: Action,
    /// Start of a non-atomic local observation; not authenticated host identity.
    pub observed_at_unix_seconds: u64,
    pub data: T,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResourceError {
    UnsupportedVersion,
    Denied,
    ClockUnavailable,
    Provider(&'static str),
}
impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedVersion => "unsupported resource version",
            Self::Denied => "resource denied",
            Self::ClockUnavailable => "observation clock unavailable",
            Self::Provider(message) => message,
        })
    }
}
impl std::error::Error for ResourceError {}

/// Providers expose only implemented operations with concrete input/output types.
/// Mutations and domain commands need separate contracts and approval boundaries.
pub trait ReadProvider {
    type Query;
    type Output;
    fn read(&self, query: Self::Query) -> Result<Self::Output, &'static str>;
}

/// Typed static registry: each future kind gets its own typed slot/route.
/// Registration is implementation availability, never authorization.
pub struct Registry<P> {
    workstation: P,
}
impl<P> Registry<P> {
    pub fn new(workstation: P) -> Self {
        Self { workstation }
    }
}
impl<P: ReadProvider<Query = StatusQuery>> Registry<P> {
    pub fn read_status(
        &self,
        request: ReadRequest<StatusQuery>,
    ) -> Result<Observation<P::Output>, ResourceError> {
        authorize_status(&request)?;
        let observed_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ResourceError::ClockUnavailable)?
            .as_secs();
        let data = self
            .workstation
            .read(request.options)
            .map_err(ResourceError::Provider)?;
        Ok(Observation {
            schema_version: RESOURCE_VERSION,
            host: Host::LocalWorkstation,
            kind: Kind::Workstation,
            id: "local",
            action: Action::Read,
            observed_at_unix_seconds,
            data,
        })
    }
}

// Host-local policy for this fixed read only. No caller-selected addresses,
// paths, principal, grants or fallback hosts. Existing reader restrictions apply.
fn authorize_status(request: &ReadRequest<StatusQuery>) -> Result<(), ResourceError> {
    if request.schema_version != RESOURCE_VERSION {
        return Err(ResourceError::UnsupportedVersion);
    }
    if request.id != "local" {
        return Err(ResourceError::Denied);
    }
    // Exhaustive tuple: adding a future variant requires a policy decision.
    match (
        request.host,
        request.kind,
        request.action,
        request.options.view,
    ) {
        (Host::LocalWorkstation, Kind::Workstation, Action::Read, StatusView::Status) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workstation::legacy_status_request;
    use serde_json::json;
    use std::cell::Cell;
    struct Fake(Cell<usize>);
    impl ReadProvider for Fake {
        type Query = StatusQuery;
        type Output = u8;
        fn read(&self, _: StatusQuery) -> Result<u8, &'static str> {
            self.0.set(self.0.get() + 1);
            Ok(42)
        }
    }
    #[test]
    fn policy_denies_before_provider_and_preserves_origin() {
        let registry = Registry::new(Fake(Cell::new(0)));
        let mut request = legacy_status_request(&json!({})).unwrap();
        request.schema_version = 2;
        assert!(registry.read_status(request).is_err());
        let mut request = legacy_status_request(&json!({})).unwrap();
        request.id = "/etc/passwd".into();
        assert!(registry.read_status(request).is_err());
        assert_eq!(registry.workstation.0.get(), 0);
        let response = registry
            .read_status(legacy_status_request(&json!({})).unwrap())
            .unwrap();
        assert_eq!(response.data, 42);
        assert_eq!(response.host, Host::LocalWorkstation);
        assert_eq!(response.id, "local");
        assert_eq!(registry.workstation.0.get(), 1);
    }
    #[test]
    fn strict_typed_contract_rejects_unregistered_authority() {
        let valid = json!({"schema_version":1,"host":"local_workstation","kind":"workstation",
            "id":"local","action":"read","options":{"view":"status"}});
        for (field, value) in [
            ("host", json!("ru0")),
            ("kind", json!("file")),
            ("action", json!("delete")),
            ("options", json!({"view":"status","path":"/etc"})),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            assert!(serde_json::from_value::<ReadRequest<StatusQuery>>(invalid).is_err());
        }
        let mut invalid = valid.clone();
        invalid["grant"] = json!(true);
        assert!(serde_json::from_value::<ReadRequest<StatusQuery>>(invalid).is_err());
        assert!(serde_json::from_value::<ReadRequest<StatusQuery>>(valid).is_ok());
        for args in [
            json!(null),
            json!([]),
            json!({"host":"ru0"}),
            json!({"action":"read"}),
        ] {
            assert_eq!(
                legacy_status_request(&args).unwrap_err(),
                "unexpected workstation arguments"
            );
        }
    }
}
