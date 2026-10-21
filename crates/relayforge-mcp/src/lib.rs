//! MCP adapter boundary. A future standards-compliant MCP server must authenticate
//! each caller, map its identity to grants, and route through coordinator policy.
//! ClientKind is descriptive only, never proof of authorization.
use relayforge_policy::Policy;
use relayforge_protocol::Request;
pub fn authorize(policy: &Policy, request: &Request) -> bool {
    policy.allows(request)
}
#[cfg(test)]
mod tests {
    use super::*;
    use relayforge_protocol::{Capability, PROTOCOL_VERSION};
    #[test]
    fn default_deny_for_any_client() {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: "id".into(),
            actor_id: "codex".into(),
            device_id: "laptop".into(),
            capability: Capability::ProcessExecute,
        };
        assert!(!authorize(&Policy::default(), &request));
    }
}

pub mod stdio;

pub mod agent;
pub mod android;
pub mod android_health;
pub mod bridge;
pub mod changes;
pub mod fleet;
pub mod http;
pub mod routeros;
pub mod routeros_health;
pub mod ssh;
pub mod workstation;

pub mod workstation_dev;

pub mod workstation_transfer;

pub mod workstation_chain;
mod workstation_development;
pub mod workstation_jobs;

pub mod workstation_dependency;

pub mod workstation_retire;

pub mod workstation_recovery;

mod runtime;
