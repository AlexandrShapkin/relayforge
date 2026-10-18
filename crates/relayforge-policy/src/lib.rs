//! Deny-by-default policy; callers must authenticate identities before checking grants.
use relayforge_protocol::Request;
use std::collections::HashSet;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Grant {
    pub actor_id: String,
    pub device_id: String,
    pub capability: String,
}

#[derive(Default)]
pub struct Policy {
    grants: HashSet<Grant>,
}

impl Policy {
    pub fn new(grants: impl IntoIterator<Item = Grant>) -> Self {
        Self {
            grants: grants.into_iter().collect(),
        }
    }
    pub fn allows(&self, request: &Request) -> bool {
        request.validate().is_ok()
            && self.grants.contains(&Grant {
                actor_id: request.actor_id.clone(),
                device_id: request.device_id.clone(),
                capability: request.capability.as_str().into(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relayforge_protocol::{Capability, PROTOCOL_VERSION};
    #[test]
    fn only_exact_grants_are_allowed() {
        let policy = Policy::new([Grant {
            actor_id: "alice".into(),
            device_id: "laptop".into(),
            capability: "device.read".into(),
        }]);
        let mut req = Request {
            version: PROTOCOL_VERSION,
            request_id: "1".into(),
            actor_id: "alice".into(),
            device_id: "laptop".into(),
            capability: Capability::DeviceRead,
        };
        assert!(policy.allows(&req));
        req.device_id = "vps".into();
        assert!(!policy.allows(&req));
        req.device_id = "laptop".into();
        req.capability = Capability::ProcessExecute;
        assert!(!policy.allows(&req));
        assert!(!Policy::default().allows(&req));
    }
}
