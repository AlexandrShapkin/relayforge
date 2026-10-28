//! Transport-independent contract shared by all RelayForge components.
//! This is NOT a complete MCP implementation or an authenticated wire format.
pub const PROTOCOL_VERSION: u16 = 1;

// Separate, inert model for a future authenticated agent transport.
pub mod wire;

/// Device platform, independent of the client transport and actor identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePlatform {
    Linux,
    RouterOs,
    Android,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    DeviceRead,
    ProcessRead,
    FileRead,
    FileWrite,
    ProcessExecute,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeviceRead => "device.read",
            Self::ProcessRead => "process.read",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::ProcessExecute => "process.execute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientKind {
    ChatGpt,
    Codex,
    AssistantHub,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub version: u16,
    pub request_id: String,
    pub actor_id: String,
    pub device_id: String,
    pub capability: Capability,
}

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.version != PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if [&self.request_id, &self.actor_id, &self.device_id]
            .iter()
            .any(|v| v.is_empty() || v.len() > 128 || v.trim() != v.as_str())
        {
            return Err("invalid request identity");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unsupported_version() {
        let r = Request {
            version: 2,
            request_id: "r".into(),
            actor_id: "a".into(),
            device_id: "d".into(),
            capability: Capability::DeviceRead,
        };
        assert!(r.validate().is_err());
    }
    #[test]
    fn accepts_independent_client_identity() {
        for client in [
            ClientKind::ChatGpt,
            ClientKind::Codex,
            ClientKind::AssistantHub,
            ClientKind::Other,
        ] {
            assert!(matches!(
                client,
                ClientKind::ChatGpt
                    | ClientKind::Codex
                    | ClientKind::AssistantHub
                    | ClientKind::Other
            ));
        }
    }
}
