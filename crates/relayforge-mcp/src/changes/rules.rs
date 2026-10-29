//! Pure, fail-closed request and approval-window rules.
//! Keep IO, audit, durable grant claims and local operator approval in the parent.
use serde_json::{json, Value};

use super::{EXECUTION_TTL_SECONDS, ID_LEN, MAX_CONTENT};

pub(super) fn valid_id(id: &str) -> bool {
    id.len() == ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Effective execution deadline. Legacy approvals without the new fields
/// keep their original deadline: deploys must NEVER revive an old grant.
/// Partial/malformed new fields fail closed.
pub(super) fn execution_deadline(record: &Value) -> Option<u64> {
    let prepared_expiry = record.get("expires")?.as_u64()?;
    match (
        record.get("approved_at_unix"),
        record.get("execution_expires_at_unix"),
    ) {
        (None, None) => Some(prepared_expiry),
        (Some(approved), Some(deadline)) => {
            let created = record.get("created")?.as_u64()?;
            let approved_at = approved.as_u64()?;
            let exec_expiry = deadline.as_u64()?;
            let expected = approved_at.checked_add(EXECUTION_TTL_SECONDS)?;
            if approved_at < created || approved_at >= prepared_expiry || exec_expiry != expected {
                None
            } else {
                Some(exec_expiry)
            }
        }
        _ => None,
    }
}

fn valid_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
        && [".txt", ".md", ".json"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

fn root_component(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && ![
            "secret",
            "credential",
            "token",
            "password",
            "private",
            "id_rsa",
            "id_ed25519",
            ".env",
            ".pem",
            ".key",
        ]
        .iter()
        .any(|part| s.to_ascii_lowercase().contains(part))
}

pub(super) fn parse_action(args: &Value) -> Result<Value, String> {
    let obj = args.as_object().ok_or("expected object")?;
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .ok_or("missing host")?;
    if !["ru0", "srv0", "workstation"].contains(&host) {
        return Err("host denied".into());
    }
    match obj.get("action").and_then(Value::as_str) {
        Some("sandbox.create") if matches!(host, "ru0" | "srv0") && obj.len() == 4 => {
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or("missing filename")?;
            let content = obj
                .get("content")
                .and_then(Value::as_str)
                .ok_or("missing content")?;
            if !valid_file_name(name) || content.len() > MAX_CONTENT {
                return Err("file parameters denied".into());
            }
            Ok(json!({"host":host,"action":"sandbox.create","name":name,"content":content}))
        }
        Some("probe.restart") if host == "ru0" && obj.len() == 2 => {
            Ok(json!({"host":"ru0","action":"probe.restart"}))
        }
        Some("artifact.root.add") if host == "workstation" && obj.len() == 4 => {
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or("artifact root name missing")?;
            let directory = obj
                .get("directory")
                .and_then(Value::as_str)
                .ok_or("artifact directory missing")?;
            if !root_component(name, 32) || !root_component(directory, 96) {
                return Err("artifact root request denied".into());
            }
            Ok(json!({"host":host,"action":"artifact.root.add",
                      "name":name,"directory":directory}))
        }
        Some("artifact.root.remove") if host == "workstation" && obj.len() == 3 => {
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or("artifact root name missing")?;
            if !root_component(name, 32) {
                return Err("artifact root request denied".into());
            }
            Ok(json!({"host":host,"action":"artifact.root.remove","name":name}))
        }
        _ => Err("operation denied".into()),
    }
}
