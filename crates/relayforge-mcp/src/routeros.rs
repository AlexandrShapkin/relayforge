//! Read-only RouterOS diagnostics through an explicitly configured SSH alias.
//! No arbitrary RouterOS script or mutation is accepted from MCP.
use serde_json::{json, Value};
use std::process::{Command, Stdio};

const CHECKS: &[(&str, &str)] = &[
    ("resource", "/system/resource/print"),
    ("identity", "/system/identity/print"),
    ("interfaces", "/interface/print terse"),
    ("addresses", "/ip/address/print terse"),
    ("routes", "/ip/route/print terse"),
    ("dhcp_leases", "/ip/dhcp-server/lease/print terse"),
    ("wifi", "/interface/wifi/print terse"),
];

pub fn tool() -> Value {
    json!({"name":"relayforge_routeros_diagnostic",
        "description":"Read a fixed RouterOS diagnostic via the preconfigured mikrotik SSH alias; no changes are allowed.",
        "inputSchema":{"type":"object","properties":{
            "check":{"type":"string","enum":["resource","identity","interfaces","addresses","routes","dhcp_leases","wifi"]}
        },"required":["check"],"additionalProperties":false}})
}

pub fn diagnostic(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("arguments must be an object")?;
    if obj.len() != 1 {
        return Err("unexpected arguments".into());
    }
    let check = obj
        .get("check")
        .and_then(Value::as_str)
        .ok_or("missing check")?;
    let command = CHECKS
        .iter()
        .find(|(name, _)| *name == check)
        .map(|(_, command)| *command)
        .ok_or("check denied")?;
    let output = Command::new("timeout")
        .args([
            "8s",
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=4",
            "-o",
            "StrictHostKeyChecking=yes",
            "--",
            "mikrotik",
            command,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "router diagnostic unavailable")?;
    if !output.status.success() {
        return Err("router unreachable or diagnostic denied".into());
    }
    let data = &output.stdout[..output.stdout.len().min(16 * 1024)];
    Ok(String::from_utf8_lossy(data).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deny_unsupported_operations() {
        for args in [
            json!({"check":"reboot"}),
            json!({"check":"resource; /system/reset-configuration"}),
            json!({"check":"resource","command":"reboot"}),
            json!({"host":"192.168.88.1","check":"resource"}),
            json!({}),
        ] {
            assert!(diagnostic(&args).is_err());
        }
    }
}
