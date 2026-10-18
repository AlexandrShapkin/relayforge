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
    // The primary SSH alias uses the OS route (wired preferred when available).
    // The secondary alias explicitly binds Wi-Fi, including when Ethernet
    // retains a link but can no longer reach the router.
    try_hosts(&["mikrotik", "mikrotik-wifi"], command, ssh_diagnostic)
}

fn try_hosts<F>(hosts: &[&str], command: &str, mut call: F) -> Result<String, String>
where
    F: FnMut(&str, &str) -> Result<String, String>,
{
    for host in hosts {
        if let Ok(value) = call(host, command) {
            return Ok(value);
        }
    }
    Err("router unreachable or diagnostic denied".into())
}

fn ssh_diagnostic(host: &str, command: &str) -> Result<String, String> {
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
            host,
            command,
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "router diagnostic unavailable")?;
    if !output.status.success() {
        return Err("router diagnostic unavailable".into());
    }
    let data = &output.stdout[..output.stdout.len().min(16 * 1024)];
    Ok(String::from_utf8_lossy(data).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fails_over_only_when_needed() {
        let mut attempts = Vec::new();
        let result = try_hosts(&["primary", "wifi"], "/system/identity/print", |host, _| {
            attempts.push(host.to_owned());
            if host == "primary" {
                Err("network down".into())
            } else {
                Ok("lan0".into())
            }
        });
        assert_eq!(result.unwrap(), "lan0");
        assert_eq!(attempts, ["primary", "wifi"]);

        let mut attempts = Vec::new();
        let result = try_hosts(&["primary", "wifi"], "/system/identity/print", |host, _| {
            attempts.push(host.to_owned());
            Ok("lan0".into())
        });
        assert!(result.is_ok());
        assert_eq!(attempts, ["primary"]);
    }

    #[test]
    fn fails_closed_when_both_channels_fail() {
        let result = try_hosts(&["primary", "wifi"], "/system/identity/print", |_, _| {
            Err("unavailable".into())
        });
        assert!(result.is_err());
    }

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
