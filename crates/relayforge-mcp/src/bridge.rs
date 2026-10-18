//! A tightly scoped SSH-backed diagnostic bridge.
//! SSH authenticates the peer using the host's existing SSH configuration.
//! Only fixed commands are executed, never user-supplied shell text.
use serde_json::{json, Value};
use std::process::{Command, Stdio};

const MAX_OUTPUT: usize = 16 * 1024;
const HOSTS: &[&str] = &["ru0", "ru1", "srv0"];
const CHECKS: &[(&str, &str)] = &[
    ("identity", "id -un"),
    ("hostname", "hostname"),
    ("uptime", "uptime"),
    ("memory", "free -m"),
    ("disk", "df -h /"),
    ("kernel", "uname -sr"),
];

pub fn tool() -> Value {
    json!({"name":"relayforge_diagnostic",
        "description":"Run a fixed read-only diagnostic on an allowlisted host via existing authenticated SSH. No arbitrary commands.",
        "inputSchema":{"type":"object","properties":{
            "host":{"type":"string","enum":HOSTS},
            "check":{"type":"string","enum":["identity","hostname","uptime","memory","disk","kernel"]}
        },"required":["host","check"],"additionalProperties":false}})
}

pub fn diagnostic(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("arguments must be an object")?;
    if obj.len() != 2 {
        return Err("unexpected arguments".into());
    }
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .ok_or("missing host")?;
    let check = obj
        .get("check")
        .and_then(Value::as_str)
        .ok_or("missing check")?;
    if !HOSTS.contains(&host) {
        return Err("host denied".into());
    }
    let command = CHECKS
        .iter()
        .find(|(name, _)| *name == check)
        .map(|(_, command)| *command)
        .ok_or("check denied")?;
    // A hard timeout is enforced by the external timeout executable.
    // BatchMode forbids interactive password prompts.
    let config = crate::ssh::config_path()?;
    let output = Command::new("timeout")
        .args(["8s", "ssh", "-F"])
        .arg(config)
        .args([
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
        .map_err(|_| "diagnostic unavailable")?;
    if !output.status.success() {
        return Err("remote diagnostic failed".into());
    }
    let data = if output.stdout.len() > MAX_OUTPUT {
        &output.stdout[..MAX_OUTPUT]
    } else {
        &output.stdout
    };
    Ok(String::from_utf8_lossy(data).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_targets_and_operations() {
        for args in [
            json!({"host":"example.com","check":"uptime"}),
            json!({"host":"ru0;id","check":"uptime"}),
            json!({"host":"ru0","check":"execute"}),
            json!({"host":"ru0","check":"uptime","command":"id"}),
            json!({"host":"ru0","check":"uptime;id"}),
            json!({}),
        ] {
            assert!(diagnostic(&args).is_err());
        }
    }
}
