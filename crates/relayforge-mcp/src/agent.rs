//! Read-only remote Rust agent invoked through authenticated existing SSH.
//! The protocol runs as the authenticated SSH user and has no listener.
use relayforge_protocol::PROTOCOL_VERSION;
use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const HOSTS: &[&str] = &["ru0", "ru1", "srv0"];
const AGENT_PATH: &str = "/home/shapkin_as/.local/libexec/relayforge-pilot/relayforge-agent";
const MAX_OUTPUT: usize = 16 * 1024;

pub fn tool() -> Value {
    json!({"name":"relayforge_agent_query",
        "description":"Query a real read-only Rust agent on an allowlisted server using authenticated SSH.",
        "inputSchema":{"type":"object","properties":{
            "host":{"type":"string","enum":HOSTS},
            "operation":{"type":"string","enum":["device.status","service.status","service.list","process.top"]},
            "unit":{"type":"string","maxLength":100,"description":"Required only for service.status; e.g. nginx.service"}
        },"required":["host","operation"],"additionalProperties":false}})
}

pub fn file_tool() -> Value {
    json!({"name":"relayforge_agent_file",
        "description":"Access fixed public OS metadata or create/list/read tiny files within a dedicated private RelayForge scratch directory. No arbitrary paths, deletes, overwrites, or service files.",
        "inputSchema":{"type":"object","properties":{
            "host":{"type":"string","enum":HOSTS},
            "operation":{"type":"string","enum":["file.list","file.read","file.create"]},
            "path":{"type":"string","maxLength":64},
            "name":{"type":"string","maxLength":64},
            "content":{"type":"string","maxLength":2048}
        },"required":["host","operation"],"additionalProperties":false}})
}

fn valid_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(c))
        && [".txt", ".md", ".json"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

fn valid_read_path(path: &str) -> bool {
    [
        "/etc/hostname",
        "/etc/os-release",
        "/proc/loadavg",
        "/proc/meminfo",
        "/proc/uptime",
    ]
    .contains(&path)
        || valid_file_name(path)
}

fn validate_file(args: &Value) -> Result<(&str, Value), String> {
    let obj = args.as_object().ok_or("arguments must be an object")?;
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .ok_or("missing host")?;
    if !HOSTS.contains(&host) {
        return Err("host denied".into());
    }
    match obj.get("operation").and_then(Value::as_str) {
        Some("file.list") if obj.len() == 2 => Ok((
            host,
            json!({"version":PROTOCOL_VERSION,"operation":"file.list"}),
        )),
        Some("file.read") if obj.len() == 3 => {
            let path = obj
                .get("path")
                .and_then(Value::as_str)
                .ok_or("missing path")?;
            if !valid_read_path(path) {
                return Err("file denied".into());
            }
            Ok((
                host,
                json!({"version":PROTOCOL_VERSION,"operation":"file.read","path":path}),
            ))
        }
        Some("file.create") if obj.len() == 4 => {
            let name = obj
                .get("name")
                .and_then(Value::as_str)
                .ok_or("missing name")?;
            let content = obj
                .get("content")
                .and_then(Value::as_str)
                .ok_or("missing content")?;
            if !valid_file_name(name) || content.len() > 2048 {
                return Err("file denied".into());
            }
            Ok((
                host,
                json!({"version":PROTOCOL_VERSION,"operation":"file.create","name":name,"content":content}),
            ))
        }
        _ => Err("file operation denied".into()),
    }
}

pub fn file_query(args: &Value) -> Result<String, String> {
    let (host, request) = validate_file(args)?;
    invoke_agent(host, request)
}

fn validate(args: &Value) -> Result<(&str, Value), String> {
    let obj = args.as_object().ok_or("arguments must be an object")?;
    let host = obj
        .get("host")
        .and_then(Value::as_str)
        .ok_or("missing host")?;
    if !HOSTS.contains(&host) {
        return Err("host denied".into());
    }
    let operation = obj
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    match operation {
        "device.status" | "service.list" | "process.top" if obj.len() == 2 => Ok((
            host,
            json!({
                "version":PROTOCOL_VERSION, "operation":operation
            }),
        )),
        "service.status" if obj.len() == 3 => {
            let unit = obj
                .get("unit")
                .and_then(Value::as_str)
                .ok_or("missing unit")?;
            if !valid_unit(unit) {
                return Err("invalid unit".into());
            }
            Ok((
                host,
                json!({
                    "version":PROTOCOL_VERSION, "operation":operation,"unit":unit
                }),
            ))
        }
        _ => Err("operation denied".into()),
    }
}

/// Both the MCP adapter and remote agent validate the unit. Neither accepts
/// remote shell syntax; the agent executes systemctl with OS argument vectors.
fn valid_unit(value: &str) -> bool {
    value.len() >= 9
        && value.len() <= 100
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@-".contains(&b))
        && [".service", ".timer", ".socket"]
            .iter()
            .any(|suffix| value.ends_with(suffix))
}

pub fn query(args: &Value) -> Result<String, String> {
    let (host, message) = validate(args)?;
    invoke_agent(host, message)
}

fn invoke_agent(host: &str, message: Value) -> Result<String, String> {
    let config = crate::ssh::config_path()?;
    let mut child = Command::new("timeout")
        .args(["10s", "ssh", "-F"])
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
            AGENT_PATH,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "agent transport unavailable")?;
    {
        let mut stdin = child.stdin.take().ok_or("agent transport unavailable")?;
        writeln!(stdin, "{message}").map_err(|_| "agent transport unavailable")?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "agent transport unavailable")?;
    if !output.status.success() || output.stdout.len() > MAX_OUTPUT {
        return Err("agent unavailable or response oversized".into());
    }
    let response: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid agent response")?;
    if response.get("ok") != Some(&Value::Bool(true)) {
        return Err("agent operation denied or failed".into());
    }
    let payload = response.get("data").ok_or("invalid agent response")?;
    Ok(payload.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn files_require_sandboxed_paths() {
        for args in [
            json!({"host":"ru0","operation":"file.read","path":"/etc/shadow"}),
            json!({"host":"ru0","operation":"file.create","name":"../../a.md","content":"text"}),
            json!({"host":"example.com","operation":"file.list"}),
            json!({"host":"ru0","operation":"file.create","name":"test.sh","content":"data"}),
            json!({"host":"ru0","operation":"file.list","actor":"root"}),
        ] {
            assert!(validate_file(&args).is_err());
        }
        assert!(validate_file(&json!({"host":"ru0","operation":"file.list"})).is_ok());
        assert!(validate_file(
            &json!({"host":"srv0","operation":"file.read","path":"/etc/os-release"})
        )
        .is_ok());
        assert!(validate_file(
            &json!({"host":"ru1","operation":"file.create","name":"report.txt","content":"test"})
        )
        .is_ok());
    }
    #[test]
    fn forbids_shell_and_cross_host_operations() {
        for req in [
            json!({"host":"example.com","operation":"device.status"}),
            json!({"host":"ru0;id","operation":"device.status"}),
            json!({"host":"ru0","operation":"service.restart","unit":"nginx.service"}),
            json!({"host":"ru0","operation":"service.status","unit":"ssh.service;id"}),
            json!({"host":"ru0","operation":"service.status","unit":"--help.service"}),
            json!({"host":"ru0","operation":"device.status","actor_id":"root"}),
            json!({"host":"ru0","operation":"service.status"}),
        ] {
            assert!(validate(&req).is_err());
        }
        assert!(validate(&json!({"host":"ru0","operation":"device.status"})).is_ok());
        assert!(validate(&json!({"host":"ru1","operation":"process.top"})).is_ok());
        assert!(validate(&json!({"host":"srv0","operation":"service.list"})).is_ok());
        assert!(validate(
            &json!({"host":"srv0","operation":"service.status","unit":"docker.service"})
        )
        .is_ok());
    }
}
