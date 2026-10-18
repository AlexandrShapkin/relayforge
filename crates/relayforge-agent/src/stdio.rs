//! Read-only agent protocol over a trusted local stdio channel.
//! The SSH account authenticates the remote operator in the pilot; the JSON
//! payload is NOT an authentication or an authorization token.
use relayforge_protocol::PROTOCOL_VERSION;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, BufRead, Write};
use std::process::{Command, Stdio};

const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_RESULT_BYTES: usize = 16 * 1024;

fn err(message: &str) -> Value {
    json!({"ok":false,"error":message})
}

fn read_short(path: &str, limit: usize) -> io::Result<String> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .chars()
        .take(limit)
        .collect::<String>()
        .trim()
        .to_owned())
}

fn device_status() -> io::Result<Value> {
    let hostname = read_short("/etc/hostname", 128)?;
    let uptime = read_short("/proc/uptime", 128)?;
    let os = read_short("/etc/os-release", 4096)?;
    let pretty_name = os
        .lines()
        .find_map(|line| line.strip_prefix("PRETTY_NAME="))
        .unwrap_or("unknown")
        .trim_matches('"');
    let mem = read_short("/proc/meminfo", 4096)?;
    let summary: Vec<&str> = mem.lines().take(4).collect();
    Ok(json!({
        "hostname": hostname,
        "os": pretty_name,
        "uptime_seconds": uptime.split_whitespace().next().unwrap_or("unknown"),
        "memory": summary,
    }))
}

pub fn valid_unit(value: &str) -> bool {
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

fn service_status(unit: &str) -> io::Result<Value> {
    let output = Command::new("systemctl")
        .args([
            "show",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,UnitFileState",
            "--",
            unit,
        ])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("systemctl unavailable"));
    }
    let data = &output.stdout[..output.stdout.len().min(MAX_RESULT_BYTES)];
    let result = String::from_utf8_lossy(data);
    // Only fixed properties. Do not expose environment, ExecStart or unit secrets.
    let values = result
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(name, _)| {
            [
                "Id",
                "LoadState",
                "ActiveState",
                "SubState",
                "UnitFileState",
            ]
            .contains(name)
        })
        .map(|(name, value)| (name.to_string(), json!(value)))
        .collect::<serde_json::Map<String, Value>>();
    Ok(Value::Object(values))
}

pub fn handle(request: &Value) -> Value {
    let Some(obj) = request.as_object() else {
        return err("invalid request");
    };
    if obj.get("version").and_then(Value::as_u64) != Some(PROTOCOL_VERSION as u64) {
        return err("unsupported protocol version");
    }
    let result = match obj.get("operation").and_then(Value::as_str) {
        Some("device.status") if obj.len() == 2 => device_status(),
        Some("service.status") if obj.len() == 3 => match obj.get("unit").and_then(Value::as_str) {
            Some(unit) if valid_unit(unit) => service_status(unit),
            _ => return err("invalid service unit"),
        },
        _ => return err("operation denied"),
    };
    match result {
        Ok(value) => json!({"ok":true,"data":value}),
        Err(_) => err("diagnostic unavailable"),
    }
}

/// A single framed request per process. Oversize input fails closed.
pub fn serve(mut reader: impl BufRead, mut writer: impl Write) -> io::Result<()> {
    let mut input = Vec::new();
    std::io::Read::take(&mut reader, (MAX_REQUEST_BYTES + 1) as u64)
        .read_until(b'\n', &mut input)?;
    if input.is_empty() {
        return Ok(());
    }
    let result = if input.len() > MAX_REQUEST_BYTES || !input.ends_with(b"\n") {
        err("invalid or oversized request")
    } else {
        match serde_json::from_slice::<Value>(&input) {
            Ok(request) => handle(&request),
            Err(_) => err("invalid JSON"),
        }
    };
    writeln!(writer, "{result}")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_mutation_and_actor_impersonation() {
        for req in [
            json!({"version":1,"operation":"process.execute","command":"id"}),
            json!({"version":1,"operation":"service.restart","unit":"ssh.service"}),
            json!({"version":1,"operation":"device.status","actor_id":"admin"}),
            json!({"version":2,"operation":"device.status"}),
            json!({"version":1,"operation":"service.status","unit":"ssh.service;id"}),
            json!({"version":1,"operation":"service.status","unit":"--help.service"}),
            json!({"version":1,"operation":"service.status","unit":"/etc/shadow"}),
        ] {
            assert_eq!(handle(&req)["ok"], false);
        }
    }

    #[test]
    fn limits_input_and_refuses_invalid_json() {
        let input = format!("{}\n", "x".repeat(MAX_REQUEST_BYTES + 100));
        let mut output = Vec::new();
        serve(input.as_bytes(), &mut output).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap()["ok"],
            false
        );
        let mut output = Vec::new();
        serve(b"oops\n".as_slice(), &mut output).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap()["error"],
            "invalid JSON"
        );
    }

    #[test]
    fn status_and_service_format() {
        assert!(handle(&json!({"version":1,"operation":"device.status"}))["ok"] == true);
        assert!(valid_unit("nginx.service"));
        assert!(valid_unit("getty@tty1.service"));
        assert!(!valid_unit("ssh.service && id"));
    }
}
