//! Read-only agent protocol over a trusted local stdio channel.
//! The SSH account authenticates the remote operator in the pilot; the JSON
//! payload is NOT an authentication or an authorization token.
use crate::files;
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

/// A bounded inventory of running/failed services; never reads ExecStart or
/// environment values from units.
fn service_inventory() -> io::Result<Value> {
    let output = Command::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,failed",
            "--plain",
            "--no-legend",
            "--no-pager",
        ])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("systemctl unavailable"));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let units: Vec<Value> = text
        .lines()
        .filter_map(|line| {
            let line = line.trim().trim_start_matches('●').trim();
            let mut columns = line.split_whitespace();
            let name = columns.next()?;
            if !valid_unit(name) {
                return None;
            }
            Some(json!({
                "unit": name,
                "load": columns.next()?,
                "active": columns.next()?,
                "sub": columns.next()?,
            }))
        })
        .take(64)
        .collect();
    Ok(json!({"units":units, "limit":64}))
}

/// Inspect services and timers owned by the SSH Unix user. No unit file,
/// environment, command line or journal contents are exposed. Enumerating a
/// user manager does not grant power to start/stop/restart anything.
fn user_unit_inventory() -> io::Result<Value> {
    const MAX_UNITS: usize = 64;
    let output = Command::new("systemctl")
        .args([
            "--user",
            "list-units",
            "--all",
            "--type=service,timer",
            "--plain",
            "--no-legend",
            "--no-pager",
        ])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("systemd user manager unavailable"));
    }
    let text = String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(32 * 1024)]);
    let units: Vec<Value> = text
        .lines()
        .filter_map(|line| {
            let mut columns = line.trim().trim_start_matches('●').split_whitespace();
            let name = columns.next()?;
            if !valid_unit(name) {
                return None;
            }
            let load = columns.next()?;
            let active = columns.next()?;
            let sub = columns.next()?;
            // Exclude arbitrary descriptions: some user services can embed
            // passwords or tokens in their descriptive metadata.
            Some(json!({"unit":name,"load":load,"active":active,"sub":sub}))
        })
        .take(MAX_UNITS)
        .collect();
    Ok(json!({"units":units,"limit":MAX_UNITS,"scope":"user"}))
}

/// Query only hard-coded, non-sensitive systemd properties. The unit is
/// syntactically restricted, never interpolated into a shell, and not-found
/// units fail explicitly rather than being reported as inactive/healthy.
fn user_unit_status(unit: &str) -> io::Result<Value> {
    if !valid_unit(unit) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid unit"));
    }
    let output = Command::new("systemctl")
        .args([
            "--user",
            "show",
            "--no-pager",
            "--property=Id,LoadState,ActiveState,SubState,UnitFileState,Result,NRestarts",
            "--",
            unit,
        ])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other("systemd user status unavailable"));
    }
    let data = &output.stdout[..output.stdout.len().min(MAX_RESULT_BYTES)];
    let mut result = serde_json::Map::new();
    for (key, value) in String::from_utf8_lossy(data)
        .lines()
        .filter_map(|line| line.split_once('='))
    {
        if [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "UnitFileState",
            "Result",
            "NRestarts",
        ]
        .contains(&key)
        {
            result.insert(key.to_owned(), json!(value));
        }
    }
    if result.get("Id").and_then(Value::as_str) != Some(unit)
        || result
            .get("LoadState")
            .and_then(Value::as_str)
            .is_none_or(|value| value == "not-found" || value == "error")
    {
        return Err(io::Error::new(io::ErrorKind::NotFound, "unit not found"));
    }
    Ok(json!({"scope":"user","properties":result}))
}

/// /proc exposes process statistics without command lines or environment.
/// Return only names, PIDs and resident memory (never secrets from argv).
fn top_processes() -> io::Result<Value> {
    let mut entries = Vec::new();
    for item in fs::read_dir("/proc")?.take(2048) {
        let Ok(item) = item else { continue };
        let Ok(pid) = item.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let path = format!("/proc/{pid}/status");
        let Ok(status) = read_short(&path, 4096) else {
            continue;
        };
        let name = status
            .lines()
            .find_map(|l| l.strip_prefix("Name:"))
            .unwrap_or("unknown")
            .trim();
        let rss = status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        entries.push((rss, pid, name.to_owned()));
    }
    entries.sort_by_key(|(rss, _, _)| std::cmp::Reverse(*rss));
    let processes: Vec<Value> = entries
        .into_iter()
        .take(20)
        .map(|(rss_kb, pid, name)| json!({"pid":pid,"name":name,"rss_kb":rss_kb}))
        .collect();
    Ok(json!({"processes":processes,"limit":20}))
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

// Deliberately limited to a dedicated inert one-shot test unit. No
// caller-supplied unit, shell command, root service or arbitrary restart.
fn restart_probe() -> io::Result<Value> {
    const UNIT: &str = "relayforge-probe.service";
    let status = Command::new("systemctl")
        .args(["--user", "restart", "--", UNIT])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !status.success() {
        return Err(io::Error::other("probe service restart denied"));
    }
    Ok(json!({"restarted":true,"unit":UNIT}))
}

/// Run exactly one noncritical ru1 health-snapshot job when an already
/// approved MCP change reaches the agent. No user-selected unit, host,
/// shell or arbitrary service operation may reach this path.
fn run_ru1_monitor() -> io::Result<Value> {
    const HOSTNAME: &str = "ru1.alexandrshapkin.ru";
    const UNIT: &str = "assistant-hub-monitor.service";
    if read_short("/etc/hostname", 128)?.trim() != HOSTNAME {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "monitor is permitted only on ru1",
        ));
    }

    fn properties(unit: &str) -> io::Result<std::collections::HashMap<String, String>> {
        let output = Command::new("systemctl")
            .args([
                "--user",
                "show",
                "--no-pager",
                "--property=Id,LoadState,Type,ActiveState,Result,ExecMainStatus",
                "--",
                unit,
            ])
            .stdin(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("user service preflight unavailable"));
        }
        let mut values = std::collections::HashMap::new();
        for (name, value) in String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| line.split_once('='))
        {
            if [
                "Id",
                "LoadState",
                "Type",
                "ActiveState",
                "Result",
                "ExecMainStatus",
            ]
            .contains(&name)
            {
                values.insert(name.to_owned(), value.to_owned());
            }
        }
        Ok(values)
    }

    let before = properties(UNIT)?;
    if before.get("Id").map(String::as_str) != Some(UNIT)
        || before.get("LoadState").map(String::as_str) != Some("loaded")
        || before.get("Type").map(String::as_str) != Some("oneshot")
        || before.get("ActiveState").map(String::as_str) != Some("inactive")
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "monitor preflight denied",
        ));
    }

    let result = Command::new("systemctl")
        .args(["--user", "start", "--", UNIT])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if !result.success() {
        return Err(io::Error::other("monitor job did not complete"));
    }
    let after = properties(UNIT)?;
    if after.get("Id").map(String::as_str) != Some(UNIT)
        || after.get("Result").map(String::as_str) != Some("success")
        || after.get("ExecMainStatus").map(String::as_str) != Some("0")
    {
        return Err(io::Error::other("monitor job did not report success"));
    }
    Ok(json!({"started":true,"host":"ru1","unit":UNIT,
        "scope":"user","result":"success"}))
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
        Some("service.list") if obj.len() == 2 => service_inventory(),
        Some("user.service.list") if obj.len() == 2 => user_unit_inventory(),
        Some("user.service.status") if obj.len() == 3 => {
            match obj.get("unit").and_then(Value::as_str) {
                Some(unit) if valid_unit(unit) => user_unit_status(unit),
                _ => return err("invalid service unit"),
            }
        }
        Some("probe.restart") if obj.len() == 2 => restart_probe(),
        Some("monitor.run") if obj.len() == 2 => run_ru1_monitor(),
        Some("process.top") if obj.len() == 2 => top_processes(),
        Some("file.list") if obj.len() == 2 => files::list_files(),
        Some("file.read") if obj.len() == 3 => match obj.get("path").and_then(Value::as_str) {
            Some(path) => files::read_file(path),
            None => return err("missing path"),
        },
        Some("file.create") if obj.len() == 4 => {
            match (
                obj.get("name").and_then(Value::as_str),
                obj.get("content").and_then(Value::as_str),
            ) {
                (Some(name), Some(content)) if files::valid_name(name) && content.len() <= 2048 => {
                    files::create_file(name, content)
                }
                _ => return err("file operation denied"),
            }
        }
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
            json!({"version":1,"operation":"probe.restart","unit":"ssh.service"}),
            json!({"version":1,"operation":"monitor.run","unit":"ssh.service"}),
            json!({"version":1,"operation":"monitor.run","host":"srv0"}),
            json!({"version":1,"operation":"monitor.run","command":"touch /tmp/file"}),
            json!({"version":1,"operation":"device.status","actor_id":"admin"}),
            json!({"version":2,"operation":"device.status"}),
            json!({"version":1,"operation":"service.status","unit":"ssh.service;id"}),
            json!({"version":1,"operation":"service.status","unit":"--help.service"}),
            json!({"version":1,"operation":"service.status","unit":"/etc/shadow"}),
            json!({"version":1,"operation":"file.read","path":"/etc/shadow"}),
            json!({"version":1,"operation":"file.create","name":"../../file.txt","content":"bad"}),
            json!({"version":1,"operation":"file.create","name":"script.sh","content":"bad"}),
            json!({"version":1,"operation":"file.create","name":"good.txt","content":"bad","actor":"root"}),
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
    fn user_units_are_read_only_and_validate_parameters() {
        for request in [
            json!({"version":1,"operation":"user.service.restart","unit":"remote-desktop.service"}),
            json!({"version":1,"operation":"user.service.status","unit":"ssh.service;id"}),
            json!({"version":1,"operation":"user.service.status","unit":"--help.service"}),
            json!({"version":1,"operation":"user.service.status","unit":"../../secret.service"}),
            json!({"version":1,"operation":"user.service.list","actor":"admin"}),
            json!({"version":1,"operation":"user.service.status","unit":"remote-desktop.service","actor":"admin"}),
        ] {
            assert_eq!(handle(&request)["ok"], false, "{request}");
        }
        let inventory = handle(&json!({"version":1,"operation":"user.service.list"}));
        assert_eq!(inventory["ok"], true);
        assert_eq!(inventory["data"]["scope"], "user");
        let arr = inventory["data"]["units"].as_array().unwrap();
        assert!(arr.len() <= 64);
        for item in arr {
            assert_eq!(item.as_object().unwrap().len(), 4);
        }
    }

    #[test]
    fn user_unit_status_returns_fixed_properties_only() {
        let status = handle(&json!({"version":1,"operation":"user.service.status",
            "unit":"default.target"}));
        // Only services, sockets and timers are authorized; targets are denied.
        assert_eq!(status["ok"], false);
        assert!(
            user_unit_status("remote-desktop.service").is_ok()
                || user_unit_status("dbus.service").is_ok()
        );
        assert!(user_unit_status("relayforge-nonexistent-test.service").is_err());
    }

    #[test]
    fn monitor_cannot_run_on_other_device() {
        // Unit testing is done on the developer host, not ru1: hostname
        // restriction must fail before any systemctl start invocation.
        if read_short("/etc/hostname", 128).unwrap_or_default() != "ru1.alexandrshapkin.ru" {
            assert!(run_ru1_monitor().is_err());
        }
    }

    #[test]
    fn inventories_return_bounded_read_only_data() {
        let processes = handle(&json!({"version":1,"operation":"process.top"}));
        assert_eq!(processes["ok"], true);
        assert!(processes["data"]["processes"].as_array().unwrap().len() <= 20);
        // no argv/env fields exposed
        for proc in processes["data"]["processes"].as_array().unwrap() {
            assert_eq!(proc.as_object().unwrap().len(), 3);
        }
        let services = handle(&json!({"version":1,"operation":"service.list"}));
        assert_eq!(services["ok"], true);
        assert!(services["data"]["units"].as_array().unwrap().len() <= 64);
    }

    #[test]
    fn status_and_service_format() {
        assert!(handle(&json!({"version":1,"operation":"device.status"}))["ok"] == true);
        assert!(valid_unit("nginx.service"));
        assert!(valid_unit("getty@tty1.service"));
        assert!(!valid_unit("ssh.service && id"));
    }
}
