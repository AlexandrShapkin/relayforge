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

/// Allowlisted scheduled jobs only. These are inspection targets, NOT
/// writable targets. The returned status only reflects systemd execution,
/// not the quality/completeness of the underlying backup or sync data.
const RU0_SCHEDULED_JOBS: &[(&str, &str, u64)] = &[
    (
        "assistant-hub-backup.timer",
        "assistant-hub-backup.service",
        48 * 60,
    ),
    (
        "assistant-hub-google-calendar.timer",
        "assistant-hub-google-calendar.service",
        120,
    ),
    (
        "assistant-hub-university-calendar.timer",
        "assistant-hub-university-calendar.service",
        240,
    ),
];

fn user_job_properties(
    unit: &str,
    fields: &str,
) -> io::Result<std::collections::HashMap<String, String>> {
    // The caller supplies only fixed internal constants for fields and unit.
    let output = Command::new("systemctl")
        .args(["--user", "show", "--no-pager", fields, "--", unit])
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() || output.stdout.len() > 4096 {
        return Err(io::Error::other("systemd job properties unavailable"));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect())
}

fn job_field<'a>(
    values: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    values.get(key).map(String::as_str)
}

fn job_classification(
    timer: &std::collections::HashMap<String, String>,
    service: &std::collections::HashMap<String, String>,
    uptime_micros: u64,
    max_age_minutes: u64,
) -> (&'static str, &'static str, Option<u64>) {
    if job_field(timer, "ActiveState") != Some("active") {
        return ("failed", "timer_not_active", None);
    }
    let result = job_field(service, "Result");
    // Any explicit non-success result is a failure, including new systemd
    // failure variants. Missing results are unverified, never marked green.
    if result.is_some_and(|v| !["success", ""].contains(&v))
        || (job_field(service, "ExecMainCode") == Some("1")
            && job_field(service, "ExecMainStatus") != Some("0"))
    {
        return ("failed", "last_execution_failed", None);
    }
    if job_field(service, "ActiveState") == Some("active") {
        return ("running", "job_currently_active", None);
    }
    let Some(exit_at) = job_field(service, "ExecMainExitTimestampMonotonic")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= uptime_micros)
    else {
        return ("unverified", "no_completion_observed_this_boot", None);
    };
    let minutes_since = (uptime_micros - exit_at) / 60_000_000;
    if job_field(service, "Result") != Some("success")
        || job_field(service, "ExecMainCode") != Some("1")
        || job_field(service, "ExecMainStatus") != Some("0")
    {
        return ("unverified", "no_confirmed_success", Some(minutes_since));
    }
    if minutes_since > max_age_minutes {
        return ("stale", "last_success_too_old", Some(minutes_since));
    }
    ("success", "completed_successfully", Some(minutes_since))
}

fn scheduled_job_snapshot(
    timer_name: &str,
    service_name: &str,
    max_age_minutes: u64,
    uptime_micros: u64,
) -> io::Result<Value> {
    let timer = user_job_properties(
        timer_name,
        "--property=Id,LoadState,ActiveState,SubState,LastTriggerUSec,NextElapseUSecRealtime",
    )?;
    let service=user_job_properties(service_name,
        "--property=Id,LoadState,ActiveState,Result,ExecMainCode,ExecMainStatus,ExecMainExitTimestampMonotonic")?;
    if timer.get("Id").map(String::as_str) != Some(timer_name)
        || service.get("Id").map(String::as_str) != Some(service_name)
        || timer.get("LoadState").map(String::as_str) != Some("loaded")
        || service.get("LoadState").map(String::as_str) != Some("loaded")
    {
        return Err(io::Error::other("required scheduled unit missing"));
    }
    let (status, reason, minutes) =
        job_classification(&timer, &service, uptime_micros, max_age_minutes);
    let last_trigger_at = timer
        .get("LastTriggerUSec")
        .map(String::as_str)
        .unwrap_or("");
    let next_scheduled_at = timer
        .get("NextElapseUSecRealtime")
        .map(String::as_str)
        .unwrap_or("");
    Ok(json!({
        "timer":timer_name, "service":service_name,
        "status":status, "reason":reason,
        "timer_active":timer.get("ActiveState").map(String::as_str)==Some("active"),
        "last_trigger_at":last_trigger_at,
        "next_scheduled_at":next_scheduled_at,
        "minutes_since_completion":minutes,
        "max_age_minutes":max_age_minutes,
    }))
}

/// One bounded SSH agent query returns both the established service
/// inventory and an optional job-success assessment. No service starts.
fn user_jobs_summary() -> io::Result<Value> {
    let hostname = read_short("/etc/hostname", 128)?;
    let jobs: &[(&str, &str, u64)] = match hostname.as_str() {
        "ru0.alexandrshapkin.ru" => RU0_SCHEDULED_JOBS,
        "srv0" => &[],
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "user jobs summary host not allowlisted",
            ))
        }
    };
    let uptime_micros = read_short("/proc/uptime", 128)?
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0 && *value < 1e12)
        .map(|value| (value * 1_000_000.0) as u64)
        .ok_or_else(|| io::Error::other("invalid host monotonic uptime"))?;
    let mut summary = user_unit_inventory()?;
    let mut snapshots = Vec::with_capacity(jobs.len());
    for &(timer, service, max_age) in jobs {
        snapshots.push(scheduled_job_snapshot(
            timer,
            service,
            max_age,
            uptime_micros,
        )?);
    }
    let obj = summary
        .as_object_mut()
        .ok_or_else(|| io::Error::other("invalid inventory"))?;
    obj.insert("host".to_owned(), json!(hostname));
    obj.insert("scheduled_jobs".to_owned(), json!(snapshots));
    obj.insert(
        "artifact_results".to_owned(),
        json!(crate::artifacts::summary(
            &hostname,
            &std::path::PathBuf::from(
                std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME unavailable"))?
            )
        )),
    );
    Ok(summary)
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
        Some("user.jobs.summary") if obj.len() == 2 => user_jobs_summary(),
        Some("user.service.status") if obj.len() == 3 => {
            match obj.get("unit").and_then(Value::as_str) {
                Some(unit) if valid_unit(unit) => user_unit_status(unit),
                _ => return err("invalid service unit"),
            }
        }
        Some("probe.restart") if obj.len() == 2 => restart_probe(),
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
    fn scheduled_jobs_reject_unknown_or_failed_runs() {
        let mut timer =
            std::collections::HashMap::from([("ActiveState".to_owned(), "active".to_owned())]);
        let mut service = std::collections::HashMap::from([
            ("ActiveState".to_owned(), "inactive".to_owned()),
            ("Result".to_owned(), "success".to_owned()),
            ("ExecMainCode".to_owned(), "1".to_owned()),
            ("ExecMainStatus".to_owned(), "0".to_owned()),
            (
                "ExecMainExitTimestampMonotonic".to_owned(),
                "500000000".to_owned(),
            ),
        ]);
        assert_eq!(
            job_classification(&timer, &service, 560_000_000, 5).0,
            "success"
        );
        assert_eq!(
            job_classification(&timer, &service, 900_000_000, 5).0,
            "stale"
        );
        service.insert("ExecMainExitTimestampMonotonic".into(), "0".into());
        assert_eq!(
            job_classification(&timer, &service, 900_000_000, 5).0,
            "unverified"
        );
        service.insert("ExecMainExitTimestampMonotonic".into(), "500000000".into());
        service.insert("Result".into(), "exit-code".into());
        assert_eq!(
            job_classification(&timer, &service, 560_000_000, 5).0,
            "failed"
        );
        service.insert("Result".into(), "start-limit-hit".into());
        assert_eq!(
            job_classification(&timer, &service, 560_000_000, 5).0,
            "failed"
        );
        service.insert("Result".into(), "success".into());
        timer.insert("ActiveState".into(), "inactive".into());
        assert_eq!(
            job_classification(&timer, &service, 560_000_000, 5).0,
            "failed"
        );
    }

    #[test]
    fn job_summary_has_no_mutation_arguments() {
        for request in [
            json!({"version":1,"operation":"user.jobs.summary","unit":"ssh.service"}),
            json!({"version":1,"operation":"user.jobs.summary","host":"ru0"}),
            json!({"version":1,"operation":"user.jobs.summary","action":"restart"}),
            json!({"version":1,"operation":"user.jobs.restart"}),
        ] {
            assert_eq!(handle(&request)["ok"], false, "{request}");
        }
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
    fn retired_monitor_action_is_denied() {
        assert_eq!(handle(&json!({"version":1,"operation":"monitor.run"}))["ok"],false);
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
