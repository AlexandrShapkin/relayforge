//! Read-only, secret-free status of the opt-in local recovery watchdog.
//! Never exposes journals, unit file contents, command lines or credentials.
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    process::{Command, Stdio},
};

const TIMER: &str = "relayforge-local-recover.timer";
const SERVICE: &str = "relayforge-local-recover.service";
const MAX_OUTPUT: usize = 8192;

fn unit_properties(unit: &str) -> Result<HashMap<String, String>, String> {
    let property = match unit {
        TIMER => "Id,LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime,NextElapseUSecMonotonic",
        SERVICE => "Id,LoadState,ActiveState,Result,ExecMainStatus,ExecMainCode,ExecMainExitTimestampMonotonic",
        _ => return Err("unit denied".into()),
    };
    let output = Command::new("timeout")
        .args([
            "-k",
            "2s",
            "8s",
            "systemctl",
            "--user",
            "show",
            "--no-pager",
            "--property",
            property,
            "--",
            unit,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "recovery status unavailable")?;
    if !output.status.success() || output.stdout.len() > MAX_OUTPUT {
        return Err("recovery status unavailable".into());
    }
    let result = String::from_utf8(output.stdout).map_err(|_| "recovery status unavailable")?;
    let mut map = HashMap::new();
    for line in result.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if value.len() > 256 || key.len() > 64 {
            return Err("invalid recovery metadata".into());
        }
        if property.split(',').any(|expected| expected == key) {
            map.insert(key.to_owned(), value.to_owned());
        }
    }
    if map.get("Id").map(String::as_str) != Some(unit)
        || map.get("LoadState").map(String::as_str) != Some("loaded")
    {
        return Err("recovery unit not installed".into());
    }
    Ok(map)
}

fn meaningful_time(value: Option<&String>) -> bool {
    value.is_some_and(|s| {
        !s.is_empty() && !matches!(s.as_str(), "n/a" | "0" | "0us" | "0 usec") && s.len() < 128
    })
}

fn summarize(
    timer: &HashMap<String, String>,
    service: &HashMap<String, String>,
    opted_in: bool,
) -> Value {
    let active = timer.get("ActiveState").map(String::as_str) == Some("active");
    let enabled = timer.get("UnitFileState").map(String::as_str) == Some("enabled");
    let timer_triggered = meaningful_time(timer.get("LastTriggerUSec"));
    let completed = meaningful_time(service.get("ExecMainExitTimestampMonotonic"));
    let result = service.get("Result").map(String::as_str);
    let code = service.get("ExecMainStatus").map(String::as_str);
    let success = timer_triggered && completed && result == Some("success") && code == Some("0");
    let state = if !opted_in {
        "not_opted_in"
    } else if !active || !enabled {
        "timer_not_active"
    } else if !timer_triggered {
        "awaiting_first_run"
    } else if success {
        "verified_last_run"
    } else {
        "last_run_unverified"
    };
    json!({
        "status":state,
        "recovery_opted_in":opted_in,
        "timer_enabled":enabled,
        "timer_active":active,
        "last_timer_trigger_observed":timer_triggered,
        "last_service_completion_observed":completed,
        "last_run_success":success,
        "next_run_scheduled":meaningful_time(timer.get("NextElapseUSecRealtime"))
            || meaningful_time(timer.get("NextElapseUSecMonotonic")),
        "read_only":true,
    })
}

pub fn snapshot(opted_in: bool) -> Result<String, String> {
    let timer = unit_properties(TIMER)?;
    let service = unit_properties(SERVICE)?;
    Ok(summarize(&timer, &service, opted_in).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (HashMap<String, String>, HashMap<String, String>) {
        let timer = HashMap::from([
            ("ActiveState".into(), "active".into()),
            ("UnitFileState".into(), "enabled".into()),
            (
                "LastTriggerUSec".into(),
                "Mon 2026-10-19 14:50:00 UTC".into(),
            ),
            (
                "NextElapseUSecRealtime".into(),
                "Mon 2026-10-19 14:55:00 UTC".into(),
            ),
        ]);
        let service = HashMap::from([
            ("Result".into(), "success".into()),
            ("ExecMainStatus".into(), "0".into()),
            (
                "ExecMainExitTimestampMonotonic".into(),
                "Mon 2026-10-19 14:50:04 UTC".into(),
            ),
        ]);
        (timer, service)
    }

    #[test]
    fn verified_success_requires_trigger_and_completed_service() {
        let (timer, service) = sample();
        let result = summarize(&timer, &service, true);
        assert_eq!(result["status"], "verified_last_run");
        assert_eq!(result["last_run_success"], true);
        assert_eq!(result["read_only"], true);
    }

    #[test]
    fn monotonic_next_elapse_is_a_valid_scheduled_run() {
        let (mut timer, service) = sample();
        timer.insert("NextElapseUSecRealtime".into(), "n/a".into());
        timer.insert("NextElapseUSecMonotonic".into(), "2h 17min".into());
        assert_eq!(summarize(&timer, &service, true)["next_run_scheduled"], true);
        timer.insert("NextElapseUSecMonotonic".into(), "n/a".into());
        assert_eq!(summarize(&timer, &service, true)["next_run_scheduled"], false);
    }

    #[test]
    fn failed_or_missing_run_is_never_green() {
        let (mut timer, mut service) = sample();
        timer.insert("LastTriggerUSec".into(), "n/a".into());
        assert_eq!(
            summarize(&timer, &service, true)["status"],
            "awaiting_first_run"
        );
        timer.insert("LastTriggerUSec".into(), "Mon 2026-10-19".into());
        service.insert("ExecMainStatus".into(), "1".into());
        assert_eq!(
            summarize(&timer, &service, true)["status"],
            "last_run_unverified"
        );
        service.insert("ExecMainStatus".into(), "0".into());
        service.insert("ExecMainExitTimestampMonotonic".into(), "0".into());
        assert_eq!(
            summarize(&timer, &service, true)["status"],
            "last_run_unverified"
        );
    }

    #[test]
    fn missing_opt_in_or_disabled_timer_is_not_green() {
        let (mut timer, service) = sample();
        assert_eq!(summarize(&timer, &service, false)["status"], "not_opted_in");
        timer.insert("ActiveState".into(), "inactive".into());
        assert_eq!(
            summarize(&timer, &service, true)["status"],
            "timer_not_active"
        );
    }

    #[test]
    fn unknown_unit_cannot_be_inspected() {
        assert!(unit_properties("sshd.service").is_err());
    }
}
