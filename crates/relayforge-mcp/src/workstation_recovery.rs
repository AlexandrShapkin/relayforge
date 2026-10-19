//! Read-only, secret-free status of the opt-in local recovery watchdog.
//! Never exposes journals, unit file contents, command lines or credentials.
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const TIMER: &str = "relayforge-local-recover.timer";
const SERVICE: &str = "relayforge-local-recover.service";
const MAX_OUTPUT: usize = 8192;
// Timer runs every ~5 minutes; 20 minutes tolerates host load and timer jitter.
const MAX_LAST_RUN_AGE_SECONDS: i64 = 20 * 60;
const MAX_SERVICE_DURATION_SECONDS: i64 = 10 * 60;

fn unit_properties(unit: &str) -> Result<HashMap<String, String>, String> {
    let property = match unit {
        TIMER => "Id,LoadState,ActiveState,UnitFileState,LastTriggerUSec,NextElapseUSecRealtime,NextElapseUSecMonotonic",
        SERVICE => "Id,LoadState,ActiveState,Result,ExecMainStatus,ExecMainCode,ExecMainExitTimestamp",
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
        .env("TZ", "UTC") // Strict, comparable timestamps independent of host locale.
        .env("LC_ALL", "C")
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

// systemctl show emits "Mon 2026-10-19 14:50:00 UTC" for USec
// properties. Parse this narrow UTC grammar, never a free-form locale date.
// Invalid, missing and out-of-range clocks fail closed.
fn utc_epoch(raw: Option<&String>) -> Option<i64> {
    let raw = raw?;
    let parts: Vec<_> = raw.split_whitespace().collect();
    if parts.len() != 4 || parts[0].len() != 3 || parts[3] != "UTC" {
        return None;
    }
    let date = parts[1];
    let clock = parts[2];
    if date.len() != 10 || clock.len() != 8 {
        return None;
    }
    let d: Vec<_> = date.split('-').collect();
    let t: Vec<_> = clock.split(':').collect();
    if d.len() != 3 || t.len() != 3 {
        return None;
    }
    let year = d[0].parse::<i64>().ok()?;
    let month = d[1].parse::<i64>().ok()?;
    let day = d[2].parse::<i64>().ok()?;
    let hour = t[0].parse::<i64>().ok()?;
    let minute = t[1].parse::<i64>().ok()?;
    let second = t[2].parse::<i64>().ok()?;
    if !(2000..=2100).contains(&year)
        || !(1..=12).contains(&month)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..60).contains(&second)
    {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > days_in_month {
        return None;
    }
    // Gregorian civil date -> days since Unix epoch, integer-only.
    let y = year - if month <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some((era * 146097 + doe - 719468) * 86400 + hour * 3600 + minute * 60 + second)
}

fn summarize(
    timer: &HashMap<String, String>,
    service: &HashMap<String, String>,
    opted_in: bool,
    now_epoch: i64,
) -> Value {
    let active = timer.get("ActiveState").map(String::as_str) == Some("active");
    let enabled = timer.get("UnitFileState").map(String::as_str) == Some("enabled");
    let timer_triggered = meaningful_time(timer.get("LastTriggerUSec"));
    let completed = meaningful_time(service.get("ExecMainExitTimestamp"));
    let timer_at = utc_epoch(timer.get("LastTriggerUSec"));
    let service_at = utc_epoch(service.get("ExecMainExitTimestamp"));
    let result = service.get("Result").map(String::as_str);
    let code = service.get("ExecMainStatus").map(String::as_str);
    let historically_successful =
        timer_triggered && completed && result == Some("success") && code == Some("0");
    let last_run_fresh = timer_at
        .is_some_and(|at| (0..=MAX_LAST_RUN_AGE_SECONDS).contains(&(now_epoch - at)))
        && service_at.is_some_and(|at| {
            (0..=MAX_LAST_RUN_AGE_SECONDS).contains(&(now_epoch - at))
                && timer_at.is_some_and(|trigger| {
                    (0..=MAX_SERVICE_DURATION_SECONDS).contains(&(at - trigger))
                })
        });
    let success = historically_successful && last_run_fresh;
    let state = if !opted_in {
        "not_opted_in"
    } else if !active || !enabled {
        "timer_not_active"
    } else if !timer_triggered {
        "awaiting_first_run"
    } else if success {
        "verified_last_run"
    } else if historically_successful
        && timer_at.is_some()
        && service_at.is_some()
        && !last_run_fresh
    {
        "last_run_stale"
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
        "last_run_fresh":last_run_fresh,
        "next_run_scheduled":meaningful_time(timer.get("NextElapseUSecRealtime"))
            || meaningful_time(timer.get("NextElapseUSecMonotonic")),
        "read_only":true,
    })
}

pub fn snapshot(opted_in: bool) -> Result<String, String> {
    let timer = unit_properties(TIMER)?;
    let service = unit_properties(SERVICE)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock unavailable")?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| "system clock unavailable")?;
    Ok(summarize(&timer, &service, opted_in, now).to_string())
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
                "ExecMainExitTimestamp".into(),
                "Mon 2026-10-19 14:50:04 UTC".into(),
            ),
        ]);
        (timer, service)
    }

    const SAMPLE_NOW: i64 = 1792421460; // 2026-10-19 14:51 UTC

    #[test]
    fn verified_success_requires_trigger_and_completed_service() {
        let (timer, service) = sample();
        let result = summarize(&timer, &service, true, SAMPLE_NOW);
        assert_eq!(result["status"], "verified_last_run");
        assert_eq!(result["last_run_success"], true);
        assert_eq!(result["read_only"], true);
    }

    #[test]
    fn monotonic_next_elapse_is_a_valid_scheduled_run() {
        let (mut timer, service) = sample();
        timer.insert("NextElapseUSecRealtime".into(), "n/a".into());
        timer.insert("NextElapseUSecMonotonic".into(), "2h 17min".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["next_run_scheduled"],
            true
        );
        timer.insert("NextElapseUSecMonotonic".into(), "n/a".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["next_run_scheduled"],
            false
        );
    }

    #[test]
    fn failed_or_missing_run_is_never_green() {
        let (mut timer, mut service) = sample();
        timer.insert("LastTriggerUSec".into(), "n/a".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["status"],
            "awaiting_first_run"
        );
        timer.insert("LastTriggerUSec".into(), "Mon 2026-10-19".into());
        service.insert("ExecMainStatus".into(), "1".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["status"],
            "last_run_unverified"
        );
        service.insert("ExecMainStatus".into(), "0".into());
        service.insert("ExecMainExitTimestamp".into(), "0".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["status"],
            "last_run_unverified"
        );
    }

    #[test]
    fn missing_opt_in_or_disabled_timer_is_not_green() {
        let (mut timer, service) = sample();
        assert_eq!(
            summarize(&timer, &service, false, SAMPLE_NOW)["status"],
            "not_opted_in"
        );
        timer.insert("ActiveState".into(), "inactive".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["status"],
            "timer_not_active"
        );
    }

    #[test]
    fn stale_and_future_runs_never_pass_as_recent() {
        let (mut timer, mut service) = sample();
        let old = SAMPLE_NOW + MAX_LAST_RUN_AGE_SECONDS + 1;
        let result = summarize(&timer, &service, true, old);
        assert_eq!(result["status"], "last_run_stale");
        assert_eq!(result["last_run_success"], false);
        assert_eq!(result["last_run_fresh"], false);
        let future = SAMPLE_NOW - 600;
        assert_eq!(
            summarize(&timer, &service, true, future)["status"],
            "last_run_stale"
        );
        timer.insert("LastTriggerUSec".into(), "n/a".into());
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["status"],
            "awaiting_first_run"
        );
        timer.insert(
            "LastTriggerUSec".into(),
            "Mon 2026-10-19 14:50:00 UTC".into(),
        );
        service.insert(
            "ExecMainExitTimestamp".into(),
            "Mon 2026-10-19 14:49:00 UTC".into(),
        );
        assert_eq!(
            summarize(&timer, &service, true, SAMPLE_NOW)["status"],
            "last_run_stale"
        );
    }

    #[test]
    fn monotonic_counter_is_not_a_wall_clock_timestamp() {
        let (timer, mut service) = sample();
        // systemd may expose an integer here; never reinterpret uptime as UTC.
        service.remove("ExecMainExitTimestamp");
        service.insert("ExecMainExitTimestampMonotonic".into(), "7933587912".into());
        let result = summarize(&timer, &service, true, SAMPLE_NOW);
        assert_eq!(result["last_run_success"], false);
        assert_eq!(result["status"], "last_run_unverified");
    }

    #[test]
    fn utc_timestamp_parser_rejects_malformed_and_invalid_calendar_values() {
        for input in [
            "n/a",
            "0",
            "Mon 2026-02-30 14:50:00 UTC",
            "Mon 2026-10-19 24:50:00 UTC",
            "Mon 2026-10-19 14:60:00 UTC",
            "Mon 2026-10-19 14:50:00 CEST",
            "2026-10-19 14:50:00 UTC",
            "Mon 2026-10-19 14:50:00 UTC extra",
        ] {
            assert_eq!(utc_epoch(Some(&input.to_owned())), None, "{input}");
        }
        assert_eq!(
            utc_epoch(Some(&"Mon 2026-10-19 14:50:00 UTC".into())),
            Some(1792421400)
        );
    }

    #[test]
    fn unknown_unit_cannot_be_inspected() {
        assert!(unit_properties("sshd.service").is_err());
    }
}
