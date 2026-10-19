//! Bounded, read-only fleet health snapshot via already authenticated agents.
//! Each host uses one SSH connection, checked in parallel to avoid serial
//! timeouts if a single host is offline. No generic command execution.
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const RU0_UNITS: &[&str] = &[
    "assistant-hub-local.service",
    "personal-xray.service",
    "remote-desktop.service",
    "assistant-hub-backup.timer",
    "assistant-hub-google-calendar.timer",
    "assistant-hub-university-calendar.timer",
];
const SRV0_UNITS: &[&str] = &["remote-desktop.service"];
const HOSTS: &[(&str, &[&str])] = &[("ru0", RU0_UNITS), ("srv0", SRV0_UNITS)];
const RU0_TIMERS: &[&str] = &[
    "assistant-hub-backup.timer",
    "assistant-hub-google-calendar.timer",
    "assistant-hub-university-calendar.timer",
];
const RU0_ARTIFACTS: &[&str] = &[
    "ru0_private_backup",
    "ru0_google_main_mirror",
    "ru0_university_mirror",
];
fn expected_artifacts(host: &str) -> &'static [&'static str] {
    match host {
        "ru0" => RU0_ARTIFACTS,
        _ => &[],
    }
}

fn expected_jobs(host: &str) -> (&'static str, &'static [&'static str]) {
    match host {
        "ru0" => ("ru0.alexandrshapkin.ru", RU0_TIMERS),
        _ => ("srv0", &[]),
    }
}

pub fn tool() -> Value {
    json!({"name":"relayforge_fleet_health",
         "description":"Read-only fleet health, outcomes of scheduled jobs and privacy-filtered evidence from actual backup/SQLite/calendar/health files. No private data is returned, no service actions.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
}

fn parse_host(host: &str, expected: &[&str], reply: Result<String, String>) -> Value {
    let raw = match reply {
        Ok(raw) => raw,
        Err(_) => {
            return json!({
                "host":host,"status":"unreachable","units":[],
                "reason":"agent_unavailable"
            })
        }
    };
    let data: Value = match serde_json::from_str(&raw) {
        Ok(data) => data,
        Err(_) => {
            return json!({
                "host":host,"status":"unreachable","units":[],
                "reason":"invalid_agent_response"
            })
        }
    };
    if data.get("scope").and_then(Value::as_str) != Some("user") {
        return json!({"host":host,"status":"unreachable","units":[],
            "reason":"invalid_agent_response"});
    }
    let Some(list) = data.get("units").and_then(Value::as_array) else {
        return json!({"host":host,"status":"unreachable","units":[],
            "reason":"invalid_agent_response"});
    };
    let (expected_hostname, expected_timers) = expected_jobs(host);
    if data["host"].as_str() != Some(expected_hostname) {
        return json!({"host":host,"status":"unreachable","units":[],
            "reason":"agent_hostname_mismatch"});
    }
    let Some(remote_jobs) = data.get("scheduled_jobs").and_then(Value::as_array) else {
        return json!({"host":host,"status":"unreachable","units":[],
            "reason":"job_telemetry_unavailable"});
    };
    let Some(remote_artifacts) = data.get("artifact_results").and_then(Value::as_array) else {
        return json!({"host":host,"status":"unreachable","units":[],
            "reason":"artifact_telemetry_unavailable"});
    };
    let mut all_healthy = true;
    let unit_states: Vec<Value> = expected
        .iter()
        .map(|expected_name| {
            let match_unit = list
                .iter()
                .find(|v| v.get("unit").and_then(Value::as_str) == Some(*expected_name));
            let (active, sub) = match match_unit {
                Some(v) => (
                    v.get("active").and_then(Value::as_str).unwrap_or("unknown"),
                    v.get("sub").and_then(Value::as_str).unwrap_or("unknown"),
                ),
                None => ("missing", "unknown"),
            };
            if active != "active" {
                all_healthy = false;
            }
            json!({"unit":expected_name,"active":active,"sub":sub})
        })
        .collect();
    let mut needs_attention = false;
    let job_states: Vec<Value> = expected_timers
        .iter()
        .map(|timer| {
            let item = remote_jobs
                .iter()
                .find(|j| j["timer"].as_str() == Some(*timer));
            match item {
                None => {
                    all_healthy = false;
                    json!({"timer":timer,"status":"missing","reason":"job_telemetry_missing"})
                }
                Some(info) => {
                    let status = info["status"].as_str().unwrap_or("unverified");
                    match status {
                        "success" if info["timer_active"] == true => {}
                        "running" | "unverified" => needs_attention = true,
                        _ => all_healthy = false,
                    }
                    // Only fixed telemetry fields are returned. The Rust agent
                    // already filters systemd properties and job unit names.
                    json!({"timer":timer,"service":info["service"],
                    "status":status,"reason":info["reason"],
                    "last_trigger_at":info["last_trigger_at"],
                    "next_scheduled_at":info["next_scheduled_at"],
                    "minutes_since_completion":info["minutes_since_completion"],
                    "max_age_minutes":info["max_age_minutes"]})
                }
            }
        })
        .collect();
    let artifact_states: Vec<Value> = expected_artifacts(host)
        .iter()
        .map(|expected_name| {
            let Some(artifact) = remote_artifacts
                .iter()
                .find(|a| a["name"].as_str() == Some(*expected_name))
            else {
                all_healthy = false;
                return json!({"name":expected_name,"status":"missing",
                "reason":"artifact_telemetry_missing"});
            };
            let status = artifact["status"].as_str().unwrap_or("invalid");
            match status {
                "verified" => {}
                "unverified" => needs_attention = true,
                "stale" | "failed" => all_healthy = false,
                _ => all_healthy = false,
            }
            // Never forward arbitrary nested fields from the agent; project
            // only bounded, explicitly approved non-content evidence fields.
            json!({
                "name":expected_name,
                "status":status,
                "reason":artifact["reason"].as_str()
                    .filter(|s| s.len()<=80).unwrap_or("invalid_reason"),
                "age_minutes":artifact["age_minutes"].as_u64(),
                "mirrored_event_count":artifact["mirrored_event_count"].as_u64(),
                "aggregator_ok":artifact["aggregator_ok"].as_bool(),
                "vpn_probe_ok":artifact["vpn_probe_ok"].as_bool(),
                "remote_desktop_ok":artifact["remote_desktop_ok"].as_bool(),
            })
        })
        .collect();
    json!({"host":host,"status":if !all_healthy {"degraded"}
        else if needs_attention {"attention"} else {"healthy"},
        "units":unit_states,"scheduled_jobs":job_states,
        "artifact_results":artifact_states})
}

fn snapshot_with<F>(query: &F) -> Value
where
    F: Fn(&str) -> Result<String, String> + Sync,
{
    let hosts = std::thread::scope(|scope| {
        let tasks: Vec<_> = HOSTS
            .iter()
            .map(|(host, expected)| scope.spawn(move || parse_host(host, expected, query(host))))
            .collect();
        tasks
            .into_iter()
            .map(|job| {
                job.join().unwrap_or_else(|_| {
            json!({"host":"unknown","status":"unreachable","units":[],"reason":"task_failed"})
        })
            })
            .collect::<Vec<_>>()
    });
    let overall = if hosts
        .iter()
        .any(|host| host["status"] == "degraded" || host["status"] == "unreachable")
    {
        "degraded"
    } else if hosts.iter().any(|host| host["status"] == "attention") {
        "attention"
    } else {
        "healthy"
    };
    let captured = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|timestamp| timestamp.as_secs())
        .unwrap_or(0);
    json!({"overall":overall,
           "checked_at_unix":captured, "hosts":hosts})
}

pub fn snapshot(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|obj| !obj.is_empty()) {
        return Err("unexpected fleet health arguments".into());
    }
    Ok(snapshot_with(&|host| {
        crate::agent::query(&json!({"host":host,"operation":"user.jobs.summary"}))
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_for(host: &str) -> String {
        let expected = match host {
            "ru0" => RU0_UNITS,
            _ => SRV0_UNITS,
        };
        let (hostname, timers) = expected_jobs(host);
        json!({
            "scope":"user","host":hostname,
            "artifact_results":expected_artifacts(host).iter().map(|name|
                json!({"name":name,"status":"verified","reason":"fixture_ok",
                    "age_minutes":10})
            ).collect::<Vec<_>>(),
            "units":expected.iter().map(|name|json!({
                "unit":name,"active":"active","sub":"running"
            })).collect::<Vec<_>>(),
            "scheduled_jobs":timers.iter().map(|timer|json!({
                "timer":timer,"status":"success","reason":"completed_successfully",
                "timer_active":true,"last_trigger_at":"today",
                "next_scheduled_at":"tomorrow",
                "minutes_since_completion":15,"max_age_minutes":120
            })).collect::<Vec<_>>()
        }).to_string()
    }

    #[test]
    fn only_current_hosts_are_monitored() {
        let result = snapshot_with(&|host| Ok(mock_for(host)));
        assert_eq!(result["overall"], "healthy");
        assert_eq!(result["hosts"].as_array().unwrap().len(), 2);
        assert_eq!(result["hosts"][0]["host"], "ru0");
        assert_eq!(result["hosts"][1]["host"], "srv0");
        assert!(result["checked_at_unix"].as_u64().unwrap() > 0);
    }

    #[test]
    fn missing_unit_degrades_health() {
        let result = snapshot_with(&|host| {
            let mut data: Value = serde_json::from_str(&mock_for(host)).unwrap();
            if host == "ru0" {
                data["units"] = json!([]);
            }
            Ok(data.to_string())
        });
        assert_eq!(result["overall"], "degraded");
        assert_eq!(result["hosts"][0]["units"][0]["active"], "missing");
    }

    #[test]
    fn unreachable_and_malformed_agents_are_not_healthy() {
        let unavailable = snapshot_with(&|host| {
            if host == "ru0" {Err("connection refused".into())}
            else {Ok(mock_for(host))}
        });
        assert_eq!(unavailable["overall"], "degraded");
        assert_eq!(unavailable["hosts"][0]["reason"], "agent_unavailable");
        let malformed = snapshot_with(&|host| {
            if host == "srv0" {Ok("{}".into())}
            else {Ok(mock_for(host))}
        });
        assert_eq!(malformed["overall"], "degraded");
        assert_eq!(malformed["hosts"][1]["reason"], "invalid_agent_response");
    }

    #[test]
    fn unverified_job_or_artifact_needs_attention() {
        let result = snapshot_with(&|host| {
            let mut data: Value = serde_json::from_str(&mock_for(host)).unwrap();
            if host == "ru0" {
                data["scheduled_jobs"][0]["status"] = json!("unverified");
                data["artifact_results"][1]["status"] = json!("unverified");
            }
            Ok(data.to_string())
        });
        assert_eq!(result["overall"], "attention");
        assert_eq!(result["hosts"][0]["status"], "attention");
    }

    #[test]
    fn stale_job_or_failed_backup_degrades_health() {
        for field in ["scheduled_jobs", "artifact_results"] {
            let result = snapshot_with(&|host| {
                let mut data: Value = serde_json::from_str(&mock_for(host)).unwrap();
                if host == "ru0" {
                    data[field][0]["status"] = json!("failed");
                }
                Ok(data.to_string())
            });
            assert_eq!(result["overall"], "degraded");
        }
    }

    #[test]
    fn malformed_telemetry_cannot_report_green() {
        let result = snapshot_with(&|host| {
            let mut data: Value = serde_json::from_str(&mock_for(host)).unwrap();
            if host == "ru0" {
                data.as_object_mut().unwrap().remove("scheduled_jobs");
            }
            Ok(data.to_string())
        });
        assert_eq!(result["overall"], "degraded");
        assert_eq!(result["hosts"][0]["reason"], "job_telemetry_unavailable");
    }

    #[test]
    fn rejects_unexpected_arguments() {
        assert!(snapshot(&json!({"host":"ru0"})).is_err());
    }
}
