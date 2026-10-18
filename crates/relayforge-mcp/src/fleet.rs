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
const RU1_UNITS: &[&str] = &[
    "assistant-hub-demo.service",
    "remote-desktop.service",
    "assistant-hub-backup.timer",
    "assistant-hub-monitor.timer",
];
const SRV0_UNITS: &[&str] = &["remote-desktop.service"];
const HOSTS: &[(&str, &[&str])] = &[("ru0", RU0_UNITS), ("ru1", RU1_UNITS), ("srv0", SRV0_UNITS)];
const RU0_TIMERS: &[&str] = &[
    "assistant-hub-backup.timer",
    "assistant-hub-google-calendar.timer",
    "assistant-hub-university-calendar.timer",
];
const RU1_TIMERS: &[&str] = &["assistant-hub-backup.timer", "assistant-hub-monitor.timer"];

fn expected_jobs(host: &str) -> (&'static str, &'static [&'static str]) {
    match host {
        "ru0" => ("ru0.alexandrshapkin.ru", RU0_TIMERS),
        "ru1" => ("ru1.alexandrshapkin.ru", RU1_TIMERS),
        _ => ("srv0", &[]),
    }
}

pub fn tool() -> Value {
    json!({"name":"relayforge_fleet_health",
         "description":"Read-only fleet health plus outcomes of scheduled backup/calendar/monitor jobs, via Rust agents on ru0, ru1, srv0. Reports unknown, stale and failed jobs separately; never runs a service.",
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
    json!({"host":host,"status":if !all_healthy {"degraded"}
        else if needs_attention {"attention"} else {"healthy"},
        "units":unit_states,"scheduled_jobs":job_states})
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
            "ru1" => RU1_UNITS,
            _ => SRV0_UNITS,
        };
        let (hostname, expected_timers) = expected_jobs(host);
        json!({"scope":"user","host":hostname,
            "units":expected.iter().map(|name|json!({
                "unit":name,"active":"active","sub":"running"})).collect::<Vec<_>>(),
            "scheduled_jobs":expected_timers.iter().map(|timer|json!({
                "timer":timer,"status":"success","reason":"completed_successfully",
                "timer_active":true,
                "last_trigger_at":"today","next_scheduled_at":"tomorrow",
                "minutes_since_completion":15,"max_age_minutes":120
            })).collect::<Vec<_>>()})
        .to_string()
    }

    #[test]
    fn all_hosts_healthy_when_required_units_active() {
        let result = snapshot_with(&|host| Ok(mock_for(host)));
        assert_eq!(result["overall"], "healthy");
        assert_eq!(result["hosts"].as_array().unwrap().len(), 3);
        assert!(result["checked_at_unix"].as_u64().unwrap() > 0);
    }

    #[test]
    fn missing_unit_means_degraded_not_healthy() {
        let result = snapshot_with(&|host| {
            if host == "ru0" {
                {
                    let mut reply: Value = serde_json::from_str(&mock_for(host)).unwrap();
                    reply["units"] = json!([]);
                    Ok(reply.to_string())
                }
            } else {
                Ok(mock_for(host))
            }
        });
        assert_eq!(result["overall"], "degraded");
        assert_eq!(result["hosts"][0]["status"], "degraded");
        assert_eq!(result["hosts"][0]["units"][0]["active"], "missing");
    }

    #[test]
    fn unavailable_and_malformed_agents_are_not_green() {
        let result = snapshot_with(&|host| match host {
            "ru0" => Err("connection refused".into()),
            "ru1" => Ok("{}".into()),
            _ => Ok(mock_for(host)),
        });
        assert_eq!(result["overall"], "degraded");
        assert_eq!(result["hosts"][0]["reason"], "agent_unavailable");
        assert_eq!(result["hosts"][1]["reason"], "invalid_agent_response");
        assert_eq!(result["hosts"][2]["status"], "healthy");
    }

    #[test]
    fn unknown_last_run_is_attention_not_verified_healthy() {
        let result = snapshot_with(&|host| {
            let mut v: Value = serde_json::from_str(&mock_for(host)).unwrap();
            if host == "ru0" {
                v["scheduled_jobs"][0]["status"] = json!("unverified");
                v["scheduled_jobs"][0]["reason"] = json!("no_completion_observed_this_boot");
            }
            Ok(v.to_string())
        });
        assert_eq!(result["overall"], "attention");
        assert_eq!(result["hosts"][0]["status"], "attention");
        assert_eq!(
            result["hosts"][0]["scheduled_jobs"][0]["status"],
            "unverified"
        );
    }

    #[test]
    fn stale_or_failed_scheduled_job_is_degraded() {
        for state in ["stale", "failed"] {
            let result = snapshot_with(&|host| {
                let mut v: Value = serde_json::from_str(&mock_for(host)).unwrap();
                if host == "ru1" {
                    v["scheduled_jobs"][1]["status"] = json!(state);
                }
                Ok(v.to_string())
            });
            assert_eq!(result["overall"], "degraded");
            assert_eq!(result["hosts"][1]["status"], "degraded");
        }
    }

    #[test]
    fn malformed_job_telemetry_does_not_return_green() {
        let result = snapshot_with(&|host| {
            let mut v: Value = serde_json::from_str(&mock_for(host)).unwrap();
            if host == "ru0" {
                v.as_object_mut().unwrap().remove("scheduled_jobs");
            }
            if host == "ru1" {
                v["host"] = json!("ru0.alexandrshapkin.ru");
            }
            Ok(v.to_string())
        });
        assert_eq!(result["overall"], "degraded");
        assert_eq!(result["hosts"][0]["status"], "unreachable");
        assert_eq!(result["hosts"][1]["reason"], "agent_hostname_mismatch");
    }

    #[test]
    fn reject_nonempty_arguments() {
        assert!(snapshot(&json!({"host":"ru0"})).is_err());
    }
}
