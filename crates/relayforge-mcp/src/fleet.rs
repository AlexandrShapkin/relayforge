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

pub fn tool() -> Value {
    json!({"name":"relayforge_fleet_health",
        "description":"Read-only snapshot of required user services and scheduled timers on ru0, ru1 and srv0, queried in parallel via authenticated Rust agents. Reports degraded and unreachable nodes explicitly.",
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
    json!({"host":host,"status":if all_healthy {"healthy"} else {"degraded"},
        "units":unit_states})
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
    let all_healthy = hosts.iter().all(|host| host["status"] == "healthy");
    let captured = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|timestamp| timestamp.as_secs())
        .unwrap_or(0);
    json!({"overall":if all_healthy {"healthy"} else {"degraded"},
           "checked_at_unix":captured, "hosts":hosts})
}

pub fn snapshot(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|obj| !obj.is_empty()) {
        return Err("unexpected fleet health arguments".into());
    }
    Ok(snapshot_with(&|host| {
        crate::agent::query(&json!({"host":host,"operation":"user.service.list"}))
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
        json!({"scope":"user","units":expected.iter().map(|name|json!({
            "unit":name,"active":"active","sub":"running"})).collect::<Vec<_>>()})
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
                Ok(json!({"scope":"user","units":[]}).to_string())
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
    fn reject_nonempty_arguments() {
        assert!(snapshot(&json!({"host":"ru0"})).is_err());
    }
}
