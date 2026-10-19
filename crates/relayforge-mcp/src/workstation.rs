//! Read-only, privacy-filtered inventory of the local MCP workstation.
//! Fixed paths and fixed commands; callers cannot select a host, path or
//! executable. Never returns environment variables, file contents or logs.
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn tool() -> Value {
    json!({"name":"relayforge_workstation_status",
        "description":"Read-only local ThinkPad development status: fixed RelayForge repo, uptime, available memory and Secure MCP Tunnel poll freshness. No shell or file access.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
}

// The invocation is not assembled from request input. Hard timeout bounds a
// stalled git/systemd/tunnel-client command; no shell ever interprets tokens.
// Outputs from commands are not forwarded, even on failure.
fn run_bounded(command: &str, args: &[&str]) -> Option<Output> {
    let result = Command::new("timeout")
        .arg("6s")
        .arg(command)
        .args(args)
        .output()
        .ok()?;
    if result.stdout.len() > 4096 || result.stderr.len() > 4096 {
        return None;
    }
    Some(result)
}

fn git(repo: &str, args: &[&str]) -> Option<Output> {
    let mut argv = vec![
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-C",
        repo,
    ];
    argv.extend_from_slice(args);
    run_bounded("git", &argv)
}

fn git_clean_result(output: Option<Output>) -> Option<bool> {
    // For 'git diff --quiet', exit 0 is clean; exit 1 means changes.
    // Any other failure, including timeout (124), is unknown, never green.
    let result = output?;
    match result.status.code()? {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

fn git_head(output: Option<Output>) -> Option<String> {
    let result = output?;
    if !result.status.success() {
        return None;
    }
    let s = std::str::from_utf8(&result.stdout).ok()?.trim();
    if ![40, 64].contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(s.to_owned())
}

fn uptime_seconds(input: &str) -> Option<u64> {
    let uptime = input.split_ascii_whitespace().next()?.parse::<f64>().ok()?;
    if !uptime.is_finite() || uptime < 0.0 || uptime > 10_000_000_000.0 {
        return None;
    }
    Some(uptime.floor() as u64)
}

fn available_memory_mib(input: &str) -> Option<u64> {
    let line = input
        .lines()
        .find(|line| line.starts_with("MemAvailable:"))?;
    let mut words = line.split_ascii_whitespace();
    if words.next() != Some("MemAvailable:") {
        return None;
    }
    let kib = words.next()?.parse::<u64>().ok()?;
    if words.next() != Some("kB") || words.next().is_some() {
        return None;
    }
    Some(kib / 1024)
}

fn poll_age_seconds(text: &str, now: u64) -> Option<u64> {
    if text.len() > 4096 {
        return None;
    }
    let parsed: Value = serde_json::from_str(text).ok()?;
    if parsed["result"] != "ok" {
        return None;
    }
    // tunnel-client may expose an integer or fractional Unix timestamp.
    let observed = parsed.pointer("/control_plane_poll/value")?.as_f64()?;
    if !observed.is_finite() || !(0.0..=(now as f64)).contains(&observed) {
        return None;
    }
    let age = now.checked_sub(observed.floor() as u64)?;
    (age <= 86400).then_some(age)
}

fn repository_snapshot(home: &str) -> Value {
    let mut repo = PathBuf::from(home);
    repo.push("Projects/relayforge");
    let path = repo.to_string_lossy();
    let head = git_head(git(&path, &["rev-parse", "--verify", "HEAD"]));
    let tracked_clean = git_clean_result(git(&path, &["diff", "--quiet", "HEAD", "--"]));
    let branch = git(&path, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .and_then(|v| v.status.success().then_some(v.stdout))
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .map(|name| name.trim() == "main");
    json!({
        "present":head.is_some(),
        "on_main":branch,
        "tracked_clean":tracked_clean,
        "head_commit":head
    })
}

fn tunnel_snapshot(home: &str) -> Value {
    let active = run_bounded(
        "systemctl",
        &[
            "--user",
            "is-active",
            "--quiet",
            "relayforge-tunnel.service",
        ],
    )
    .map(|output| output.status.success());
    let mut client = PathBuf::from(home);
    client.push(".local/libexec/relayforge/tunnel-client");
    let runtime = std::env::var("XDG_RUNTIME_DIR").ok();
    let health_file = runtime.map(|root| {
        let mut file = PathBuf::from(root);
        file.push("relayforge-tunnel/health.url");
        file.to_string_lossy().into_owned()
    });
    let freshness = if active == Some(true) {
        health_file.as_ref().and_then(|file| {
            let binary = client.to_str()?;
            let args = [
                "health",
                "--url-file",
                file.as_str(),
                "--require-control-plane-poll",
                "--json",
            ];
            let output = run_bounded(binary, &args)?;
            if !output.status.success() {
                return None;
            }
            let body = std::str::from_utf8(&output.stdout).ok()?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            poll_age_seconds(body, now)
        })
    } else {
        None
    };
    let recent = freshness.map(|age| age <= 30);
    json!({
        "service_active":active,
        "authenticated_poll_recent":recent,
        "last_successful_poll_age_seconds":freshness
    })
}

fn classify(repo: &Value, tunnel: &Value) -> &'static str {
    let repo_ok =
        repo["present"] == true && repo["on_main"] == true && repo["tracked_clean"] == true;
    let tunnel_ok = tunnel["service_active"] == true && tunnel["authenticated_poll_recent"] == true;
    if repo_ok && tunnel_ok {
        "healthy"
    } else if repo["present"] == false || tunnel["service_active"] == false {
        "degraded"
    } else {
        // Fail conservatively when a timestamp, branch, diff or systemd
        // command is unavailable. We do not claim the workstation is green.
        "unverified"
    }
}

pub fn snapshot(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|value| !value.is_empty()) {
        return Err("unexpected workstation arguments".into());
    }
    let home = std::env::var("HOME").map_err(|_| "workstation home unavailable")?;
    if !home.starts_with('/') || home.len() > 256 {
        return Err("workstation home invalid".into());
    }
    let repo = repository_snapshot(&home);
    let tunnel = tunnel_snapshot(&home);
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| uptime_seconds(&s));
    let memory = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| available_memory_mib(&s));
    Ok(json!({
        "status":classify(&repo, &tunnel),
        "scope":"local_workstation_only",
        "repository":repo,
        "tunnel":tunnel,
        "resources":{"uptime_seconds":uptime, "memory_available_mib":memory},
        "permissions":{"shell":false,"arbitrary_files":false,"service_mutation":false}
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    #[test]
    fn strictly_denies_request_parameters() {
        for args in [
            json!({"command":"id"}),
            json!({"path":"/home/user/.ssh/id_ed25519"}),
            json!({"host":"ru0"}),
            json!(null),
        ] {
            assert!(snapshot(&args).is_err());
        }
        assert_eq!(tool()["inputSchema"]["additionalProperties"], false);
    }

    #[test]
    fn parsing_never_claims_good_for_bad_input() {
        assert_eq!(uptime_seconds("123.42 12.0"), Some(123));
        assert_eq!(uptime_seconds("invalid"), None);
        assert_eq!(uptime_seconds("-10.00"), None);
        assert_eq!(
            available_memory_mib("MemAvailable: 2097152 kB\n"),
            Some(2048)
        );
        assert_eq!(available_memory_mib("MemAvailable: 123 MB\n"), None);
        assert_eq!(available_memory_mib("MemFree: 1234 kB\n"), None);
        let now = 1792360000u64;
        let input = format!(
            r#"{{"result":"ok","control_plane_poll":{{"value":{}}}}}"#,
            now - 3
        );
        assert_eq!(poll_age_seconds(&input, now), Some(3));
        let fractional = format!(
            r#"{{"result":"ok","control_plane_poll":{{"value":{}.25}}}}"#,
            now - 3
        );
        assert_eq!(poll_age_seconds(&fractional, now), Some(3));
        assert_eq!(poll_age_seconds(&input, now - 86400), None);
        assert_eq!(
            poll_age_seconds(
                r#"{"result":"degraded","control_plane_poll":{"value":1}}"#,
                now
            ),
            None
        );
    }

    #[test]
    fn diff_exit_code_excludes_timeout_and_errors() {
        for (exit, expected) in [(0, Some(true)), (1, Some(false)), (2, None), (124, None)] {
            let status = std::process::ExitStatus::from_raw(exit << 8);
            let output = Output {
                status,
                stdout: vec![],
                stderr: vec![],
            };
            assert_eq!(git_clean_result(Some(output)), expected);
        }
        assert_eq!(git_clean_result(None), None);
    }

    #[test]
    fn status_fails_closed_for_missing_evidence() {
        let valid_repo = json!({"present":true,"on_main":true,"tracked_clean":true});
        let valid_tunnel = json!({"service_active":true,"authenticated_poll_recent":true});
        assert_eq!(classify(&valid_repo, &valid_tunnel), "healthy");
        assert_eq!(
            classify(&json!({"present":false}), &valid_tunnel),
            "degraded"
        );
        assert_eq!(
            classify(&valid_repo, &json!({"service_active":false})),
            "degraded"
        );
        assert_eq!(classify(&valid_repo, &json!({})), "unverified");
        assert_eq!(
            classify(&json!({"present":true}), &valid_tunnel),
            "unverified"
        );
    }
}
