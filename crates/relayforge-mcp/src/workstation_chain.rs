//! Bounded, sequential, offline sandbox jobs.
//! Step N receives the validated stdout of step N-1 on stdin. No shell,
//! credentials, network, filesystem writes outside per-step /tmp or recursion.
use crate::workstation_jobs::{
    self as jobs, job_dir, read_text, schedule_worker, script_valid, write_private,
};
use serde_json::{json, Value};
use std::{fs, path::Path};

const MAX_STEPS: usize = 6;
const MAX_HANDOFF: usize = 8 * 1024;
const MAX_CHAIN_TIME: u32 = 3600;
const MAX_CHAIN_BYTES: usize = 16 * 1024;

pub(crate) fn chain_count(dir: &Path) -> Result<usize, String> {
    let s = read_text(dir, "chain.count", 16)?.ok_or("not a chain")?;
    let n = s.parse::<usize>().map_err(|_| "invalid chain receipt")?;
    if !(2..=MAX_STEPS).contains(&n) {
        return Err("invalid chain size".into());
    }
    Ok(n)
}

fn scripts(args: &Value) -> Result<Vec<&str>, String> {
    let params = args
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or("chain parameters required")?;
    if params.len() != 1 {
        return Err("unexpected chain parameters".into());
    }
    let steps = params
        .get("scripts")
        .and_then(Value::as_array)
        .ok_or("scripts required")?;
    if !(2..=MAX_STEPS).contains(&steps.len()) {
        return Err("chain size denied".into());
    }
    let mut total = 0;
    let mut out = Vec::with_capacity(steps.len());
    for step in steps {
        let source = step.as_str().ok_or("chain script not text")?;
        if !script_valid(source) {
            return Err("invalid chain script".into());
        }
        total += source.len();
        if total > MAX_CHAIN_BYTES {
            return Err("chain script budget exceeded".into());
        }
        out.push(source);
    }
    Ok(out)
}

fn artifact_name(step: usize, suffix: &str) -> String {
    format!("step-{step:02}.{suffix}")
}

pub(crate) fn artifact_allowed(name: &str, n: usize) -> bool {
    if name == "chain.count" {
        return true;
    }
    (1..=n).any(|i| {
        ["sh", "stdout", "stderr", "json"]
            .iter()
            .any(|suffix| name == artifact_name(i, suffix))
    })
}

fn submit(home: &Path, steps: Vec<&str>) -> Result<String, String> {
    let root = jobs::root(home, true)?.ok_or("job directory unavailable")?;
    if jobs::inventory(&root)?.len() >= jobs::MAX_JOBS {
        return Err("job capacity reached; remove completed jobs first".into());
    }
    let id = jobs::new_id()?;
    let dir = root.join(&id);
    let mut builder = fs::DirBuilder::new();
    use std::os::unix::fs::DirBuilderExt;
    builder.mode(0o700)
        .create(&dir)
        .map_err(|_| "job directory unavailable")?;
    // Scripts are immutable create_new 0600 files. Publish the count only
    // after ALL scripts are durable; nothing runs until schedule_worker.
    for (i, source) in steps.iter().enumerate() {
        write_private(&dir, &artifact_name(i + 1, "sh"), source.as_bytes())?;
    }
    write_private(&dir, "chain.count", steps.len().to_string().as_bytes())?;
    schedule_worker(home, &id, MAX_CHAIN_TIME)?;
    Ok(json!({
        "job_id":id, "chain":true, "steps":steps.len(),
        "started":true, "limit_seconds":MAX_CHAIN_TIME
    }).to_string())
}

fn stage_accepted(result: &jobs::StageResult, handoff_needed: bool) -> bool {
    result.exit_code == 0
        && !result.stdout_truncated
        && !result.stderr_truncated
        && (!handoff_needed || (
            result.stdout.len() <= MAX_HANDOFF
            && std::str::from_utf8(&result.stdout).is_ok()
        ))
}

fn persist_final(dir: &Path, index: usize, code: i32, kind: Option<&str>) -> Result<(), String> {
    let mut value = json!({
        "state":"finished", "exit_code":code, "chain":true,
        "completed_steps":index, "stdout_truncated":false,
        "stderr_truncated":false
    });
    if let Some(kind) = kind {
        value["failure_kind"] = json!(kind);
    }
    write_private(dir, "result.json", value.to_string().as_bytes())
}

/// Called by the same locally installed fixed worker as an ordinary job.
pub(crate) fn run(home: &Path, id: &str) -> Result<i32, String> {
    let dir = job_dir(home, id)?;
    let total = chain_chain_count(&dir)?;
    let mut previous = None;
    for i in 1..=total {
        let script = artifact_name(i, "sh");
        if read_text(&dir, &script, jobs::MAX_SCRIPT)?.is_none() {
            return Err("chain script unavailable".into());
        }
        let result = jobs::sandbox_stage(home, &dir.join(&script), previous.as_deref())?;
        let stdout_name = artifact_name(i, "stdout");
        let stderr_name = artifact_name(i, "stderr");
        write_private(&dir, &stdout_name, &result.stdout)?;
        write_private(&dir, &stderr_name, &result.stderr)?;
        let stage_code = if stage_accepted(&result, i < total) {
            0
        } else if result.exit_code != 0 {
            result.exit_code
        } else {
            1
        };
        write_private(
            &dir,
            &artifact_name(i, "json"),
            json!({
                "step":i, "exit_code":stage_code,
                "stdout_truncated":result.stdout_truncated,
                "stderr_truncated":result.stderr_truncated,
                "handoff_accepted":stage_code == 0
            })
            .to_string()
            .as_bytes(),
        )?;
        if stage_code != 0 {
            persist_final(&dir, i, stage_code, Some("stage_failed"))?;
            return Ok(stage_code);
        }
        previous = Some(dir.join(stdout_name));
        if i == total {
            // Preserve compatibility with existing job.output consumers.
            write_private(&dir, "stdout.log", &result.stdout)?;
            write_private(&dir, "stderr.log", &result.stderr)?;
            persist_final(&dir, i, 0, None)?;
            return Ok(0);
        }
    }
    Err("chain incomplete".into())
}

fn status(home: &Path, id: &str) -> Result<String, String> {
    let dir = job_dir(home, id)?;
    let total = chain_count(&dir)?;
    let base = jobs::job_status(home, id)?;
    let mut completed = 0;
    for i in 1..=total {
        if read_text(&dir, &artifact_name(i, "json"), 512)?.is_some() {
            completed += 1;
        } else {
            break;
        }
    }
    Ok(json!({
        "job_id":id, "chain":true, "steps":total,
        "completed_steps":completed,
        "state":base["state"], "exit_code":base.get("exit_code"),
        "failure_kind":base.get("failure_kind")
    }).to_string())
}

fn output(home: &Path, id: &str, step: usize) -> Result<String, String> {
    let dir = job_dir(home, id)?;
    let total = chain_count(&dir)?;
    if !(1..=total).contains(&step) {
        return Err("step out of range".into());
    }
    let receipt = read_text(&dir, &artifact_name(step, "json"), 512)?;
    let detail = receipt.map(|s| serde_json::from_str::<Value>(&s))
        .transpose().map_err(|_| "invalid stage receipt")?;
    Ok(json!({
        "job_id":id, "step":step, "steps":total, "result":detail,
        "stdout":read_text(&dir, &artifact_name(step, "stdout"), jobs::MAX_LOG)?
            .unwrap_or_default(),
        "stderr":read_text(&dir, &artifact_name(step, "stderr"), jobs::MAX_LOG)?
            .unwrap_or_default()
    }).to_string())
}

pub(crate) fn execute(home: &Path, args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("expected object")?;
    match obj.get("operation").and_then(Value::as_str) {
        Some("job.chain.start") if obj.len() == 2 => submit(home, scripts(args)?),
        Some("job.chain.status") if obj.len() == 2 => {
            let id = obj.get("task_id").and_then(Value::as_str)
                .ok_or("job ID required")?;
            status(home, id)
        }
        Some("job.chain.output") if obj.len() == 3 => {
            let id = obj.get("task_id").and_then(Value::as_str)
                .ok_or("job ID required")?;
            let params = obj.get("parameters").and_then(Value::as_object)
                .ok_or("step parameter required")?;
            if params.len() != 1 {
                return Err("unexpected output parameters".into());
            }
            let step = params.get("step").and_then(Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or("step number required")?;
            output(home, id, step)
        }
        _ => Err("operation or parameters denied".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scripts_and_extra_parameters_fail_closed() {
        assert!(scripts(&json!({"parameters":{"scripts":["echo a","cat"]}})).is_ok());
        for value in [
            json!({"parameters":{"scripts":["echo one"]}}),
            json!({"parameters":{"scripts":[]}}),
            json!({"parameters":{"scripts":["x","y"],"host":"ru0"}}),
            json!({"parameters":{"scripts":["x",2]}}),
            json!({"parameters":{"scripts":["x","z\u{0000}"]}}),
            json!({"parameters":{"scripts":["x".repeat(2050),"z"]}}),
            json!({"parameters":{"scripts":["x","y","z","w","p","q","r"]}}),
        ] {
            assert!(scripts(&value).is_err(), "{value}");
        }
    }
    #[test]
    fn artifacts_are_exact_and_bounded() {
        for name in ["chain.count","step-01.sh","step-06.stdout","step-03.json"] {
            assert!(artifact_allowed(name, 6));
        }
        for name in ["step-00.sh","step-07.sh","step-01.log","../step-01.sh",
            "step-1.sh","script.sh","step-02.sh.backup"] {
            assert!(!artifact_allowed(name, 6), "{name}");
        }
    }
    #[test]
    fn handoff_rejects_overflow_non_utf8_and_failed_stages() {
        let mut stage = jobs::StageResult {
            exit_code: 0, stdout: b"alpha\n".to_vec(), stderr: vec![],
            stdout_truncated: false, stderr_truncated: false,
        };
        assert!(stage_accepted(&stage, true));
        stage.stdout = vec![b'a'; MAX_HANDOFF + 1];
        assert!(!stage_accepted(&stage, true));
        assert!(stage_accepted(&stage, false));
        stage.stdout = vec![0xff];
        assert!(!stage_accepted(&stage, true));
        stage.stdout = b"safe".to_vec();
        stage.stderr_truncated = true;
        assert!(!stage_accepted(&stage, false));
        stage.stderr_truncated = false;
        stage.exit_code = 17;
        assert!(!stage_accepted(&stage, false));
    }
    #[test]
    fn chain_progress_and_step_output_are_durable_without_execution() {
        use std::os::unix::fs::PermissionsExt;
        let unique = format!("rf-chain-test-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(
                std::time::UNIX_EPOCH).unwrap().as_nanos());
        let home = std::env::temp_dir().join(unique);
        let state = home.join(".local/state/relayforge");
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let root = jobs::root(&home, true).unwrap().unwrap();
        let id = "relayforge-job-1792390000-a1b2c3";
        let dir = root.join(id);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        write_private(&dir, "chain.count", b"2").unwrap();
        write_private(&dir, "step-01.stdout", b"alpha").unwrap();
        write_private(&dir, "step-01.stderr", b"").unwrap();
        write_private(&dir, "step-01.json", b"{\"step\":1,\"exit_code\":0}").unwrap();
        write_private(&dir, "result.json", b"{\"state\":\"finished\",\"exit_code\":1}").unwrap();
        let reported: Value = serde_json::from_str(&status(&home, id).unwrap()).unwrap();
        assert_eq!(reported["completed_steps"], 1);
        assert_eq!(reported["steps"], 2);
        let out: Value = serde_json::from_str(&output(&home, id, 1).unwrap()).unwrap();
        assert_eq!(out["stdout"], "alpha");
        assert_eq!(out["result"]["exit_code"], 0);
        assert!(output(&home, id, 0).is_err());
        assert!(output(&home, id, 3).is_err());
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn schema_rejects_extra_fields_and_steps() {
        let home = Path::new("/nonexistent");
        for payload in [
            json!({"operation":"job.chain.start", "script":"echo x"}),
            json!({"operation":"job.chain.start","parameters":{"scripts":["x","y"]},"host":"ru0"}),
            json!({"operation":"job.chain.output","task_id":"foo","parameters":{"step":0,"host":"ru0"}}),
            json!({"operation":"job.chain.status","task_id":"foo","script":"id"}),
        ] {
            assert!(execute(home, &payload).is_err());
        }
    }
}
