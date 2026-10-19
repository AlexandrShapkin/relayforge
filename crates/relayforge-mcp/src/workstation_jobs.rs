//! Bounded asynchronous shell jobs. A job sees only vetted tracked sources,
//! an isolated /tmp, and its own read-only script inside bubblewrap. Never
//! expose host shell, user service names, network, or arbitrary files.
use crate::workstation_dev::sandbox_file_mounts;
use serde_json::{json, Value};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_JOBS: usize = 12;
const MAX_SCRIPT: usize = 2048;
const MAX_LOG: usize = 64 * 1024;
const NOFOLLOW: i32 = 0x20000; // O_NOFOLLOW, Linux.
const PREFIX: &str = "relayforge-job-";

fn current_uid() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| "identity unavailable")?;
    status.lines().find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_ascii_whitespace().next())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "identity unavailable".to_string())
}

fn check_dir(path: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "private directory unavailable")?;
    if !meta.is_dir() || meta.file_type().is_symlink()
        || meta.uid() != current_uid()?
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("insecure job directory".into());
    }
    Ok(())
}

fn root(home: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    let parent = home.join(".local/state/relayforge");
    check_dir(&parent)?;
    let root = parent.join("sandbox-jobs");
    if fs::symlink_metadata(&root).is_err() {
        if !create {
            return Ok(None);
        }
        DirBuilder::new().mode(0o700).create(&root)
            .map_err(|_| "job directory unavailable")?;
    }
    check_dir(&root)?;
    Ok(Some(root))
}

fn valid_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix(PREFIX) else { return false; };
    let mut components = rest.split('-');
    let seconds = components.next().unwrap_or("");
    let suffix = components.next().unwrap_or("");
    components.next().is_none()
        && seconds.len() == 10 && seconds.bytes().all(|b| b.is_ascii_digit())
        && suffix.len() == 6
        && suffix.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn new_id() -> Result<String, String> {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?.as_secs();
    let mut random = [0u8;3];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|_| "random unavailable")?;
    let id = format!("{PREFIX}{seconds}-{:02x}{:02x}{:02x}",
        random[0], random[1], random[2]);
    if !valid_id(&id) { return Err("invalid job ID".into()); }
    Ok(id)
}

fn inventory(root: &Path) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| "job list unavailable")? {
        let entry = entry.map_err(|_| "job list unavailable")?;
        let id = entry.file_name().into_string().map_err(|_| "invalid job ID")?;
        if !valid_id(&id) { return Err("unexpected job directory".into()); }
        check_dir(&entry.path())?;
        ids.push(id);
        if ids.len() > MAX_JOBS { return Err("job capacity reached".into()); }
    }
    ids.sort();
    Ok(ids)
}

fn job_dir(home: &Path, id: &str) -> Result<PathBuf, String> {
    if !valid_id(id) { return Err("job ID denied".into()); }
    let root = root(home, false)?.ok_or("job directory unavailable")?;
    let dir = root.join(id);
    check_dir(&dir)?;
    Ok(dir)
}

fn read_text(dir: &Path, file: &str, cap: usize) -> Result<Option<String>, String> {
    let path = dir.join(file);
    if fs::symlink_metadata(&path).is_err() { return Ok(None); }
    let meta = fs::symlink_metadata(&path).map_err(|_| "job artifact unavailable")?;
    if !meta.is_file() || meta.file_type().is_symlink()
        || meta.uid() != current_uid()? || meta.permissions().mode() & 0o077 != 0
        || meta.len() > cap as u64 {
        return Err("insecure job artifact".into());
    }
    let mut output = Vec::new();
    OpenOptions::new().read(true).custom_flags(NOFOLLOW)
        .open(&path).map_err(|_| "job artifact unavailable")?
        .take((cap+1) as u64).read_to_end(&mut output)
        .map_err(|_| "job artifact unavailable")?;
    if output.len() > cap { return Err("job artifact too large".into()); }
    Ok(Some(String::from_utf8(output).map_err(|_| "non-utf8 job artifact")?))
}

fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let mut out = OpenOptions::new().write(true).create_new(true)
        .mode(0o600).custom_flags(NOFOLLOW)
        .open(dir.join(name)).map_err(|_| "job artifact unavailable")?;
    out.write_all(bytes).and_then(|_| out.sync_all())
        .map_err(|_| "job artifact write failed")
}

fn script_valid(script: &str) -> bool {
    !script.is_empty() && script.len() <= MAX_SCRIPT
        && !script.bytes().any(|b| b == 0 || (b < 32 && b != b'\n' && b != b'\t'))
}

fn capped<R: Read>(reader: R) -> Result<(Vec<u8>, bool), String> {
    let mut buffer = Vec::new();
    reader.take((MAX_LOG + 1) as u64).read_to_end(&mut buffer)
        .map_err(|_| "job output unavailable")?;
    let overflow = buffer.len() > MAX_LOG;
    buffer.truncate(MAX_LOG);
    Ok((buffer, overflow))
}

fn run_job(home: &Path, id: &str) -> Result<i32, String> {
    let dir = job_dir(home, id)?;
    let script = dir.join("script.sh");
    if read_text(&dir, "script.sh", MAX_SCRIPT)?.is_none() {
        return Err("job script unavailable".into());
    }
    let repo = home.join("Projects/relayforge");
    let mut args = vec![
        "--unshare-all".to_string(), "--die-with-parent".into(),
        "--new-session".into(),
        "--ro-bind".into(), "/usr".into(), "/usr".into(),
        "--ro-bind".into(), "/bin".into(), "/bin".into(),
        "--ro-bind".into(), "/lib".into(), "/lib".into(),
        "--ro-bind".into(), "/lib64".into(), "/lib64".into(),
        "--proc".into(), "/proc".into(), "--dev".into(), "/dev".into(),
        "--tmpfs".into(), "/tmp".into(), "--dir".into(), "/workspace".into(),
        "--dir".into(), "/job".into(),
    ];
    args.extend(sandbox_file_mounts(&repo)?);
    args.extend([
        "--ro-bind".into(), script.to_string_lossy().to_string(),
        "/job/script.sh".into(),
        "--chdir".into(), "/workspace".into(), "--clearenv".into(),
        "--setenv".into(), "HOME".into(), "/workspace".into(),
        "--setenv".into(), "PATH".into(), "/usr/bin:/bin".into(),
        "--".into(), "/bin/bash".into(), "--noprofile".into(),
        "--norc".into(), "/job/script.sh".into(),
    ]);
    let mut process = Command::new("/usr/bin/bwrap").args(&args)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().map_err(|_| "sandbox unavailable")?;
    let out = process.stdout.take().ok_or("stdout unavailable")?;
    let err = process.stderr.take().ok_or("stderr unavailable")?;
    let stdout = thread::spawn(move || capped(out));
    let stderr = thread::spawn(move || capped(err));
    let status = process.wait().map_err(|_| "job wait failed")?;
    let (out, out_limit) = stdout.join().map_err(|_| "stdout reader failed")??;
    let (err, err_limit) = stderr.join().map_err(|_| "stderr reader failed")??;
    write_private(&dir, "stdout.log", &out)?;
    write_private(&dir, "stderr.log", &err)?;
    let code = status.code().unwrap_or(128);
    write_private(&dir, "result.json", json!({
        "state":"finished","exit_code":code,
        "stdout_truncated":out_limit,"stderr_truncated":err_limit
    }).to_string().as_bytes())?;
    Ok(code)
}

/// Only invoked by the locally installed fixed RelayForge release binary.
/// Neither the user or a tunnel request can supply a host executable/path.
pub fn run_worker(id: &str) -> i32 {
    if !valid_id(id) { return 2; }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return 2; };
    if !home.is_absolute() || home.as_os_str().len() > 256 { return 2; }
    match run_job(&home, id) {
        Ok(code) => code,
        Err(_) => 1,
    }
}

fn unit_state(id: &str) -> Result<Option<String>, String> {
    if !valid_id(id) { return Err("job ID denied".into()); }
    let unit = format!("{id}.service");
    let out = Command::new("timeout").args(["5s","systemctl","--user","show",
        &unit,"--property=ActiveState","--value"])
        .output().map_err(|_| "systemd unavailable")?;
    if !out.status.success() { return Ok(None); }
    let status = String::from_utf8(out.stdout).map_err(|_| "invalid systemd status")?;
    let status = status.trim();
    if matches!(status,"active"|"activating"|"inactive"|"failed"|"deactivating") {
        Ok(Some(status.to_string()))
    } else { Ok(None) }
}

fn job_status(home: &Path, id: &str) -> Result<Value, String> {
    let dir = job_dir(home, id)?;
    if let Some(result) = read_text(&dir, "result.json", 2048)? {
        let parsed: Value = serde_json::from_str(&result)
            .map_err(|_| "invalid job result")?;
        return Ok(json!({"job_id":id, "state":"finished",
            "exit_code":parsed["exit_code"],
            "stdout_truncated":parsed["stdout_truncated"],
            "stderr_truncated":parsed["stderr_truncated"]}));
    }
    if read_text(&dir, "stopped", 16)?.is_some() {
        return Ok(json!({"job_id":id,"state":"stopped"}));
    }
    let state = unit_state(id)?;
    let value = match state.as_deref() {
        Some("active"|"activating"|"deactivating") => "running",
        Some("failed") => "failed",
        _ => "unknown",
    };
    Ok(json!({"job_id":id,"state":value}))
}

fn job_start(home: &Path, script: &str) -> Result<String, String> {
    if !script_valid(script) { return Err("invalid job script".into()); }
    let root = root(home, true)?.ok_or("job directory unavailable")?;
    if inventory(&root)?.len() >= MAX_JOBS {
        return Err("job capacity reached; remove completed jobs first".into());
    }
    let id = new_id()?;
    let dir = root.join(&id);
    DirBuilder::new().mode(0o700).create(&dir)
        .map_err(|_| "job directory unavailable")?;
    if let Err(error) = write_private(&dir, "script.sh", script.as_bytes()) {
        let _ = fs::remove_dir_all(&dir);
        return Err(error);
    }
    let binary = home.join("Projects/relayforge/target/release/relayforge-mcp");
    if !binary.is_file() { return Err("worker binary unavailable".into()); }
    let unit = format!("--unit={id}");
    let path = binary.to_str().ok_or("binary path unavailable")?;
    let output = Command::new("timeout").args([
        "-k", "2s", "12s", "systemd-run", "--user", "--collect",
        &unit, "--property=Type=exec", "--property=RuntimeMaxSec=600",
        "--", path, "--sandbox-job-worker", &id,
    ]).output().map_err(|_| "job scheduler unavailable")?;
    if !output.status.success() {
        // An ambiguous client failure must not erase a job that systemd
        // successfully accepted. Retain the receipt for inspection.
        return Err("job scheduling unverified; check job.list".into());
    }
    Ok(json!({"job_id":id,"started":true,"limit_seconds":600}).to_string())
}

fn job_stop(home: &Path, id: &str) -> Result<String, String> {
    let dir = job_dir(home, id)?;
    if job_status(home,id)?["state"] != "running" {
        return Err("job is not running".into());
    }
    let unit = format!("{id}.service");
    let output = Command::new("timeout").args(["8s","systemctl","--user","stop",&unit])
        .output().map_err(|_| "stop unavailable")?;
    if !output.status.success() { return Err("could not stop job".into()); }
    write_private(&dir, "stopped", b"stopped")?;
    Ok(json!({"job_id":id,"stop_requested":true}).to_string())
}

fn job_remove(home: &Path, id: &str) -> Result<String, String> {
    let state = job_status(home, id)?;
    if state["state"] == "running" {
        return Err("cannot remove running job".into());
    }
    // An absent transient unit is not proof the worker never started.
    // Give a missing/ambiguous receipt the full 10-minute runtime plus
    // cleanup margin before allowing removal of its script.
    if state["state"] == "unknown" || state["state"] == "failed" {
        let epoch = id.strip_prefix(PREFIX).unwrap_or("")
            .split('-').next().unwrap_or("")
            .parse::<u64>().map_err(|_| "invalid job ID")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "clock unavailable")?.as_secs();
        if now.saturating_sub(epoch) < 900 {
            return Err("ambiguous job may still be starting; retry cleanup later".into());
        }
    }
    let dir = job_dir(home, id)?;
    let allowed = ["script.sh","stdout.log","stderr.log","result.json","stopped"];
    for entry in fs::read_dir(&dir).map_err(|_| "job unavailable")? {
        let entry = entry.map_err(|_| "job unavailable")?;
        let name = entry.file_name().into_string().map_err(|_| "job unavailable")?;
        if !allowed.contains(&name.as_str()) { return Err("unexpected job artifact".into()); }
        let meta = fs::symlink_metadata(entry.path()).map_err(|_| "job unavailable")?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.uid()!=current_uid()?
            || meta.permissions().mode() & 0o077 != 0 { return Err("insecure job artifact".into()); }
    }
    fs::remove_dir_all(dir).map_err(|_| "job cleanup failed")?;
    Ok(json!({"job_id":id,"removed":true}).to_string())
}

pub fn execute(home: &Path, args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("expected object")?;
    let operation = obj.get("operation").and_then(Value::as_str).ok_or("operation required")?;
    match operation {
        "job.start" if obj.len()==2 => {
            let script = obj.get("script").and_then(Value::as_str).ok_or("script required")?;
            job_start(home, script)
        }
        "job.list" if obj.len()==1 => {
            let Some(dir) = root(home,false)? else {
                return Ok(json!({"jobs":[],"capacity":MAX_JOBS}).to_string());
            };
            Ok(json!({"jobs":inventory(&dir)?,"capacity":MAX_JOBS}).to_string())
        }
        "job.status" if obj.len()==2 => {
            let id = obj.get("task_id").and_then(Value::as_str).ok_or("job ID required")?;
            Ok(job_status(home,id)?.to_string())
        }
        "job.output" if obj.len()==2 => {
            let id = obj.get("task_id").and_then(Value::as_str).ok_or("job ID required")?;
            let dir = job_dir(home,id)?;
            Ok(json!({"job_id":id,
                "status":job_status(home,id)?,
                "stdout":read_text(&dir,"stdout.log",MAX_LOG)?.unwrap_or_default(),
                "stderr":read_text(&dir,"stderr.log",MAX_LOG)?.unwrap_or_default(),
            }).to_string())
        }
        "job.stop" if obj.len()==2 => {
            let id = obj.get("task_id").and_then(Value::as_str).ok_or("job ID required")?;
            job_stop(home,id)
        }
        "job.remove" if obj.len()==2 => {
            let id = obj.get("task_id").and_then(Value::as_str).ok_or("job ID required")?;
            job_remove(home,id)
        }
        _ => Err("operation or parameters denied".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ids_and_scripts_reject_injection() {
        assert!(valid_id("relayforge-job-1792390000-abcdef"));
        for s in ["relayforge-dev-1792390000-abcdef",
            "relayforge-job-1792390000-zzzzzz",
            "relayforge-job-1792390000-abcdef.service",
            "relayforge-job-1792390000-abcdef/../etc"] {
            assert!(!valid_id(s));
        }
        assert!(script_valid("pwd\nsleep 3\n"));
        assert!(!script_valid("echo hello\0evil"));
        assert!(!script_valid("\u{1b}[31m"));
        assert!(!script_valid(""));
    }
    #[test]
    fn unknown_operations_and_extra_arguments_denied() {
        let home = Path::new("/nonexistent");
        assert!(execute(home,&json!({"operation":"job.exec","script":"id"})).is_err());
        assert!(execute(home,&json!({"operation":"job.start","script":"id","host":"ru0"})).is_err());
        assert!(execute(home,&json!({"operation":"job.stop","task_id":"systemd.service"})).is_err());
    }
}
