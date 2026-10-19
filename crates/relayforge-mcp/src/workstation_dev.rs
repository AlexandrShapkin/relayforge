//! Narrow workstation development bridge over the existing private tunnel.
//! No caller-supplied executable, working directory, shell, service name,
//! host, credentials or arbitrary filesystem root. Mutations require a
//! separate local operator-created, permission-checked opt-in file.
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_OUTPUT: usize = 64 * 1024;
const MAX_CONTENT: usize = 48 * 1024;
const OPT_IN: &str = ".config/relayforge/allow-workstation-development";
const SOURCE_EDIT_OPT_IN: &str = ".config/relayforge/allow-workstation-source-edits";

pub fn tool() -> Value {
    json!({"name":"relayforge_workstation_develop",
        "description":"ThinkPad-only bounded development: tracked repository inventory/reads, isolated read-only offline shell, process status, Git sync/build and tunnel restart. Source writes need a separate local opt-in. No unrestricted host shell.",
        "inputSchema":{"type":"object","properties":{
            "operation":{"type":"string","minLength":1,"maxLength":48,
                "description":"Server-validated operation name. Use capabilities for the current allowlist; unknown values always denied."},
            "path":{"type":"string","maxLength":192},
            "content":{"type":"string","maxLength":49152},
            "task_id":{"type":"string","maxLength":32},
            "script":{"type":"string","maxLength":2048},
            "parameters":{"type":"object","description":"Reserved for future, strictly server-validated operation arguments. Unrecognized payloads denied."}
        },"required":["operation"],"additionalProperties":false}})
}

fn home_and_repo() -> Result<(PathBuf, PathBuf), String> {
    let home = PathBuf::from(std::env::var_os("HOME").ok_or("home unavailable")?);
    if !home.is_absolute() || home.as_os_str().len() > 256 {
        return Err("home invalid".into());
    }
    let repo = home.join("Projects/relayforge");
    if !repo.join(".git").exists() || !repo.is_dir() {
        return Err("repository unavailable".into());
    }
    Ok((home, repo))
}

fn local_opt_in(home: &Path, name: &str, expected: &[u8]) -> bool {
    let path = home.join(name);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return false;
    };
    if !meta.is_file()
        || meta.file_type().is_symlink()
        || meta.permissions().mode() & 0o077 != 0
        || meta.uid() != unsafe_uid()
        || meta.len() > 64
    {
        return false;
    }
    fs::read(&path).is_ok_and(|value| value == expected)
}

fn dev_enabled(home: &Path) -> bool {
    local_opt_in(home, OPT_IN, b"ALLOW_RELAYFORGE_DEVELOPMENT\n")
}

fn source_edit_enabled(home: &Path) -> bool {
    local_opt_in(home, SOURCE_EDIT_OPT_IN, b"ALLOW_RELAYFORGE_SOURCE_EDITS\n")
}

// Parse /proc/self/status rather than running id or accepting UID from MCP.
// Filesystem ownership checks must use the real local process identity.
fn unsafe_uid() -> u32 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return u32::MAX;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_ascii_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(u32::MAX)
}

fn plain_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path.len() <= 192
        && !path.bytes().any(|b| b == b'\\' || b == 0 || b < 32)
        && Path::new(path).components().all(|part| match part {
            Component::Normal(value) => {
                let s = value.to_string_lossy();
                !s.starts_with('.') || s == ".github"
            }
            _ => false,
        })
        && !path
            .split('/')
            .any(|part| part == "target" || part == "node_modules")
}

fn source_file(path: &str) -> bool {
    plain_path(path)
        && [
            ".rs", ".toml", ".md", ".py", ".sh", ".yml", ".yaml", ".json",
        ]
        .iter()
        .any(|ext| path.ends_with(ext))
}

fn read_capped<R: Read>(reader: R) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    reader
        .take((MAX_OUTPUT + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| "output unreadable")?;
    if output.len() > MAX_OUTPUT {
        return Err("output too large".into());
    }
    Ok(output)
}

fn command(program: &str, args: &[&str], max_seconds: u32) -> Result<Output, String> {
    let seconds = format!("{max_seconds}s");
    // Two bounded readers prevent a compromised program from exhausting
    // the MCP process memory through stdout or stderr in a short interval.
    let mut process = Command::new("timeout")
        .args(["-k", "2s", &seconds, program])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "local process unavailable")?;
    let stdout = process.stdout.take().ok_or("stdout unavailable")?;
    let stderr = process.stderr.take().ok_or("stderr unavailable")?;
    let out_reader = thread::spawn(move || read_capped(stdout));
    let err_reader = thread::spawn(move || read_capped(stderr));
    let status = process.wait().map_err(|_| "process wait failed")?;
    let out = out_reader.join().map_err(|_| "stdout reader failed")??;
    let err = err_reader.join().map_err(|_| "stderr reader failed")??;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}

fn text_output(output: Output) -> Result<String, String> {
    let stdout = String::from_utf8(output.stdout).map_err(|_| "non-utf8 output")?;
    let stderr = String::from_utf8(output.stderr).map_err(|_| "non-utf8 output")?;
    Ok(json!({"exit_code":output.status.code(),
        "stdout":stdout,"stderr":stderr})
    .to_string())
}

fn git(repo: &Path, args: &[&str]) -> Result<Output, String> {
    let path = repo.to_str().ok_or("repository path invalid")?;
    let mut fixed = vec![
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-C",
        path,
    ];
    fixed.extend_from_slice(args);
    command("git", &fixed, 12)
}

fn tracked_paths(repo: &Path) -> Result<Vec<String>, String> {
    let output = git(repo, &["ls-files", "-z"])?;
    if !output.status.success() {
        return Err("tracked inventory unavailable".into());
    }
    let mut result = Vec::new();
    for entry in output.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let name = std::str::from_utf8(entry).map_err(|_| "invalid tracked path")?;
        if plain_path(name) {
            result.push(name.to_owned());
        }
    }
    Ok(result)
}

fn safe_existing_file(repo: &Path, path: &str) -> Result<PathBuf, String> {
    if !source_file(path) || !tracked_paths(repo)?.iter().any(|name| name == path) {
        return Err("tracked source path denied".into());
    }
    let root = fs::canonicalize(repo).map_err(|_| "repo unavailable")?;
    let candidate = repo.join(path);
    let resolved = fs::canonicalize(&candidate).map_err(|_| "source unavailable")?;
    if !resolved.starts_with(&root) || resolved == root {
        return Err("path escapes repository".into());
    }
    let metadata = fs::symlink_metadata(&candidate).map_err(|_| "source unavailable")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("non-regular source denied".into());
    }
    Ok(resolved)
}

fn audit(home: &Path, operation: &str) -> Result<(), String> {
    let path = home.join(".local/state/relayforge/workstation-dev-audit.jsonl");
    let parent = path.parent().ok_or("audit directory unavailable")?;
    let dir = fs::symlink_metadata(parent).map_err(|_| "audit directory unavailable")?;
    if !dir.is_dir()
        || dir.file_type().is_symlink()
        || dir.permissions().mode() & 0o077 != 0
        || dir.uid() != unsafe_uid()
    {
        return Err("insecure audit directory".into());
    }
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o077 != 0
            || meta.len() > 8 * 1024 * 1024
        {
            return Err("insecure audit file".into());
        }
    }
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(0x20000) // O_NOFOLLOW on Linux
        .open(path)
        .map_err(|_| "audit unavailable")?;
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?
        .as_secs();
    writeln!(file, "{}", json!({"at":at,"operation":operation}))
        .map_err(|_| "audit unavailable")?;
    file.sync_all().map_err(|_| "audit unavailable".to_string())
}

// Return only allowlisted transient unit identities and state, never
// systemd's freeform Description column, ExecStart, environment, or logs.
fn bounded_task_inventory(output: &str) -> Result<Value, String> {
    if output.len() > MAX_OUTPUT {
        return Err("task inventory too large".into());
    }
    let mut tasks = Vec::new();
    for line in output.lines() {
        let tokens: Vec<_> = line.split_whitespace().collect();
        let Some(position) = tokens
            .iter()
            .position(|token| token.strip_suffix(".service").is_some_and(unit_id))
        else {
            continue;
        };
        if tokens.len() < position + 4 {
            continue;
        }
        let id = tokens[position].strip_suffix(".service").unwrap_or("");
        let active = tokens[position + 2];
        let sub = tokens[position + 3];
        if !matches!(
            active,
            "active" | "activating" | "inactive" | "failed" | "deactivating"
        ) || !matches!(
            sub,
            "running"
                | "start"
                | "dead"
                | "exited"
                | "failed"
                | "auto-restart"
                | "waiting"
                | "stop-sigterm"
                | "stop"
                | "condition"
        ) {
            continue;
        }
        tasks.push(json!({"task_id":id, "active":active, "sub":sub}));
        if tasks.len() == 30 {
            break;
        }
    }
    Ok(json!({"tasks":tasks, "limited":true}))
}

fn unit_id(input: &str) -> bool {
    let Some(raw) = input.strip_prefix("relayforge-dev-") else {
        return false;
    };
    let mut pieces = raw.split('-');
    let epoch = pieces.next().unwrap_or("");
    if epoch.len() != 10 || !epoch.bytes().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    match (pieces.next(), pieces.next()) {
        (None, None) => true, // Old receipts remain readable.
        (Some(suffix), None) => {
            suffix.len() == 6
                && suffix
                    .bytes()
                    .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
        }
        _ => false,
    }
}

fn new_unit_id() -> Result<String, String> {
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?
        .as_secs();
    let mut suffix = [0u8; 3];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut suffix))
        .map_err(|_| "randomness unavailable")?;
    let id = format!(
        "relayforge-dev-{epoch}-{:02x}{:02x}{:02x}",
        suffix[0], suffix[1], suffix[2]
    );
    if !unit_id(&id) {
        return Err("invalid generated task ID".into());
    }
    Ok(id)
}

fn task_lock(repo: &Path) -> Result<String, String> {
    let home = repo
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid repository root")?;
    let lock = home.join(".local/state/relayforge/development.lock");
    lock.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "invalid task lock path".into())
}

fn spawn_task(repo: &Path, kind: &str) -> Result<String, String> {
    let unit = new_unit_id()?;
    let repo_string = repo.to_str().ok_or("invalid repo path")?;
    let lock = task_lock(repo)?;
    let workdir = format!("--working-directory={repo_string}");
    let unit_opt = format!("--unit={unit}");
    let mut args = vec![
        "--user",
        &unit_opt,
        "--collect",
        &workdir,
        "--property=Type=oneshot",
        "--property=TimeoutStartSec=1800",
        "flock",
        "-w",
        "600",
        &lock,
    ];
    match kind {
        "repo.sync" => {
            args.extend([
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                repo_string,
                "pull",
                "--ff-only",
                "origin",
                "main",
            ]);
        }
        "build.start" => {
            args.extend([
                "cargo",
                "build",
                "--release",
                "--locked",
                "-p",
                "relayforge-mcp",
                "-p",
                "relayforge-agent",
            ]);
        }
        _ => return Err("task denied".into()),
    }
    let result = command("systemd-run", &args, 10)?;
    if !result.status.success() {
        return Err("could not schedule development task".into());
    }
    Ok(json!({"task_id":unit,"started":true,"kind":kind}).to_string())
}

// The shell runs in a disposable mount/user/PID/network namespace: only
// the RelayForge checkout is writable, and no other home directory, private
// SSH configuration, host services, or network interface is exposed. This is
// deliberately NOT an unrestricted workstation command executor.
fn sandbox_shell(repo: &Path, script: &str) -> Result<String, String> {
    if script.is_empty()
        || script.len() > 2048
        || script
            .bytes()
            .any(|ch| ch == 0 || (ch < 32 && ch != b'\n' && ch != b'\t'))
    {
        return Err("invalid sandbox command".into());
    }
    let workdir = repo.to_str().ok_or("workspace path invalid")?;
    let out = command(
        "bwrap",
        &[
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/lib64",
            "/lib64",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/workspace",
            "--ro-bind",
            workdir,
            "/workspace",
            "--chdir",
            "/workspace",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "HOME",
            "/workspace",
            "--",
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            script,
        ],
        15,
    )?;
    text_output(out)
}

fn clean_main_checkout(repo: &Path) -> Result<(), String> {
    let branch = git(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"])?;
    if !branch.status.success() || branch.stdout != b"main\n" {
        return Err("checkout not on main".into());
    }
    let diff = git(repo, &["diff", "--quiet", "HEAD", "--"])?;
    if !diff.status.success() {
        return Err("tracked changes require review before system tasks".into());
    }
    Ok(())
}

pub fn execute(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("expected object")?;
    let operation = obj
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    // Tool discovery also runs on disposable CI without a ThinkPad checkout.
    if operation == "capabilities" {
        if obj.len() != 1 {
            return Err("unexpected capability arguments".into());
        }
        let home = PathBuf::from(std::env::var_os("HOME").ok_or("home unavailable")?);
        if !home.is_absolute() || home.as_os_str().len() > 256 {
            return Err("home invalid".into());
        }
        return Ok(json!({
            "api_revision": 2,
            "transport": "private_secure_mcp_tunnel",
            "operations": [
                "capabilities", "repo.status", "repo.list", "repo.read",
                "repo.write", "repo.sync", "build.start",
                "task.status", "task.logs", "task.list",
                "tunnel.inspect", "tunnel.restart",
                "shell.sandbox", "process.list", "user.services"
            ],
            "write_grants": {
                "development": dev_enabled(&home),
                "source_edit": source_edit_enabled(&home)
            },
            "arbitrary_host_shell": false,
            "arbitrary_host_files": false,
            "local_grants_required_for_mutations": true
        })
        .to_string());
    }
    let (home, repo) = home_and_repo()?;
    match operation {
        "task.list" if obj.len() == 1 => {
            let output = command(
                "systemctl",
                &[
                    "--user",
                    "list-units",
                    "--all",
                    "--type=service",
                    "--no-legend",
                    "--plain",
                    "relayforge-dev-*.service",
                ],
                8,
            )?;
            if !output.status.success() {
                return Err("task inventory unavailable".into());
            }
            let text =
                String::from_utf8(output.stdout).map_err(|_| "task inventory encoding invalid")?;
            Ok(bounded_task_inventory(&text)?.to_string())
        }
        "tunnel.inspect" if obj.len() == 1 => {
            // Compose fixed read-only health evidence; no service logs,
            // credential reference, command line or environment is returned.
            let snapshot = crate::workstation::snapshot(&json!({}))?;
            let health: Value =
                serde_json::from_str(&snapshot).map_err(|_| "health unavailable")?;
            let active = health["tunnel"]["service_active"].as_bool();
            let recent = health["tunnel"]["authenticated_poll_recent"].as_bool();
            let age = health["tunnel"]["last_successful_poll_age_seconds"].as_u64();
            Ok(json!({
                "status":if active == Some(true) && recent == Some(true) {
                    "healthy"
                } else {
                    "unverified"
                },
                "service_active":active,
                "authenticated_poll_recent":recent,
                "last_successful_poll_age_seconds":age,
                "api_revision":2
            })
            .to_string())
        }
        "process.list" if obj.len() == 1 => {
            text_output(command("ps", &["-eo", "pid=,comm=,etime=,rss="], 8)?)
        }
        "user.services" if obj.len() == 1 => text_output(command(
            "systemctl",
            &[
                "--user",
                "list-units",
                "--type=service",
                "--all",
                "--no-pager",
                "--no-legend",
            ],
            8,
        )?),
        "repo.status" if obj.len() == 1 => text_output(git(
            &repo,
            &["status", "--short", "--branch", "--untracked-files=no"],
        )?),
        "repo.list"
            if obj.len() <= 2 && obj.keys().all(|key| key == "operation" || key == "path") =>
        {
            let prefix = obj.get("path").and_then(Value::as_str).unwrap_or("");
            if !prefix.is_empty() && !plain_path(prefix) {
                return Err("path denied".into());
            }
            let all = tracked_paths(&repo)?;
            let filter = if prefix.is_empty() {
                String::new()
            } else {
                format!("{prefix}/")
            };
            let mut names = BTreeSet::new();
            for path in all {
                if let Some(tail) = path.strip_prefix(&filter) {
                    if !tail.is_empty() {
                        names.insert(tail.split('/').next().unwrap_or(tail).to_owned());
                    }
                }
            }
            Ok(
                json!({"path":prefix,"entries":names.into_iter().take(200).collect::<Vec<_>>(),
                "limited":true})
                .to_string(),
            )
        }
        "repo.read" if obj.len() == 2 => {
            let path = obj
                .get("path")
                .and_then(Value::as_str)
                .ok_or("path required")?;
            let safe = safe_existing_file(&repo, path)?;
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(0x20000) // O_NOFOLLOW
                .open(&safe)
                .map_err(|_| "source unreadable")?;
            let mut data = Vec::new();
            file.take((MAX_CONTENT + 1) as u64)
                .read_to_end(&mut data)
                .map_err(|_| "source unreadable")?;
            if data.len() > MAX_CONTENT {
                return Err("source too large; use GitHub source browser".into());
            }
            let value = String::from_utf8(data).map_err(|_| "source is not UTF-8")?;
            Ok(json!({"path":path,"utf8_text":value}).to_string())
        }
        "repo.write" if obj.len() == 3 => {
            if !dev_enabled(&home) || !source_edit_enabled(&home) {
                return Err("local development opt-in missing".into());
            }
            let path = obj
                .get("path")
                .and_then(Value::as_str)
                .ok_or("path required")?;
            let content = obj
                .get("content")
                .and_then(Value::as_str)
                .ok_or("content required")?;
            if content.len() > MAX_CONTENT {
                return Err("content too large".into());
            }
            let safe = safe_existing_file(&repo, path)?;
            audit(&home, operation)?;
            // Refuse links at open; never follow paths outside the fixed workspace.
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .custom_flags(0x20000)
                .open(safe)
                .map_err(|_| "source not writable")?;
            file.write_all(content.as_bytes())
                .map_err(|_| "write failed")?;
            file.sync_all().map_err(|_| "write failed")?;
            Ok(json!({"written":true,"byte_length":content.len()}).to_string())
        }
        "repo.sync" | "build.start" if obj.len() == 1 => {
            if !dev_enabled(&home) {
                return Err("local development opt-in missing".into());
            }
            clean_main_checkout(&repo)?;
            audit(&home, operation)?;
            spawn_task(&repo, operation)
        }
        "task.status" | "task.logs" if obj.len() == 2 => {
            let task = obj
                .get("task_id")
                .and_then(Value::as_str)
                .ok_or("task required")?;
            if !unit_id(task) {
                return Err("task denied".into());
            }
            let unit = format!("{task}.service");
            if operation == "task.status" {
                text_output(command(
                    "systemctl",
                    &[
                        "--user",
                        "show",
                        &unit,
                        "-p",
                        "ActiveState",
                        "-p",
                        "Result",
                        "-p",
                        "ExecMainStatus",
                    ],
                    8,
                )?)
            } else {
                text_output(command(
                    "journalctl",
                    &[
                        "--user",
                        "-u",
                        &unit,
                        "--no-pager",
                        "-n",
                        "80",
                        "--output=cat",
                    ],
                    8,
                )?)
            }
        }
        "shell.sandbox" if obj.len() == 2 => {
            if !dev_enabled(&home) {
                return Err("local development opt-in missing".into());
            }
            let script = obj
                .get("script")
                .and_then(Value::as_str)
                .ok_or("script required")?;
            audit(&home, operation)?;
            sandbox_shell(&repo, script)
        }
        "tunnel.restart" if obj.len() == 1 => {
            // The persistent hot-stdio parent automatically adopts new worker
            // binaries. Restarting the actual tunnel would sever this session.
            if std::env::var_os("RELAYFORGE_HOT_STDIO_WORKER").is_some() {
                return Err("tunnel restart disabled in hot-worker mode".into());
            }
            if !dev_enabled(&home) {
                return Err("local development opt-in missing".into());
            }
            clean_main_checkout(&repo)?;
            audit(&home, operation)?;
            // A transient unit restarts the tunnel independently of the MCP
            // call that initiates it. It waits for ongoing builds/syncs first.
            let unit = new_unit_id()?;
            let unit_opt = format!("--unit={unit}");
            let lock = task_lock(&repo)?;
            let result = command(
                "systemd-run",
                &[
                    "--user",
                    "--collect",
                    &unit_opt,
                    "--property=Type=oneshot",
                    "--property=TimeoutStartSec=1800",
                    "flock",
                    "-w",
                    "600",
                    &lock,
                    "systemctl",
                    "--user",
                    "restart",
                    "relayforge-tunnel.service",
                ],
                8,
            )?;
            if !result.status.success() {
                return Err("restart not scheduled".into());
            }
            Ok(json!({"restart_scheduled":true,"may_disconnect":true,"task_id":unit}).to_string())
        }
        _ => Err("operation or parameters denied".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_traversal_and_private_files() {
        for name in [
            "../.ssh/id_ed25519",
            "/etc/passwd",
            "src/../../etc/passwd",
            ".git/config",
            "target/release/relayforge-mcp",
            "src/secret.env",
            "src/./main.rs",
            "foo\\bar.rs",
            "src/.env",
        ] {
            assert!(!source_file(name), "{name}");
        }
        assert!(source_file("crates/relayforge-mcp/src/workstation.rs"));
        assert!(source_file(".github/workflows/tests.yml"));
    }
    #[test]
    fn sandbox_denies_bad_commands_and_traversal() {
        for script in ["", "x\0y", "echo \u{1b}[31m"] {
            assert!(sandbox_shell(Path::new("/workspace"), script).is_err());
        }
        let response = sandbox_shell(Path::new("/nonexistent/relayforge"), "pwd");
        assert!(response.is_err() || response.is_ok_and(|value| value.contains("exit_code")));
    }
    #[test]
    fn bounded_output_stops_large_streams() {
        assert_eq!(read_capped(b"ok".as_slice()).unwrap(), b"ok");
        let overflow = vec![b'a'; MAX_OUTPUT + 2048];
        assert!(read_capped(overflow.as_slice()).is_err());
        let cmd = command("sh", &["-c", "head -c 100000 /dev/zero"], 5);
        assert!(cmd.is_err());
    }

    #[test]
    fn task_inventory_filters_freeform_service_descriptions() {
        let input = concat!(
            "relayforge-dev-1792370000-a0b1c2.service loaded active running API_SECRET=never_return\n",
            "relayforge-tunnel.service loaded active running PRIVATE_TOKEN=hidden\n",
            "relayforge-dev-1792370001-aaa111.service loaded failed failed KEY=never_return\n",
            "relayforge-dev-1792370002-aaa111.service loaded weird unknown NOTE=hidden\n",
            "untrusted arbitrary.service loaded active running secret\n");
        let snapshot = bounded_task_inventory(input).unwrap();
        let rendered = snapshot.to_string();
        assert_eq!(snapshot["tasks"].as_array().unwrap().len(), 2);
        assert!(rendered.contains("relayforge-dev-1792370000-a0b1c2"));
        for value in ["SECRET", "PRIVATE_TOKEN", "KEY=", "NOTE=", "untrusted"] {
            assert!(!rendered.contains(value));
        }
    }

    #[test]
    fn open_schema_remains_server_validated() {
        let schema = tool();
        assert!(schema["inputSchema"]["properties"]["operation"]["enum"].is_null());
        assert_eq!(schema["inputSchema"]["additionalProperties"], false);
        assert!(execute(&json!({"operation":"shell.host"})).is_err());
        assert!(execute(&json!({"operation":"capabilities","arbitrary":true})).is_err());
        assert!(execute(&json!({"operation":"capabilities","parameters":{"shell":"id"}})).is_err());
    }
    #[test]
    fn strict_task_identifiers_and_required_arguments() {
        assert!(unit_id("relayforge-dev-1792370000"));
        assert!(unit_id("relayforge-dev-1792370000-a0b1c2"));
        assert_eq!(new_unit_id().unwrap().len(), 32);
        assert!(!unit_id("relayforge-dev-1792370000-a0b1cx"));
        assert!(!unit_id("relayforge-dev-1792370000-a0b1c2-extra"));
        assert!(!unit_id("relayforge-dev-1;id"));
        assert!(!unit_id("sshd"));
        assert!(execute(&json!({"operation":"unknown"})).is_err());
        assert!(execute(&json!({"operation":"repo.read","path":"../../etc/passwd"})).is_err());
        assert!(execute(&json!({"operation":"repo.sync","cmd":"sh"})).is_err());
    }
}
