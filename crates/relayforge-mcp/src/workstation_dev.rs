//! Narrow workstation development bridge over the existing private tunnel.
//! No caller-supplied executable, working directory, shell, service name,
//! host, credentials or arbitrary filesystem root. Mutations require a
//! separate local operator-created, permission-checked opt-in file.
use crate::{
    workstation_artifacts, workstation_dependency, workstation_development, workstation_jobs,
    workstation_recovery, workstation_retire, workstation_transfer,
};
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
            "parameters":{"type":"object","description":"Strict server-validated job.chain payloads or development.prepare proposal; all other nested payloads denied."}
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

pub(crate) fn dev_enabled(home: &Path) -> bool {
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
        && ([
            ".rs", ".toml", ".md", ".py", ".sh", ".yml", ".yaml", ".json",
        ]
        .iter()
        .any(|ext| path.ends_with(ext))
            || matches!(
                path,
                "deploy/systemd/relayforge-local-recover.service"
                    | "deploy/systemd/relayforge-local-recover.timer"
            ))
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
    command_input(program, args, None, max_seconds)
}

fn command_input(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    max_seconds: u32,
) -> Result<Output, String> {
    let seconds = format!("{max_seconds}s");
    // Cap stdout/stderr during acquisition; keep caller scripts off argv.
    let mut process = Command::new("timeout")
        .args(["-k", "2s", &seconds, program])
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "local process unavailable")?;
    let stdout = process.stdout.take().ok_or("stdout unavailable")?;
    let stderr = process.stderr.take().ok_or("stderr unavailable")?;
    let out_reader = thread::spawn(move || read_capped(stdout));
    let err_reader = thread::spawn(move || read_capped(stderr));
    let sent = if let Some(body) = input {
        let mut writer = process.stdin.take().ok_or("stdin unavailable")?;
        writer
            .write_all(body.as_bytes())
            .map_err(|_| "stdin write failed")
    } else {
        Ok(())
    };
    let status = process.wait().map_err(|_| "process wait failed")?;
    let out = out_reader.join().map_err(|_| "stdout reader failed")??;
    let err = err_reader.join().map_err(|_| "stderr reader failed")??;
    sent?;
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

fn verified_tracked_file(repo: &Path, path: &str) -> Result<PathBuf, String> {
    if !source_file(path) {
        return Err("tracked source path denied".into());
    }
    let root = fs::canonicalize(repo).map_err(|_| "repo unavailable")?;
    let mut cursor = repo.to_path_buf();
    // Reject a symlink in any path component, not just the final file.
    // The leaf must be a real regular file inside the fixed checkout.
    let mut leaf = None;
    for component in Path::new(path).components() {
        let Component::Normal(name) = component else {
            return Err("path denied".into());
        };
        cursor.push(name);
        let meta = fs::symlink_metadata(&cursor).map_err(|_| "source unavailable")?;
        if meta.file_type().is_symlink() {
            return Err("symlink source denied".into());
        }
        leaf = Some(meta);
    }
    if !leaf.is_some_and(|meta| meta.is_file()) {
        return Err("non-regular source denied".into());
    }
    let resolved = fs::canonicalize(&cursor).map_err(|_| "source unavailable")?;
    if !resolved.starts_with(&root) || resolved == root {
        return Err("path escapes repository".into());
    }
    Ok(resolved)
}

fn safe_existing_file(repo: &Path, path: &str) -> Result<PathBuf, String> {
    if !source_file(path) || !tracked_paths(repo)?.iter().any(|name| name == path) {
        return Err("tracked source path denied".into());
    }
    verified_tracked_file(repo, path)
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

// Only the fixed Git fast-forward and locked Cargo build may be retried:
// both are idempotent and share a single file lock. In particular, NEVER
// apply this retry policy to tunnel.restart or any other service mutation.
fn spawn_task(repo: &Path, kind: &str) -> Result<String, String> {
    if !matches!(kind, "repo.sync" | "build.start") {
        return Err("task denied".into());
    }
    let repo_string = repo.to_str().ok_or("invalid repo path")?;
    let lock = task_lock(repo)?;
    let build_target = repo.join(".build/workstation");
    let build_target = build_target.to_str().ok_or("build target unavailable")?;
    let workdir = format!("--working-directory={repo_string}");
    let mut last_reason = "unavailable";
    for attempt in 1..=3 {
        let unit = new_unit_id()?;
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
            "repo.sync" => args.extend([
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                repo_string,
                "pull",
                "--ff-only",
                "origin",
                "main",
            ]),
            "build.start" => args.extend([
                "cargo",
                "build",
                "--release",
                "--locked",
                "--target-dir",
                build_target,
                "-p",
                "relayforge-mcp",
                "-p",
                "relayforge-agent",
            ]),
            _ => unreachable!(),
        }
        match command("systemd-run", &args, 10) {
            Ok(output) if output.status.success() => {
                return Ok(json!({
                    "task_id":unit, "started":true, "kind":kind,
                    "schedule_attempts":attempt
                })
                .to_string());
            }
            Ok(output) => last_reason = schedule_failure_class(&output),
            Err(_) => last_reason = "client_unavailable",
        }
        if attempt < 3 {
            // A previous transient unit may have been queued despite a
            // client-side error. Distinct IDs + the shared lock ensure that
            // at worst the fixed idempotent operation is repeated serially.
            // Do not expose stderr: systemd diagnostics can contain paths.
            thread::sleep(std::time::Duration::from_millis(350 * attempt));
        }
    }
    Err(format!(
        "development task scheduling failed after three attempts ({last_reason})"
    ))
}

fn schedule_failure_class(output: &Output) -> &'static str {
    let msg = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if msg.contains("connection") || msg.contains("connect to bus") {
        "bus_unavailable"
    } else if msg.contains("already exists") {
        "unit_conflict"
    } else if msg.contains("start request repeated") || msg.contains("rate limit") {
        "rate_limited"
    } else if msg.contains("timed out") || output.status.code() == Some(124) {
        "timeout"
    } else if msg.contains("permission") || msg.contains("access denied") {
        "permission_denied"
    } else {
        "systemd_rejected"
    }
}

// Materialize a read-only view of allowlisted, currently tracked source
// files inside the sandbox. Never bind the repository directory itself:
// that would expose .git, private untracked files and hidden local state.
pub(crate) fn sandbox_file_mounts(repo: &Path) -> Result<Vec<String>, String> {
    let paths = tracked_paths(repo)?;
    let mut dirs = BTreeSet::new();
    let mut mounts = Vec::new();
    for path in paths.into_iter().filter(|name| source_file(name)) {
        if mounts.len() >= 512 {
            return Err("sandbox source count exceeds limit".into());
        }
        let source = verified_tracked_file(repo, &path)?;
        let source = source.to_str().ok_or("source path invalid")?.to_owned();
        let mut parent = String::from("/workspace");
        let parts: Vec<&str> = path.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            parent.push('/');
            parent.push_str(part);
            dirs.insert(parent.clone());
        }
        mounts.push((source, format!("/workspace/{path}")));
    }
    let mut argv = Vec::new();
    for dir in dirs {
        argv.push("--dir".to_owned());
        argv.push(dir);
    }
    for (source, dest) in mounts {
        argv.push("--ro-bind".to_owned());
        argv.push(source);
        argv.push(dest);
    }
    Ok(argv)
}

// The shell runs in disposable mount/user/PID/network namespaces. Only
// allowlisted tracked source files are visible; the parent repository,
// private untracked files, .git and other user data are never mounted.
fn sandbox_shell(repo: &Path, script: &str) -> Result<String, String> {
    if script.is_empty()
        || script.len() > 2048
        || script
            .bytes()
            .any(|ch| ch == 0 || (ch < 32 && ch != b'\n' && ch != b'\t'))
    {
        return Err("invalid sandbox command".into());
    }
    let mut arguments = [
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
    ]
    .iter()
    .map(|v| (*v).to_owned())
    .collect::<Vec<_>>();
    arguments.extend(sandbox_file_mounts(repo)?);
    arguments.extend(
        [
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
            "-s",
        ]
        .iter()
        .map(|v| (*v).to_owned()),
    );

    // The tunnel service forbids AF_NETLINK. bwrap needs that socket while
    // creating a NEW isolated network namespace. A separate transient user
    // service performs the sandbox setup without relaxing the tunnel policy.
    // The command script flows through stdin, never through ExecStart.
    let mut launch = vec![
        "--user".to_owned(),
        "--wait".to_owned(),
        "--pipe".to_owned(),
        "--collect".to_owned(),
        "--property=Type=exec".to_owned(),
        "--property=RuntimeMaxSec=20".to_owned(),
        "--".to_owned(),
        "/usr/bin/bwrap".to_owned(),
    ];
    launch.extend(arguments);
    let args: Vec<&str> = launch.iter().map(String::as_str).collect();
    text_output(command_input("systemd-run", &args, Some(script), 24)?)
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
            "api_revision": 9,
            "transport": "private_secure_mcp_tunnel",
            "operations": [
                "capabilities", "repo.status", "repo.list", "repo.read",
                "repo.write", "repo.sync", "build.start",
                "task.status", "task.logs", "task.list",
                "tunnel.inspect", "tunnel.restart", "recovery.inspect",
                "workspace.list", "workspace.read", "workspace.put",
                "workspace.remove", "artifact.list", "artifact.read",
                "job.start", "job.list", "job.status", "job.output",
                "job.stop", "job.remove",
                "job.chain.start", "job.chain.status", "job.chain.output",
                "development.prepare", "development.run", "development.inspect",
                "dependency.audit",
                "ssh.retire.plan", "ssh.retire.config", "ssh.retire.known_hosts",
                "shell.sandbox", "process.list", "user.services"
            ],
            "write_grants": {
                "development": dev_enabled(&home),
                "source_edit": source_edit_enabled(&home)
            },
            "artifacts": workstation_artifacts::discovery(&home),
            "arbitrary_host_shell": false,
            "arbitrary_host_files": false,
            "development_tasks": {
                "schema_version":1,
                "repositories":["relayforge"],
                "profiles":["python-stdlib-v1"],
                "max_files":4,
                "max_proposal_bytes":24576,
                "task_grant_required":true,
                "max_authorization_lifetime_seconds":3600,
                "checkout_writes":false,
                "publication":"external_github_only"
            },
            "local_grants_required_for_mutations": true
        })
        .to_string());
    }
    let (home, repo) = home_and_repo()?;
    match operation {
        "artifact.list" | "artifact.read" => {
            audit(&home, operation)?;
            workstation_artifacts::execute(&home, args)
        }
        "development.prepare" | "development.run" | "development.inspect" => {
            if operation != "development.inspect" {
                if !dev_enabled(&home) {
                    return Err("local development opt-in missing".into());
                }
                audit(&home, operation)?;
            }
            workstation_development::execute(&home, &repo, args)
        }
        "ssh.retire.plan" if obj.len() == 1 => workstation_retire::plan(&home),
        "ssh.retire.config" | "ssh.retire.known_hosts" if obj.len() == 1 => {
            if !dev_enabled(&home) {
                return Err("local development opt-in missing".into());
            }
            audit(&home, operation)?;
            workstation_retire::dispatch(&home, operation)
        }
        "recovery.inspect" if obj.len() == 1 => {
            let opted_in = local_opt_in(
                &home,
                ".config/relayforge/allow-self-recovery",
                b"ALLOW_RELAYFORGE_SELF_RECOVERY\n",
            );
            workstation_recovery::snapshot(opted_in)
        }
        "dependency.audit" if obj.len() == 1 => workstation_dependency::snapshot(&home),
        "job.start" | "job.list" | "job.status" | "job.output" | "job.stop" | "job.remove"
        | "job.chain.start" | "job.chain.status" | "job.chain.output" => {
            if matches!(
                operation,
                "job.start" | "job.stop" | "job.remove" | "job.chain.start"
            ) {
                if !dev_enabled(&home) {
                    return Err("local development opt-in missing".into());
                }
                audit(&home, operation)?;
            }
            workstation_jobs::execute(&home, args)
        }
        "workspace.list" | "workspace.read" | "workspace.put" | "workspace.remove" => {
            if matches!(operation, "workspace.put" | "workspace.remove") {
                if !dev_enabled(&home) {
                    return Err("local development opt-in missing".into());
                }
                audit(&home, operation)?;
            }
            workstation_transfer::execute(&home, args)
        }
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
        // Offline guard tests read exactly these two publicly tracked unit
        // fixtures. This does not expose live /etc or ~/.config/systemd.
        assert!(source_file(
            "deploy/systemd/relayforge-local-recover.service"
        ));
        assert!(source_file("deploy/systemd/relayforge-local-recover.timer"));
        assert!(!source_file("deploy/systemd/arbitrary.service"));
        assert!(!source_file("deploy/systemd/../../etc/private.service"));
    }
    #[test]
    fn sandbox_exposes_tracked_sources_but_not_git_or_untracked_files() {
        let unique = format!(
            "relayforge-sandbox-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let repo = std::env::temp_dir().join(unique);
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/allowed.rs"), "fn allowed() {}").unwrap();
        fs::write(repo.join("src/private.rs"), "secret").unwrap();
        fs::write(repo.join(".env"), "SECRET=never").unwrap();
        let initialized = Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(&repo)
            .status()
            .unwrap();
        assert!(initialized.success());
        let added = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["add", "src/allowed.rs"])
            .status()
            .unwrap();
        assert!(added.success());
        let mounts = sandbox_file_mounts(&repo).unwrap();
        let rendered = mounts.join(" ");
        assert!(rendered.contains("/workspace/src/allowed.rs"));
        assert!(!rendered.contains("private.rs"));
        assert!(!rendered.contains(".env"));
        assert!(!rendered.contains(".git"));
        assert!(!rendered.contains("SECRET"));
        let bad = repo.join("src/symlink.rs");
        std::os::unix::fs::symlink(repo.join("src/private.rs"), &bad).unwrap();
        assert!(verified_tracked_file(&repo, "src/symlink.rs").is_err());
        fs::remove_dir_all(repo).unwrap();
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
    fn scheduling_errors_are_classified_without_raw_output() {
        use std::os::unix::process::ExitStatusExt;
        let fail = |message: &str| Output {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stdout: vec![],
            stderr: message.as_bytes().to_vec(),
        };
        assert_eq!(
            schedule_failure_class(&fail("Failed to connect to bus: Connection refused")),
            "bus_unavailable"
        );
        assert_eq!(
            schedule_failure_class(&fail("Unit name already exists")),
            "unit_conflict"
        );
        assert_eq!(
            schedule_failure_class(&fail("Sensitive path /home/private/secret-key")),
            "systemd_rejected"
        );
        assert!(spawn_task(Path::new("/tmp"), "tunnel.restart").is_err());
    }

    #[test]
    fn bounded_stdin_is_passed_without_argv_script() {
        let out = command_input("sh", &["-s"], Some("printf 'FROM_STDIN'"), 5).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"FROM_STDIN");
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
