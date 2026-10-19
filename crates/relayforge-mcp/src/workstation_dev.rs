//! Narrow workstation development bridge over the existing private tunnel.
//! No caller-supplied executable, working directory, shell, service name,
//! host, credentials or arbitrary filesystem root. Mutations require a
//! separate local operator-created, permission-checked opt-in file.
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_OUTPUT: usize = 64 * 1024;
const MAX_CONTENT: usize = 48 * 1024;
const OPT_IN: &str = ".config/relayforge/allow-workstation-development";

pub fn tool() -> Value {
    json!({"name":"relayforge_workstation_develop",
        "description":"ThinkPad-only bounded development: tracked repository inventory/reads, fixed Git status, and operator-opted-in tracked source edits, Git sync, release build and tunnel restart. No arbitrary shell or filesystem access.",
        "inputSchema":{"type":"object","properties":{
            "operation":{"type":"string","enum":["repo.status","repo.list","repo.read","repo.write","repo.sync","build.start","task.status","task.logs","tunnel.restart"]},
            "path":{"type":"string","maxLength":192},
            "content":{"type":"string","maxLength":49152},
            "task_id":{"type":"string","maxLength":32}
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

fn dev_enabled(home: &Path) -> bool {
    let path = home.join(OPT_IN);
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
    fs::read(&path).is_ok_and(|value| value == b"ALLOW_RELAYFORGE_DEVELOPMENT\n")
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

fn command(program: &str, args: &[&str], max_seconds: u32) -> Result<Output, String> {
    let seconds = format!("{max_seconds}s");
    let output = Command::new("timeout")
        .args(["-k", "2s", &seconds, program])
        .args(args)
        .output()
        .map_err(|_| "local process unavailable")?;
    if output.stdout.len() > MAX_OUTPUT || output.stderr.len() > MAX_OUTPUT {
        return Err("output too large".into());
    }
    Ok(output)
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
    file.sync_all().map_err(|_| "audit unavailable")
}

fn unit_id(input: &str) -> bool {
    let Some(ts) = input.strip_prefix("relayforge-dev-") else {
        return false;
    };
    ts.len() == 10 && ts.bytes().all(|ch| ch.is_ascii_digit())
}

fn spawn_task(repo: &Path, kind: &str) -> Result<String, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?
        .as_secs();
    let unit = format!("relayforge-dev-{ts}");
    let repo_string = repo.to_str().ok_or("invalid repo path")?;
    let workdir = format!("--working-directory={repo_string}");
    let unit_opt = format!("--unit={unit}");
    let mut args = vec![
        "--user",
        &unit_opt,
        "--collect",
        &workdir,
        "--property=Type=oneshot",
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

pub fn execute(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("expected object")?;
    let operation = obj
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("missing operation")?;
    let (home, repo) = home_and_repo()?;
    match operation {
        "repo.status" if obj.len() == 1 => {
            text_output(git(&repo, &["status", "--short", "--branch"])?)
        }
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
            let data = fs::read(&safe).map_err(|_| "source unreadable")?;
            if data.len() > MAX_CONTENT {
                return Err("source too large; use GitHub source browser".into());
            }
            let value = String::from_utf8(data).map_err(|_| "source is not UTF-8")?;
            Ok(json!({"path":path,"utf8_text":value}).to_string())
        }
        "repo.write" if obj.len() == 3 => {
            if !dev_enabled(&home) {
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
        "tunnel.restart" if obj.len() == 1 => {
            if !dev_enabled(&home) {
                return Err("local development opt-in missing".into());
            }
            audit(&home, operation)?;
            // A transient unit restarts the tunnel independently of the MCP
            // call that initiates it. Reconnection must be checked afterward.
            let result = command(
                "systemd-run",
                &[
                    "--user",
                    "--collect",
                    "--unit=relayforge-dev-tunnel-restart",
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
            Ok(json!({"restart_scheduled":true,"may_disconnect":true}).to_string())
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
    fn strict_task_identifiers_and_required_arguments() {
        assert!(unit_id("relayforge-dev-1792370000"));
        assert!(!unit_id("relayforge-dev-1;id"));
        assert!(!unit_id("sshd"));
        assert!(execute(&json!({"operation":"unknown"})).is_err());
        assert!(execute(&json!({"operation":"repo.read","path":"../../etc/passwd"})).is_err());
        assert!(execute(&json!({"operation":"repo.sync","cmd":"sh"})).is_err());
    }
}
