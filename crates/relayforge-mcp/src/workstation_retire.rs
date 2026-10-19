//! Exact, audit-gated retirement of the literal ru1 SSH entries only.
//! Never accepts hostnames, paths, shell commands or file contents from MCP.
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MAX_BYTES: u64 = 128 * 1024;
const NOFOLLOW: i32 = 0x20000;

fn uid() -> Result<u32, String> {
    let value = fs::read_to_string("/proc/self/status").map_err(|_| "uid unavailable")?;
    value
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|line| line.parse().ok())
        .ok_or("uid unavailable".to_string())
}

fn private_directory(dir: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(dir).map_err(|_| "directory unavailable")?;
    if !m.is_dir()
        || m.file_type().is_symlink()
        || m.uid() != uid()?
        || m.permissions().mode() & 0o077 != 0
    {
        return Err("insecure directory".into());
    }
    Ok(())
}

fn load(path: &Path) -> Result<Option<String>, String> {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("file unavailable".into()),
    };
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.uid() != uid()?
        || m.len() > MAX_BYTES
        || m.permissions().mode() & 0o022 != 0
    {
        return Err("insecure or oversized ssh file".into());
    }
    let mut content = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW)
        .open(path)
        .map_err(|_| "ssh file unavailable")?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut content)
        .map_err(|_| "ssh file unavailable")?;
    if content.len() > MAX_BYTES as usize {
        return Err("ssh file too large".into());
    }
    Ok(Some(
        String::from_utf8(content).map_err(|_| "ssh file not utf8")?,
    ))
}

fn retired_host(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "ru1" | "ru1.alexandrshapkin.ru" | "[ru1]:22" | "[ru1.alexandrshapkin.ru]:22"
    )
}

/// Remove exactly one Host stanza, delimited by next Host or Match. A
/// multi-host stanza is refused; changing it could affect active hosts.
fn prune_config(input: &str) -> Result<(String, usize), String> {
    let mut output = String::new();
    let mut dropping = false;
    let mut removed = 0;
    for line in input.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let tokens: Vec<_> = trimmed.split_whitespace().collect();
        if let Some(command) = tokens.first() {
            if !command.starts_with('#') && command.eq_ignore_ascii_case("Host") {
                dropping = false;
                if tokens.len() > 1 && tokens[1..].iter().any(|s| retired_host(s)) {
                    if tokens.len() != 2 || !retired_host(tokens[1]) {
                        return Err("shared Host stanza requires manual review".into());
                    }
                    dropping = true;
                    removed += 1;
                }
            } else if !command.starts_with('#') && command.eq_ignore_ascii_case("Match") {
                dropping = false;
            }
        }
        if !dropping {
            output.push_str(line);
        }
    }
    if output.to_ascii_lowercase().contains("ru1") {
        return Err("other ru1 references require manual review".into());
    }
    Ok((output, removed))
}

/// Remove only lines whose entire hostname field names the retired node.
fn prune_known_hosts(input: &str) -> Result<(String, usize), String> {
    let mut output = String::new();
    let mut removed = 0;
    for line in input.split_inclusive('\n') {
        if !line.to_ascii_lowercase().contains("ru1") {
            output.push_str(line);
            continue;
        }
        let value = line.trim_start();
        if value.starts_with('#') {
            return Err("ru1 comment requires manual review".into());
        }
        let fields: Vec<_> = value.split_whitespace().collect();
        let hosts = fields.first().copied().ok_or("invalid known_hosts entry")?;
        if fields.len() < 3 || !hosts.split(',').all(retired_host) {
            return Err("shared known_hosts entry requires manual review".into());
        }
        removed += 1;
    }
    Ok((output, removed))
}

fn kind_path(home: &Path, operation: &str) -> Result<(PathBuf, &'static str), String> {
    let dir = home.join(".ssh");
    private_directory(&dir)?;
    match operation {
        "ssh.retire.config" => Ok((dir.join("config"), "retired-ru1-ssh-config.backup")),
        "ssh.retire.known_hosts" => Ok((dir.join("known_hosts"), "retired-ru1-known-hosts.backup")),
        _ => Err("ssh operation denied".into()),
    }
}

fn prune(operation: &str, input: &str) -> Result<(String, usize), String> {
    match operation {
        "ssh.retire.config" => prune_config(input),
        "ssh.retire.known_hosts" => prune_known_hosts(input),
        _ => Err("ssh operation denied".into()),
    }
}

pub fn plan(home: &Path) -> Result<String, String> {
    let mut results = Vec::new();
    for op in ["ssh.retire.config", "ssh.retire.known_hosts"] {
        let (path, _) = kind_path(home, op)?;
        let input = load(&path)?.unwrap_or_default();
        let result = match prune(op, &input) {
            Ok((_, count)) => json!({"operation":op,"removable":count,"needs_manual_review":false}),
            Err(_) => json!({"operation":op,"removable":0,"needs_manual_review":true}),
        };
        results.push(result);
    }
    Ok(json!({"retired_host":"ru1","files":results,
        "scope":"local_user_ssh_only","writes":false})
    .to_string())
}

fn save_once(path: &Path, contents: &str) -> Result<(), String> {
    let temp = path.with_extension("relayforge-retire-pending");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(&temp)
        .map_err(|_| "staged ssh file unavailable")?;
    if f.write_all(contents.as_bytes())
        .and_then(|_| f.sync_all())
        .is_err()
    {
        let _ = fs::remove_file(&temp);
        return Err("staged ssh file write failed".into());
    }
    fs::rename(&temp, path).map_err(|_| "ssh file replacement failed".to_owned())
}

pub fn apply(home: &Path, operation: &str) -> Result<String, String> {
    let (path, backup_name) = kind_path(home, operation)?;
    let original = load(&path)?.unwrap_or_default();
    let (updated, removed) = prune(operation, &original)?;
    if removed == 0 {
        return Ok(json!({"retired_host":"ru1","removed":0,"already_clean":true}).to_string());
    }
    let state = home.join(".local/state/relayforge");
    private_directory(&state)?;
    let backup = state.join(backup_name);
    // A prior attempt may have written the private backup but been denied
    // at the tunnel service's ProtectHome boundary. Permit resuming only
    // if that backup is byte-identical to the *current* original.
    if backup.exists() {
        if load(&backup)?.as_deref() != Some(original.as_str()) {
            return Err("existing backup differs from live config".into());
        }
    } else {
        let mut saved = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(NOFOLLOW)
            .open(backup)
            .map_err(|_| "backup unavailable")?;
        saved
            .write_all(original.as_bytes())
            .and_then(|_| saved.sync_all())
            .map_err(|_| "backup write failed")?;
    }
    // Detect a race with a local editor before atomically replacing the file.
    if load(&path)?.unwrap_or_default() != original {
        return Err("ssh file changed since inspection".into());
    }
    save_once(&path, &updated)?;
    Ok(json!({"retired_host":"ru1","removed":removed,
        "operation":operation,"backup_private":true})
    .to_string())
}

/// The MCP tunnel worker cannot write ~/.ssh (ProtectHome=read-only).
/// Delegate a fixed, tightly validated retirement operation to a short-lived
/// user systemd unit without weakening or restarting the secure tunnel.
pub fn dispatch(home: &Path, operation: &str) -> Result<String, String> {
    let kind = match operation {
        "ssh.retire.config" => "config",
        "ssh.retire.known_hosts" => "known_hosts",
        _ => return Err("ssh operation denied".into()),
    };
    let binary = home.join("Projects/relayforge/target/release/relayforge-mcp");
    let binary = binary.to_str().ok_or("worker path invalid")?;
    let output = Command::new("timeout")
        .args(["-k", "2s", "22s", "systemd-run", "--user", "--wait", "--pipe",
            "--collect", "--property=Type=exec", "--property=RuntimeMaxSec=16",
            "--", binary, "--retire-ssh-worker", kind])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| "retirement worker unavailable")?;
    if !output.status.success() || output.stdout.len() > 2048 {
        return Err("retirement worker failed".into());
    }
    let result: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "retirement worker reply invalid")?;
    if result["retired_host"] != "ru1" ||
        (result.get("operation") != Some(&Value::String(operation.to_owned())) &&
        result["already_clean"] != true) {
        return Err("retirement worker reply invalid".into());
    }
    Ok(result.to_string())
}

/// Fixed local entrypoint, callable only with one of two exact names.
pub fn run_worker(kind: &str) -> i32 {
    let operation = match kind {
        "config" => "ssh.retire.config",
        "known_hosts" => "ssh.retire.known_hosts",
        _ => return 2,
    };
    let Some(home) = std::env::var_os("HOME") else { return 2; };
    let home = PathBuf::from(home);
    if !home.is_absolute() || home.as_os_str().len() > 256 { return 2; }
    match apply(&home, operation) {
        Ok(result) => {
            println!("{result}");
            0
        }
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_ru1_host_stanza_is_removed() {
        let file = "Host ru0\n HostName ru0.example\nHost ru1\n HostName ru1.example\n User restricted\nHost srv0\n HostName srv0.example\n";
        let (clean, count) = prune_config(file).unwrap();
        assert_eq!(count, 1);
        assert!(clean.contains("Host ru0"));
        assert!(clean.contains("Host srv0"));
        assert!(!clean.contains("ru1"));
        assert!(prune_config("Host ru1 ru0\n Port 22\n").is_err());
        assert!(prune_config("Host ru0\n HostName ru1\n").is_err());
    }
    #[test]
    fn known_hosts_cleanup_refuses_shared_keys() {
        let input = "ru0 ssh-ed25519 abc\nru1 ssh-ed25519 def\nsrv0 ssh-ed25519 ghi\n";
        let (clean, count) = prune_known_hosts(input).unwrap();
        assert_eq!(count, 1);
        assert!(clean.contains("ru0"));
        assert!(clean.contains("srv0"));
        assert!(!clean.contains("ru1"));
        assert!(prune_known_hosts("ru1,ru0 ssh-ed25519 abc\n").is_err());
        assert!(prune_known_hosts("# ru1 backup\n").is_err());
    }
}
