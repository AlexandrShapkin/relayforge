//! Read-only four-project inventory. Names and paths are compiled-in policy,
//! not supplied from GitHub Issues, repository TOML or arbitrary MCP strings.
//! No git fetch/pull, delete, install, host shell or task execution.
use crate::workstation_dev::{command, git, unsafe_uid};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

const PROJECTS: [&str; 4] = ["codex-smart", "relayforge", "assistant-hub", "rustcraft"];
const ARTIFACTS: [&str; 6] = [
    "target",
    "dist",
    "node_modules",
    ".pytest_cache",
    "__pycache__",
    "web/node_modules",
];

fn safe_directory(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_dir()
        && !meta.file_type().is_symlink()
        && meta.uid() == unsafe_uid()
        && meta.permissions().mode() & 0o022 == 0
}

fn project_root(home: &Path, project: &str) -> Option<PathBuf> {
    if !PROJECTS.contains(&project) || !safe_directory(home) {
        return None;
    }
    let projects = home.join("Projects");
    if !safe_directory(&projects) {
        return None;
    }
    let root = projects.join(project);
    if !safe_directory(&root) {
        return None;
    }
    let gitmeta = fs::symlink_metadata(root.join(".git")).ok()?;
    if gitmeta.file_type().is_symlink()
        || (!gitmeta.is_dir() && !gitmeta.is_file())
        || gitmeta.uid() != unsafe_uid()
    {
        return None;
    }
    Some(root)
}

fn git_text(repo: &Path, args: &[&str]) -> Option<String> {
    let output = git(repo, args).ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn git_count(repo: &Path, args: &[&str], delim: u8) -> Option<usize> {
    let output = git(repo, args).ok()?;
    if !output.status.success() {
        return None;
    }
    Some(
        output
            .stdout
            .split(|b| *b == delim)
            .filter(|part| !part.is_empty())
            .count(),
    )
}

fn head_sha(repo: &Path, reference: &str) -> Option<String> {
    let sha = git_text(repo, &["rev-parse", "--verify", reference])?;
    let sha = sha.trim();
    if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(sha.to_owned())
    } else {
        None
    }
}

fn worktree_counts(repo: &Path) -> Value {
    let Some(text) = git_text(repo, &["worktree", "list", "--porcelain"]) else {
        return json!({"status":"unverified"});
    };
    // Never return worktree absolute paths or names: they can be private.
    json!({
        "status":"observed",
        "count":text.lines().filter(|line| line.starts_with("worktree ")).count(),
        "locked":text.lines().filter(|line| *line == "locked" || line.starts_with("locked ")).count(),
        "prunable":text.lines().filter(|line| *line == "prunable" || line.starts_with("prunable ")).count(),
        "cleanup_authorized":false
    })
}

fn free_kib(root: &Path) -> Option<u64> {
    let name = root.to_str()?;
    let output = command("df", &["-Pk", "--", name], 8).ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    // POSIX df -P: filesystem, blocks, used, available, capacity, mount.
    let available = stdout.lines().nth(1)?.split_whitespace().nth(3)?;
    available.parse::<u64>().ok()
}

fn artifact_snapshot(root: &Path) -> Value {
    let mut found = Vec::new();
    for relative in ARTIFACTS {
        let path = root.join(relative);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        // Deliberately report no size when a directory can contain unique
        // user data or nested symlinks. Even familiar names aren't deletion grants.
        found.push(json!({
            "path":relative,
            "directory":meta.is_dir() && !meta.file_type().is_symlink(),
            "symlink":meta.file_type().is_symlink(),
            "cleanup_authorized":false,
            "stale":Value::Null
        }));
    }
    json!(found)
}

fn checks(project: &str) -> &'static [&'static str] {
    match project {
        "codex-smart" => &["just check", "just security"],
        "relayforge" => &["just verify"],
        "assistant-hub" => &["just verify"],
        "rustcraft" => &["just ci"],
        _ => &[],
    }
}

fn one(home: &Path, project: &str) -> Value {
    let Some(root) = project_root(home, project) else {
        return json!({"project":project,"status":"unavailable",
            "remote_main_verified":false,"build_executed":false});
    };
    let head = head_sha(&root, "HEAD");
    let local_tracking = head_sha(&root, "refs/remotes/origin/main");
    let branch = git_text(&root, &["symbolic-ref", "--quiet", "--short", "HEAD"])
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty());
    let tracked_clean = git_text(&root, &["status", "--porcelain=v1", "--untracked-files=no"])
        .map(|s| s.is_empty());
    let untracked_count = git_count(
        &root,
        &["ls-files", "--others", "--exclude-standard", "-z"],
        0,
    );
    let branch_count = git_count(
        &root,
        &["for-each-ref", "--format=%(refname)", "refs/heads"],
        b'\n',
    );
    json!({
        "project":project,
        "status":if head.is_some() {"observed"} else {"unverified"},
        "head":head,
        "branch":branch,
        "on_main":branch.as_deref()==Some("main"),
        "tracked_clean":tracked_clean,
        "untracked_count":untracked_count,
        "local_branch_count":branch_count,
        "origin_main_cached":local_tracking,
        // Remote tracking refs can be stale. A live GitHub main read
        // through the independent connector is required to assess currency.
        "remote_main_verified":false,
        "worktrees":worktree_counts(&root),
        "disk_available_kib":free_kib(&root),
        "artifact_candidates":artifact_snapshot(&root),
        "native_checks":checks(project),
        "build_executed":false,
        "cleanup_authorized":false
    })
}

/// Only the empty argument object is accepted by the dispatching caller.
pub fn inventory(home: &Path) -> Result<String, String> {
    if !home.is_absolute() || home.as_os_str().len() > 256 {
        return Err("home invalid".into());
    }
    Ok(json!({"api_revision":9, "read_only":true,
        "projects":PROJECTS.iter().map(|name| one(home,name)).collect::<Vec<_>>(),
        "note":"Live GitHub main and real checks require separate provider evidence; no cleanup is authorized."
    }).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn fixed_registry_rejects_arbitrary_names_and_symlinks() {
        let base =
            std::env::temp_dir().join(format!("relayforge-inventory-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("Projects/relayforge")).unwrap();
        fs::create_dir_all(base.join("Projects/codex-smart")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::create_dir_all(base.join("Projects/relayforge/.git")).unwrap();
        symlink(base.join("outside"), base.join("Projects/assistant-hub")).unwrap();
        assert!(project_root(&base, "relayforge").is_some());
        assert!(project_root(&base, "assistant-hub").is_none());
        assert!(project_root(&base, "../../.ssh").is_none());
        assert!(project_root(&base, "arbitrary").is_none());
        assert!(project_root(&base, "codex-smart").is_none());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn missing_projects_never_become_claimed_verified() {
        let base = std::env::temp_dir().join(format!(
            "relayforge-inventory-missing-{}",
            std::process::id()
        ));
        let out: Value = serde_json::from_str(&inventory(&base).unwrap()).unwrap();
        assert_eq!(out["projects"].as_array().unwrap().len(), 4);
        assert!(out["projects"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["status"] == "unavailable" && p["remote_main_verified"] == false));
    }

    #[test]
    fn paths_and_unknown_artifacts_never_authorize_deletion() {
        let base = std::env::temp_dir().join(format!(
            "relayforge-inventory-artifacts-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("target")).unwrap();
        fs::write(base.join("target/unique-report.txt"), b"unique").unwrap();
        let snapshot = artifact_snapshot(&base);
        assert_eq!(snapshot[0]["cleanup_authorized"], false);
        assert!(snapshot[0]["stale"].is_null());
        let _ = fs::remove_dir_all(base);
    }
}
