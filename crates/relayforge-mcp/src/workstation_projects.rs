//! Read-only four-project inventory. Names and paths are compiled-in policy,
//! not supplied from GitHub Issues, repository TOML or arbitrary MCP strings.
//! No git fetch/pull, delete, install, host shell or task execution.
use crate::workstation_dev::{read_capped, unsafe_uid};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
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

// Pin each directory while walking: no symlink components or path-check/use race.
// Linux-only, like the existing workstation bridge; no new dependency or grant.
fn open_directory(path: &Path) -> Option<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(0x10000 | 0x20000)
        .open(path)
        .ok()
}

fn fd_path(file: &File) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    ))
}

fn trusted_directory(file: &File) -> bool {
    let Ok(meta) = file.metadata() else {
        return false;
    };
    meta.uid() == unsafe_uid()
        && meta.permissions().mode() & 0o022 == 0
        && meta.permissions().mode() & 0o500 == 0o500
}

struct Repository {
    root: File,
    metadata: File,
}

fn project_root(home: &Path, project: &str) -> Option<Repository> {
    if !PROJECTS.contains(&project) || !home.is_absolute() {
        return None;
    }
    let mut directory = open_directory(Path::new("/"))?;
    for part in home.components() {
        match part {
            Component::RootDir => (),
            Component::Normal(name) => directory = open_directory(&fd_path(&directory).join(name))?,
            _ => return None,
        }
    }
    if !trusted_directory(&directory) {
        return None;
    }
    let projects = open_directory(&fd_path(&directory).join("Projects"))?;
    if !trusted_directory(&projects) {
        return None;
    }
    let root = open_directory(&fd_path(&projects).join(project))?;
    if !trusted_directory(&root) {
        return None;
    }
    // Linked-worktree .git files can redirect outside the fixed registry.
    // Keep them unavailable until a separately reviewed metadata-root policy exists.
    let metadata = open_directory(&fd_path(&root).join(".git"))?;
    if !trusted_directory(&metadata) {
        return None;
    }
    Some(Repository { root, metadata })
}

fn diagnostic_command(program: &str, args: &[&str]) -> Result<Output, String> {
    // Do not inherit GIT_DIR, config injection, PATH, pager or credential helpers.
    // No optional locks: even git status must not refresh the on-disk index.
    let mut child = Command::new("/usr/bin/timeout")
        .args(["-k", "2s", "12s", program])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "diagnostic process unavailable")?;
    let stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let out = thread::spawn(move || read_capped(stdout));
    let err = thread::spawn(move || read_capped(stderr));
    let status = child.wait().map_err(|_| "diagnostic wait failed")?;
    Ok(Output {
        status,
        stdout: out.join().map_err(|_| "stdout reader failed")??,
        stderr: err.join().map_err(|_| "stderr reader failed")??,
    })
}

fn git(repo: &Repository, args: &[&str]) -> Result<Output, String> {
    let root = fd_path(&repo.root);
    let metadata = fd_path(&repo.metadata);
    let mut fixed = vec![
        "--no-pager",
        "--no-optional-locks",
        "--git-dir",
        metadata.to_str().ok_or("invalid metadata")?,
        "--work-tree",
        root.to_str().ok_or("invalid root")?,
        "-C",
        root.to_str().ok_or("invalid root")?,
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "submodule.recurse=false",
    ];
    fixed.extend_from_slice(args);
    diagnostic_command("/usr/bin/git", &fixed)
}

fn git_text(repo: &Repository, args: &[&str]) -> Option<String> {
    let output = git(repo, args).ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn git_count(repo: &Repository, args: &[&str], delim: u8) -> Option<usize> {
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

fn head_sha(repo: &Repository, reference: &str) -> Option<String> {
    let sha = git_text(repo, &["rev-parse", "--verify", reference])?;
    let sha = sha.trim();
    if sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(sha.to_owned())
    } else {
        None
    }
}

fn worktree_counts(repo: &Repository) -> Value {
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
    let output = diagnostic_command("/usr/bin/df", &["-Pk", "--", name]).ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    // POSIX df -P: filesystem, blocks, used, available, capacity, mount.
    let available = stdout.lines().nth(1)?.split_whitespace().nth(3)?;
    available.parse::<u64>().ok()
}

fn artifact_snapshot(root: &File) -> Value {
    let mut found = Vec::new();
    for relative in ARTIFACTS {
        let (parent, name) = relative.rsplit_once('/').unwrap_or(("", relative));
        let directory = if parent.is_empty() {
            root.try_clone().ok()
        } else {
            open_directory(&fd_path(root).join(parent))
        };
        let Some(directory) = directory else {
            continue;
        };
        let path = fd_path(&directory).join(name);
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
    let tracked_clean = git_text(
        &root,
        &[
            "status",
            "--porcelain=v1",
            "--untracked-files=no",
            "--ignore-submodules=all",
        ],
    )
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
        "disk_available_kib":free_kib(&fd_path(&root.root)),
        "artifact_candidates":artifact_snapshot(&root.root),
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

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "relayforge-inventory-guard-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::create_dir_all(path.join("Projects/relayforge/.git")).unwrap();
            Self(path)
        }
        fn root(&self) -> PathBuf {
            self.0.join("Projects/relayforge")
        }
        fn native_git(&self, args: &[&str]) {
            let output = Command::new("/usr/bin/git")
                .arg("-C")
                .arg(self.root())
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "fixture git failed");
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn permission_denials_and_writable_roots_fail_closed() {
        let f = Fixture::new();
        for path in [
            &f.0,
            &f.0.join("Projects"),
            &f.root(),
            &f.root().join(".git"),
        ] {
            let original = fs::metadata(path).unwrap().permissions();
            for mode in [0o000, 0o200, 0o777] {
                // Fixture-only modes; never modify a real checkout or host grant.
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
                let denied = project_root(&f.0, "relayforge").is_none();
                fs::set_permissions(path, original.clone()).unwrap();
                assert!(denied, "mode {mode:o} must be denied even under root tests");
            }
        }
    }

    #[test]
    fn symlinked_ancestors_metadata_and_gitdir_files_are_denied() {
        let f = Fixture::new();
        let alias = f.0.join("alias");
        symlink(f.0.join("Projects"), &alias).unwrap();
        assert!(project_root(&alias.join(".."), "relayforge").is_none());
        let alias_home = f.0.join("home-link");
        symlink(&f.0, &alias_home).unwrap();
        assert!(project_root(&alias_home, "relayforge").is_none());
        fs::rename(f.root().join(".git"), f.0.join("metadata")).unwrap();
        symlink(f.0.join("metadata"), f.root().join(".git")).unwrap();
        assert!(project_root(&f.0, "relayforge").is_none());
        fs::remove_file(f.root().join(".git")).unwrap();
        fs::write(
            f.root().join(".git"),
            format!("gitdir: {}", f.0.join("metadata").display()),
        )
        .unwrap();
        assert_eq!(one(&f.0, "relayforge")["status"], "unavailable");
        assert!(inventory(Path::new("relative")).is_err());
    }

    #[test]
    fn corrupt_repository_is_unverified_without_output_or_authority() {
        let f = Fixture::new();
        fs::write(f.root().join(".git/HEAD"), b"PRIVATE invalid head").unwrap();
        let out = one(&f.0, "relayforge");
        assert_eq!(out["status"], "unverified");
        assert!(out["head"].is_null());
        assert_eq!(out["remote_main_verified"], false);
        assert_eq!(out["cleanup_authorized"], false);
        assert!(!out.to_string().contains("PRIVATE"));
    }

    #[test]
    fn observed_checkout_is_read_only_and_does_not_execute_repo_helpers() {
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        fs::write(f.root().join("tracked.txt"), b"tracked").unwrap();
        f.native_git(&["add", "tracked.txt"]);
        f.native_git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fixture",
        ]);
        fs::write(f.root().join("untracked.txt"), b"unique evidence").unwrap();
        let marker = f.0.join("executed");
        f.native_git(&[
            "config",
            "core.fsmonitor",
            &format!("touch {}", marker.display()),
        ]);
        f.native_git(&["config", "core.untrackedCache", "true"]);
        let index = f.root().join(".git/index");
        let bytes = fs::read(&index).unwrap();
        let modified = fs::metadata(&index).unwrap().modified().unwrap();
        let out = one(&f.0, "relayforge");
        assert_eq!(out["status"], "observed");
        assert_eq!(out["branch"], "main");
        assert_eq!(out["tracked_clean"], true);
        assert_eq!(out["untracked_count"], 1);
        assert_eq!(out["local_branch_count"], 1);
        assert_eq!(out["worktrees"]["count"], 1);
        assert!(out["disk_available_kib"].as_u64().is_some());
        assert!(!marker.exists());
        assert_eq!(fs::read(&index).unwrap(), bytes);
        assert_eq!(fs::metadata(index).unwrap().modified().unwrap(), modified);
        assert_eq!(
            fs::read(f.root().join("untracked.txt")).unwrap(),
            b"unique evidence"
        );
    }

    #[test]
    fn pinned_checkout_survives_path_replacement_without_following_it() {
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        let repo = project_root(&f.0, "relayforge").unwrap();
        fs::rename(f.root(), f.0.join("saved")).unwrap();
        fs::create_dir_all(f.0.join("outside/target")).unwrap();
        symlink(f.0.join("outside"), f.root()).unwrap();
        assert_eq!(
            git_text(&repo, &["symbolic-ref", "--short", "HEAD"])
                .unwrap()
                .trim(),
            "main"
        );
        assert_eq!(artifact_snapshot(&repo.root), json!([]));
        assert!(project_root(&f.0, "relayforge").is_none());
    }

    #[test]
    fn nested_artifact_symlinks_are_not_followed() {
        let f = Fixture::new();
        fs::create_dir_all(f.0.join("outside/node_modules")).unwrap();
        symlink(f.0.join("outside"), f.root().join("web")).unwrap();
        symlink(f.0.join("outside"), f.root().join("target")).unwrap();
        let out = artifact_snapshot(&open_directory(&f.root()).unwrap());
        assert_eq!(out.as_array().unwrap().len(), 1);
        assert_eq!(out[0]["path"], "target");
        assert_eq!(out[0]["symlink"], true);
        assert_eq!(out[0]["cleanup_authorized"], false);
    }

    #[test]
    fn diagnostic_environment_is_an_explicit_allowlist() {
        let out = diagnostic_command("/usr/bin/env", &[]).unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        let keys: std::collections::BTreeSet<_> =
            text.lines().map(|s| s.split_once('=').unwrap().0).collect();
        assert_eq!(
            keys,
            std::collections::BTreeSet::from([
                "PATH",
                "LC_ALL",
                "GIT_CONFIG_NOSYSTEM",
                "GIT_CONFIG_GLOBAL",
                "GIT_OPTIONAL_LOCKS"
            ])
        );
    }

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
        let snapshot = artifact_snapshot(&open_directory(&base).unwrap());
        assert_eq!(snapshot[0]["cleanup_authorized"], false);
        assert!(snapshot[0]["stale"].is_null());
        let _ = fs::remove_dir_all(base);
    }
}
