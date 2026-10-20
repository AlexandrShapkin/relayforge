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
    // A present redirect is refused. If one appears later it has no effect:
    // inventory never asks Git to interpret metadata or follows commondir.
    if !fs::symlink_metadata(fd_path(&metadata).join("commondir"))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return None;
    }
    Some(Repository { root, metadata })
}

fn diagnostic_command(program: &str, args: &[&str]) -> Result<Output, String> {
    // Do not inherit GIT_DIR, config injection, PATH, pager or credential helpers.
    // Used only for fixed df probes; no Git command is executed by inventory.
    let mut child = Command::new("/usr/bin/timeout")
        .args(["-k", "2s", "12s", program])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
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

// Git is deliberately not invoked for inventory. Even nominally read-only Git
// commands interpret mutable config, commondir, ref symlinks and object stores.
// These bounded reads never interpret config, alternates, gitdir or commondir.
fn metadata_text(root: &File, relative: &str) -> Option<String> {
    let mut directory = root.try_clone().ok()?;
    let mut parts = relative.split('/').peekable();
    while let Some(name) = parts.next() {
        if name.is_empty() || name == "." || name == ".." {
            return None;
        }
        let path = fd_path(&directory).join(name);
        if parts.peek().is_some() {
            directory = open_directory(&path)?;
            if !trusted_directory(&directory) {
                return None;
            }
        } else {
            // NONBLOCK avoids waiting on a substituted FIFO before fstat.
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(0x20000 | 0x800)
                .open(path)
                .ok()?;
            let meta = file.metadata().ok()?;
            if !meta.is_file()
                || meta.nlink() != 1
                || meta.uid() != unsafe_uid()
                || meta.permissions().mode() & 0o022 != 0
                || meta.len() > 65536
            {
                return None;
            }
            return String::from_utf8(read_capped(file).ok()?).ok();
        }
    }
    None
}

fn sha(value: &str) -> Option<String> {
    let value = value.trim();
    (value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())).then(|| value.to_owned())
}

fn ref_name(value: &str) -> bool {
    value.starts_with("refs/")
        && value.len() <= 192
        && value.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && !part.ends_with('.')
                && !part.ends_with(".lock")
        })
        && !value.contains("..")
        && !value.contains("@{")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b))
}

fn packed_refs(repo: &Repository) -> Option<std::collections::BTreeMap<String, String>> {
    let path = fd_path(&repo.metadata).join("packed-refs");
    if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return Some(std::collections::BTreeMap::new());
    }
    let text = metadata_text(&repo.metadata, "packed-refs")?;
    let mut refs = std::collections::BTreeMap::new();
    for line in text
        .lines()
        .filter(|s| !s.starts_with('#') && !s.starts_with('^'))
    {
        let (value, name) = line.split_once(' ')?;
        if !ref_name(name) || refs.insert(name.to_owned(), sha(value)?).is_some() {
            return None;
        }
    }
    Some(refs)
}

fn head_sha(repo: &Repository, reference: &str) -> Option<String> {
    let text = metadata_text(&repo.metadata, reference);
    if let Some(value) = text.as_deref().and_then(sha) {
        return Some(value);
    }
    if reference == "HEAD" {
        let name = text.as_deref()?.trim().strip_prefix("ref: ")?;
        if !ref_name(name) {
            return None;
        }
        return head_sha(repo, name);
    }
    // Do not follow symbolic-ref chains or symlinks from repository metadata.
    if !ref_name(reference) {
        return None;
    }
    packed_refs(repo)?.get(reference).cloned()
}

fn branch_count(repo: &Repository) -> Option<usize> {
    fn visit(
        dir: &File,
        prefix: &str,
        names: &mut std::collections::BTreeSet<String>,
        budget: &mut usize,
        depth: usize,
    ) -> Option<()> {
        if depth > 16 {
            return None;
        }
        for item in fs::read_dir(fd_path(dir)).ok()? {
            if *budget == 0 {
                return None;
            }
            *budget -= 1;
            let item = item.ok()?;
            let name = item.file_name().into_string().ok()?;
            let relative = format!("{prefix}/{name}");
            if !ref_name(&relative) {
                return None;
            }
            let meta = item.file_type().ok()?;
            if meta.is_dir() {
                let child = open_directory(&fd_path(dir).join(name))?;
                if !trusted_directory(&child) {
                    return None;
                }
                visit(&child, &relative, names, budget, depth + 1)?;
            } else if meta.is_file() {
                names.insert(relative);
            } else {
                return None;
            }
        }
        Some(())
    }
    let mut names: std::collections::BTreeSet<_> = packed_refs(repo)?
        .into_keys()
        .filter(|name| name.starts_with("refs/heads/"))
        .collect();
    let refs = open_directory(&fd_path(&repo.metadata).join("refs"))?;
    if !trusted_directory(&refs) {
        return None;
    }
    let heads = open_directory(&fd_path(&refs).join("heads"))?;
    if !trusted_directory(&heads) {
        return None;
    }
    visit(&heads, "refs/heads", &mut names, &mut 1024, 0)?;
    Some(names.len())
}

fn worktree_counts(repo: &Repository) -> Value {
    let path = fd_path(&repo.metadata).join("worktrees");
    if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return json!({"status":"observed","count":1,"locked":0,"prunable":Value::Null,"cleanup_authorized":false});
    }
    let observed = (|| {
        let directory = open_directory(&path)?;
        if !trusted_directory(&directory) {
            return None;
        }
        let mut count = 1;
        let mut locked = 0;
        for item in fs::read_dir(fd_path(&directory)).ok()?.take(1025) {
            if count > 1024 {
                return None;
            }
            let item = item.ok()?;
            let child = open_directory(&fd_path(&directory).join(item.file_name()))?;
            if !trusted_directory(&child) {
                return None;
            }
            // Never follow gitdir files or inspect registered checkout paths.
            count += 1;
            if fs::symlink_metadata(fd_path(&child).join("locked")).is_ok() {
                locked += 1;
            }
        }
        Some((count, locked))
    })();
    match observed {
        Some((count, locked)) => {
            json!({"status":"observed","count":count,"locked":locked,"prunable":Value::Null,"cleanup_authorized":false})
        }
        None => json!({"status":"unverified","cleanup_authorized":false}),
    }
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
    let branch = metadata_text(&root.metadata, "HEAD")
        .and_then(|text| {
            text.trim()
                .strip_prefix("ref: refs/heads/")
                .map(str::to_owned)
        })
        .filter(|name| ref_name(&format!("refs/heads/{name}")));
    let branch_count = branch_count(&root);
    json!({
        "project":project,
        "status":if head.is_some() {"observed"} else {"unverified"},
        "head":head,
        "branch":branch,
        "on_main":branch.as_deref()==Some("main"),
        "tracked_clean":Value::Null,
        "tracked_clean_note":"unverified: inventory never invokes Git status or reads working-file contents",
        "untracked_count":Value::Null,
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
    fn external_commondir_is_denied_and_cannot_redirect_pinned_reads() {
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        fs::write(f.root().join("tracked"), b"local").unwrap();
        f.native_git(&["add", "."]);
        f.native_git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "local",
        ]);
        let external = Fixture::new();
        external.native_git(&["init", "--initial-branch=private-external-branch"]);
        fs::write(external.root().join("tracked"), b"external").unwrap();
        external.native_git(&["add", "."]);
        external.native_git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "external",
        ]);
        let pinned = project_root(&f.0, "relayforge").unwrap();
        let local_sha = head_sha(&pinned, "HEAD").unwrap();
        let external_sha = fs::read_to_string(
            external
                .root()
                .join(".git/refs/heads/private-external-branch"),
        )
        .unwrap();
        fs::write(
            f.root().join(".git/commondir"),
            external.root().join(".git").to_str().unwrap(),
        )
        .unwrap();
        let out = one(&f.0, "relayforge");
        assert_eq!(out["status"], "unavailable");
        for private in [
            "private-external-branch",
            external_sha.trim(),
            external.root().to_str().unwrap(),
        ] {
            assert!(!out.to_string().contains(private));
        }
        // A redirect appearing after validation cannot affect direct fd reads.
        assert_eq!(
            head_sha(&pinned, "HEAD").as_deref(),
            Some(local_sha.as_str())
        );
    }

    #[test]
    fn metadata_symlinks_and_config_object_redirects_are_not_followed() {
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        let external = f.0.join("external-metadata");
        fs::create_dir(&external).unwrap();
        fs::write(
            external.join("HEAD"),
            b"ref: refs/heads/private-external-branch\n",
        )
        .unwrap();
        let secret_sha = "1234567890123456789012345678901234567890";
        fs::write(external.join("ref"), secret_sha).unwrap();
        fs::write(
            external.join("packed-refs"),
            format!("{secret_sha} refs/heads/main\n"),
        )
        .unwrap();
        let metadata = f.root().join(".git");
        fs::remove_file(metadata.join("HEAD")).unwrap();
        symlink(external.join("HEAD"), metadata.join("HEAD")).unwrap();
        let out = one(&f.0, "relayforge");
        assert!(out["head"].is_null() && out["branch"].is_null());
        fs::remove_file(metadata.join("HEAD")).unwrap();
        fs::write(metadata.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        symlink(external.join("ref"), metadata.join("refs/heads/main")).unwrap();
        symlink(external.join("packed-refs"), metadata.join("packed-refs")).unwrap();
        let out = one(&f.0, "relayforge");
        assert!(out["head"].is_null());
        assert!(!out.to_string().contains(secret_sha));
        fs::remove_file(metadata.join("refs/heads/main")).unwrap();
        fs::remove_file(metadata.join("packed-refs")).unwrap();
        fs::hard_link(external.join("ref"), metadata.join("refs/heads/main")).unwrap();
        assert!(one(&f.0, "relayforge")["head"].is_null());
        fs::remove_file(metadata.join("refs/heads/main")).unwrap();
        // Internal config/objects are never consulted, even when they redirect.
        fs::write(
            metadata.join("config"),
            format!("[include]\npath = {}\n", external.join("HEAD").display()),
        )
        .unwrap();
        fs::create_dir_all(metadata.join("objects/info")).unwrap();
        fs::write(
            metadata.join("objects/info/alternates"),
            external.to_str().unwrap(),
        )
        .unwrap();
        let out = one(&f.0, "relayforge");
        assert!(!out.to_string().contains("private-external-branch"));
        assert!(!out.to_string().contains(external.to_str().unwrap()));
    }

    #[test]
    fn concurrent_git_config_cannot_execute_filters_or_write_checkout_data() {
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Barrier,
        };
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        fs::write(f.root().join("tracked.txt"), b"same").unwrap();
        fs::write(f.root().join(".gitattributes"), b"*.txt filter=probe\n").unwrap();
        f.native_git(&["add", "."]);
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
        fs::write(f.root().join("tracked.txt"), b"same").unwrap();
        let index = f.root().join(".git/index");
        let index_bytes = fs::read(&index).unwrap();
        let index_mtime = fs::metadata(&index).unwrap().modified().unwrap();
        let tracked_mtime = fs::metadata(f.root().join("tracked.txt"))
            .unwrap()
            .modified()
            .unwrap();
        let config = f.root().join(".git/config");
        let baseline = fs::read_to_string(&config).unwrap();
        let marker = f.0.join("filter-executed");
        let hostile = format!("{baseline}\n[filter \"probe\"]\nclean = touch {}; cat\nsmudge = touch {}; cat\nprocess = touch {}\n", marker.display(), marker.display(), marker.display());
        let barrier = Arc::new(Barrier::new(2));
        let stop = Arc::new(AtomicBool::new(false));
        let changes = Arc::new(AtomicUsize::new(0));
        let thread_barrier = barrier.clone();
        let thread_stop = stop.clone();
        let thread_changes = changes.clone();
        let writer = thread::spawn(move || {
            let replacement = config.with_file_name("review-config-next");
            fs::write(&replacement, &hostile).unwrap();
            fs::rename(&replacement, &config).unwrap();
            thread_changes.fetch_add(1, Ordering::SeqCst);
            thread_barrier.wait();
            while !thread_stop.load(Ordering::SeqCst) {
                for content in [&baseline, &hostile] {
                    fs::write(&replacement, content).unwrap();
                    fs::rename(&replacement, &config).unwrap();
                    thread_changes.fetch_add(1, Ordering::SeqCst);
                    thread::yield_now();
                }
            }
        });
        barrier.wait();
        let snapshots: Vec<_> = (0..32).map(|_| one(&f.0, "relayforge")).collect();
        stop.store(true, Ordering::SeqCst);
        writer.join().unwrap();
        assert!(changes.load(Ordering::SeqCst) > 1);
        assert!(snapshots
            .iter()
            .all(|out| out["tracked_clean"].is_null() && out["status"] == "observed"));
        assert!(!marker.exists());
        assert_eq!(fs::read(&index).unwrap(), index_bytes);
        assert_eq!(
            fs::metadata(index).unwrap().modified().unwrap(),
            index_mtime
        );
        assert_eq!(fs::read(f.root().join("tracked.txt")).unwrap(), b"same");
        assert_eq!(
            fs::metadata(f.root().join("tracked.txt"))
                .unwrap()
                .modified()
                .unwrap(),
            tracked_mtime
        );
        assert_eq!(
            fs::read(f.root().join("untracked.txt")).unwrap(),
            b"unique evidence"
        );
        assert_eq!(
            fs::read(f.root().join(".gitattributes")).unwrap(),
            b"*.txt filter=probe\n"
        );
    }

    #[test]
    fn loose_and_packed_ref_observations_remain_bounded_and_local() {
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        fs::write(f.root().join("tracked"), b"local").unwrap();
        f.native_git(&["add", "."]);
        f.native_git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fixture",
        ]);
        let before = one(&f.0, "relayforge");
        f.native_git(&["pack-refs", "--all"]);
        let after = one(&f.0, "relayforge");
        assert_eq!(before["head"], after["head"]);
        assert_eq!(after["local_branch_count"], 1);
        let repo = project_root(&f.0, "relayforge").unwrap();
        assert!(head_sha(&repo, "refs/../../outside").is_none());
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
        assert!(out["tracked_clean"].is_null());
        assert!(out["untracked_count"].is_null());
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
    fn configured_clean_filters_never_execute_during_status() {
        let f = Fixture::new();
        f.native_git(&["init", "--initial-branch=main"]);
        fs::write(f.root().join("tracked.txt"), b"same").unwrap();
        fs::write(f.root().join(".gitattributes"), b"*.txt filter=probe\n").unwrap();
        f.native_git(&["add", "."]);
        f.native_git(&[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-m",
            "fixture",
        ]);
        let marker = f.0.join("executed");
        f.native_git(&[
            "config",
            "filter.probe.clean",
            &format!("touch {}; cat", marker.display()),
        ]);
        // Same-size rewrites can make status hash content and invoke a filter.
        fs::write(f.root().join("tracked.txt"), b"same").unwrap();
        let out = one(&f.0, "relayforge");
        assert_eq!(out["status"], "observed");
        assert!(out["tracked_clean"].is_null());
        assert!(!marker.exists());
        assert!(!out.to_string().contains("touch"));
        f.native_git(&["config", "--unset", "filter.probe.clean"]);
        f.native_git(&["config", "remote.origin.promisor", "true"]);
        assert!(one(&f.0, "relayforge")["tracked_clean"].is_null());
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
            metadata_text(&repo.metadata, "HEAD").unwrap().trim(),
            "ref: refs/heads/main"
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
                "GIT_OPTIONAL_LOCKS",
                "GIT_NO_LAZY_FETCH"
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
