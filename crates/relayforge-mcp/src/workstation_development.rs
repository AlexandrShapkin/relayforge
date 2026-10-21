//! Immutable task proposals, local expiring authority and one offline profile.
//! No checkout writes, credentials, network, arbitrary commands or grant writer.
use crate::workstation_jobs as jobs;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

const NOFOLLOW: i32 = 0x20000;
const DIRECTORY: i32 = 0x10000;
const MAX_PROPOSAL: usize = 24 * 1024;
const PROFILE: &str = "python-stdlib-v1";
const OPERATIONS: [&str; 4] = ["source.edit", "build", "test", "diff"];

fn keys(value: &Value, names: &[&str]) -> Result<(), String> {
    let map = value.as_object().ok_or("object required")?;
    if map.len() != names.len() || !names.iter().all(|name| map.contains_key(*name)) {
        return Err("unexpected development fields".into());
    }
    Ok(())
}

fn uid() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| "identity unavailable")?;
    status
        .lines()
        .find_map(|s| s.strip_prefix("Uid:"))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "identity unavailable".into())
}

// Pin every ancestor, including the configured HOME, without following links.
fn directory(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("absolute development root required".into());
    }
    let mut parent = File::open("/").map_err(|_| "root unavailable")?;
    for component in path.components().skip(1) {
        let Component::Normal(name) = component else {
            return Err("path denied".into());
        };
        let child = OpenOptions::new()
            .read(true)
            .custom_flags(DIRECTORY | NOFOLLOW)
            .open(pinned(&parent, name))
            .map_err(|_| "development directory unavailable")?;
        parent = child;
    }
    let meta = parent
        .metadata()
        .map_err(|_| "directory metadata unavailable")?;
    if meta.uid() != uid()? || meta.permissions().mode() & 0o022 != 0 {
        return Err("unsafe development directory".into());
    }
    Ok(parent)
}

fn descriptor(file: &File) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        file.as_raw_fd()
    ))
}

fn pinned(dir: &File, name: impl AsRef<Path>) -> PathBuf {
    descriptor(dir).join(name)
}

fn record(dir: &File, name: &str, limit: usize) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | 0x800)
        .open(pinned(dir, name))
        .map_err(|_| "development record unavailable")?;
    let meta = file.metadata().map_err(|_| "record metadata unavailable")?;
    if !meta.is_file()
        || meta.uid() != uid()?
        || meta.nlink() != 1
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() > limit as u64
    {
        return Err("unsafe development record".into());
    }
    Ok(file)
}

fn read(dir: &File, name: &str, limit: usize) -> Result<String, String> {
    let file = record(dir, name, limit)?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "record unreadable")?;
    if bytes.len() > limit {
        return Err("development record too large".into());
    }
    String::from_utf8(bytes).map_err(|_| "record is not UTF-8".into())
}

fn write(dir: &File, name: &str, text: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(pinned(dir, name))
        .map_err(|_| "development record exists or unavailable")?;
    file.write_all(text.as_bytes())
        .and_then(|_| file.sync_all())
        .and_then(|_| dir.sync_all())
        .map_err(|_| "development record not durable".into())
}

fn paths(proposal: &Value) -> Result<Vec<String>, String> {
    keys(
        proposal,
        &[
            "schema_version",
            "repository",
            "base_revision",
            "profile",
            "edits",
        ],
    )?;
    let revision = proposal["base_revision"]
        .as_str()
        .ok_or("base revision required")?;
    if proposal["schema_version"].as_u64() != Some(1)
        || proposal["repository"] != "relayforge"
        || proposal["profile"] != PROFILE
        || revision.len() != 40
        || !revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("repository, revision or profile denied".into());
    }
    let edits = proposal["edits"].as_array().ok_or("edits required")?;
    if !(1..=4).contains(&edits.len()) || proposal.to_string().len() > MAX_PROPOSAL {
        return Err("development input budget exceeded".into());
    }
    let mut paths = BTreeSet::new();
    for edit in edits {
        keys(edit, &["path", "before", "after"])?;
        let path = edit["path"].as_str().ok_or("source path required")?;
        if !path.starts_with("scripts/")
            || !path.ends_with(".py")
            || path.len() > 160
            || !path.split('/').all(|p| {
                !p.is_empty()
                    && !p.starts_with('.')
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
            || !paths.insert(path.to_string())
        {
            return Err("development path denied or repeated".into());
        }
        for key in ["before", "after"] {
            let text = edit[key].as_str().ok_or("source text required")?;
            if text.len() > 8192
                || text.contains('\0')
                || (!text.is_empty() && !text.ends_with('\n'))
            {
                return Err("development source budget or encoding invalid".into());
            }
        }
    }
    Ok(paths.into_iter().collect())
}

// Git only reads pinned local objects. No pager/hooks/filters/lazy network fetch.
fn git(repo: &Path, arguments: &[&str]) -> Result<String, String> {
    let root = directory(repo)?;
    let gitdir = OpenOptions::new()
        .read(true)
        .custom_flags(DIRECTORY | NOFOLLOW)
        .open(pinned(&root, ".git"))
        .map_err(|_| "Git directory unavailable")?;
    let meta = gitdir.metadata().map_err(|_| "Git metadata unavailable")?;
    if meta.uid() != uid()? || meta.permissions().mode() & 0o022 != 0 {
        return Err("unsafe Git directory".into());
    }
    // These redirects are unnecessary for the single fixed checkout contract.
    for name in [
        "commondir",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
        if fs::symlink_metadata(pinned(&gitdir, name)).is_ok() {
            return Err("redirected Git metadata denied".into());
        }
    }
    let location = format!("--git-dir={}", pinned(&gitdir, "").display());
    let mut child = Command::new("/usr/bin/timeout")
        .args([
            "-k",
            "1s",
            "5s",
            "/usr/bin/git",
            "--no-pager",
            "--no-replace-objects",
        ])
        .arg(location)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
        ])
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_LAZY_FETCH", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Git source unavailable")?;
    let out = child.stdout.take().ok_or("Git output unavailable")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        out.take(16385).read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = child.wait().map_err(|_| "Git status unavailable")?;
    let bytes = reader
        .join()
        .map_err(|_| "Git reader unavailable")?
        .map_err(|_| "Git source unreadable")?;
    if !status.success() || bytes.len() > 16384 {
        return Err("Git source unverified".into());
    }
    String::from_utf8(bytes).map_err(|_| "Git source encoding invalid".into())
}

fn base_current(repo: &Path, proposal: &Value) -> Result<(), String> {
    if git(repo, &["rev-parse", "--verify", "HEAD^{commit}"])?.trim()
        != proposal["base_revision"].as_str().ok_or("base missing")?
    {
        return Err("stale development base revision".into());
    }
    Ok(())
}

fn proposal(home: &Path, id: &str) -> Result<(File, Value), String> {
    let dir = directory(&jobs::job_dir(home, id)?)?;
    let value = serde_json::from_str(&read(&dir, "development.json", MAX_PROPOSAL)?)
        .map_err(|_| "invalid development record")?;
    paths(&value)?;
    Ok((dir, value))
}

fn authorized(home: &Path, id: &str, proposal: &Value) -> Result<u64, String> {
    let root = directory(&home.join(".config/relayforge/task-authorizations"))?;
    if root
        .metadata()
        .map_err(|_| "authorization unavailable")?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err("authorization directory must be private".into());
    }
    let grant: Value = serde_json::from_str(&read(&root, &format!("{id}.json"), 4096)?)
        .map_err(|_| "invalid task authorization")?;
    keys(
        &grant,
        &[
            "schema_version",
            "job_id",
            "repository",
            "base_revision",
            "profile",
            "paths",
            "operations",
            "issued_at",
            "expires_at",
        ],
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock unavailable")?
        .as_secs();
    let issued = grant["issued_at"]
        .as_u64()
        .ok_or("authorization issue time missing")?;
    let expires = grant["expires_at"]
        .as_u64()
        .ok_or("authorization expiry missing")?;
    if grant["schema_version"].as_u64() != Some(1)
        || grant["job_id"] != id
        || grant["repository"] != proposal["repository"]
        || grant["base_revision"] != proposal["base_revision"]
        || grant["profile"] != PROFILE
        || grant["paths"] != json!(paths(proposal)?)
        || grant["operations"] != json!(OPERATIONS)
        || issued > now
        || now >= expires
        || expires.saturating_sub(issued) > 3600
        || expires <= issued
    {
        return Err("task authorization absent, mismatched or expired".into());
    }
    Ok(expires)
}

fn profile_script() -> String {
    format!(
        "exec /usr/bin/python3 -I -S - <<'RELAYFORGE_PROFILE'\n{}\nRELAYFORGE_PROFILE\n",
        include_str!("development_profile.py")
    )
}

fn prepare(home: &Path, repo: &Path, value: &Value) -> Result<String, String> {
    paths(value)?;
    base_current(repo, value)?;
    for edit in value["edits"].as_array().ok_or("edits missing")? {
        let spec = format!(
            "{}:{}",
            value["base_revision"].as_str().ok_or("base missing")?,
            edit["path"].as_str().ok_or("path missing")?
        );
        if git(repo, &["cat-file", "blob", &spec])?
            != edit["before"].as_str().ok_or("before missing")?
        {
            return Err("conflicting development source".into());
        }
    }
    base_current(repo, value)?;
    let _state = directory(&home.join(".local/state/relayforge"))?;
    let root = jobs::root(home, true)?.ok_or("job root unavailable")?;
    if jobs::inventory(&root)?.len() >= jobs::MAX_JOBS {
        return Err("job capacity reached".into());
    }
    let id = jobs::new_id()?;
    let path = root.join(&id);
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|_| "development workspace unavailable")?;
    let dir = directory(&path)?;
    write(&dir, "script.sh", &profile_script())?;
    write(&dir, "development.json", &value.to_string())?;
    Ok(
        json!({"job_id":id,"state":"prepared","base_revision":value["base_revision"],
        "profile":PROFILE,"operator_task_authorization_required":true,"checkout_modified":false})
        .to_string(),
    )
}

pub(crate) fn execute(home: &Path, repo: &Path, args: &Value) -> Result<String, String> {
    let operation = args["operation"].as_str().ok_or("operation missing")?;
    if operation == "development.prepare" {
        keys(args, &["operation", "parameters"])?;
        return prepare(home, repo, &args["parameters"]);
    }
    keys(args, &["operation", "task_id"])?;
    let id = args["task_id"].as_str().ok_or("task ID missing")?;
    let (dir, value) = proposal(home, id)?;
    match operation {
        "development.run" => {
            authorized(home, id, &value)?;
            base_current(repo, &value)?;
            // Immutable create_new arbitrates duplicate/conflicting submissions.
            write(&dir, "development.run", "requested\n")?;
            jobs::schedule_worker(home, id, 600)?;
            Ok(
                json!({"job_id":id,"state":"submitted","base_revision":value["base_revision"]})
                    .to_string(),
            )
        }
        "development.inspect" => Ok(json!({"job_id":id,"proposal":value,
            "execution_requested":fs::symlink_metadata(pinned(&dir,"development.run")).is_ok(),
            "authorization_valid":authorized(home,id,&value).is_ok(),
            "result":jobs::job_status(home,id)?})
        .to_string()),
        _ => Err("development operation denied".into()),
    }
}

pub(crate) fn mounts(dir: &Path) -> Result<(Vec<String>, Vec<File>), String> {
    let handle = directory(dir)?;
    let mut args = Vec::new();
    let mut records = Vec::new();
    for (name, limit) in [
        ("development.json", MAX_PROPOSAL),
        ("development.authority.json", 256),
        ("script.sh", 16384),
    ] {
        let file = record(&handle, name, limit)?;
        args.extend([
            "--ro-bind-data".into(),
            file.as_raw_fd().to_string(),
            format!("/job/{name}"),
        ]);
        records.push(file);
    }
    Ok((args, records))
}

pub(crate) fn run_worker(home: &Path, id: &str) -> Result<i32, String> {
    if !crate::workstation_dev::dev_enabled(home) {
        return Err("local development opt-in missing".into());
    }
    let (dir, value) = proposal(home, id)?;
    if read(&dir, "script.sh", 16384)? != profile_script() {
        return Err("development profile mismatch".into());
    }
    if read(&dir, "development.run", 32)? != "requested\n" {
        return Err("development execution not requested".into());
    }
    let expires = authorized(home, id, &value)?;
    base_current(&home.join("Projects/relayforge"), &value)?;
    let job = jobs::job_dir(home, id)?;
    write(
        &dir,
        "development.authority.json",
        &json!({"expires_at":expires}).to_string(),
    )?;
    let result = jobs::sandbox_stage_until(home, &job.join("script.sh"), expires)?;
    jobs::write_private(&job, "stdout.log", &result.stdout)?;
    jobs::write_private(&job, "stderr.log", &result.stderr)?;
    let code = if result.stdout_truncated || result.stderr_truncated {
        1
    } else {
        result.exit_code
    };
    jobs::write_private(
        &job,
        "result.json",
        json!({"state":"finished","exit_code":code,
        "stdout_truncated":result.stdout_truncated,"stderr_truncated":result.stderr_truncated,
        "base_revision":value["base_revision"],"profile":PROFILE,
        "failure_kind":if result.exit_code == 124 {json!("authorization_expired")} else {Value::Null}})
        .to_string()
        .as_bytes(),
    )?;
    Ok(code)
}
