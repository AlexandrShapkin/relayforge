//! Owner-selected report roots. No grant writer, shell, or arbitrary host paths.
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_BYTES: usize = 48 * 1024;
const MAX_FILES: usize = 64;
const NOFOLLOW: i32 = 0x20000;
const DIRECTORY: i32 = 0x10000;
const NONBLOCK: i32 = 0x800;
const CONFIG: &str = ".config/relayforge/artifact-roots.json";
const ADDITIONAL: &str = "artifact-approved-roots";

fn uid() -> Result<u32, String> {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("Uid:")
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse().ok())
            })
        })
        .ok_or_else(|| "artifact identity unavailable".into())
}

fn pinned(dir: &File, name: &str) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        dir.as_raw_fd()
    ))
    .join(name)
}

// Every lookup is relative to a pinned directory, never a checked string path.
fn child(dir: &File, name: &str, directory: bool) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | NONBLOCK | if directory { DIRECTORY } else { 0 })
        .open(pinned(dir, name))
        .map_err(|_| "artifact denied")?;
    let meta = file.metadata().map_err(|_| "artifact denied")?;
    if meta.uid() != uid()?
        || meta.mode() & 0o022 != 0
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err("artifact denied".into());
    }
    Ok(file)
}

fn home_dir(home: &Path) -> Result<File, String> {
    if !home.is_absolute() {
        return Err("artifact denied".into());
    }
    let mut dir = File::open("/").map_err(|_| "artifact denied")?;
    for part in home.components().skip(1) {
        let Component::Normal(part) = part else {
            return Err("artifact denied".into());
        };
        // Ancestors locate HOME; they do not authorize a report. In a systemd
        // user mount namespace their owners may be unmapped. Pin each component
        // without following links and reject unsafe permissions, then require
        // the HOME descriptor and every descendant to belong to our exact UID.
        // No unmapped UID is accepted as an owner of an authorization object.
        let next = OpenOptions::new()
            .read(true)
            .custom_flags(NOFOLLOW | DIRECTORY)
            .open(pinned(&dir, part.to_str().ok_or("artifact denied")?))
            .map_err(|_| "artifact denied")?;
        let m = next.metadata().map_err(|_| "artifact denied")?;
        // /tmp is used only by disposable offline fixtures (sticky root-owned).
        if m.mode() & 0o022 != 0 && !(m.uid() == 0 && m.mode() & 0o1000 != 0) {
            return Err("artifact denied".into());
        }
        dir = next;
    }
    let m = dir.metadata().map_err(|_| "artifact denied")?;
    if m.uid() != uid()? || m.mode() & 0o022 != 0 {
        return Err("artifact denied".into());
    }
    Ok(dir)
}

fn text(file: File, limit: usize) -> Result<String, String> {
    if file.metadata().map_err(|_| "artifact denied")?.len() > limit as u64 {
        return Err("artifact too large".into());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "artifact denied")?;
    if bytes.len() > limit {
        return Err("artifact too large".into());
    }
    let value = String::from_utf8(bytes).map_err(|_| "artifact text denied")?;
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err("artifact text denied".into());
    }
    // Defense in depth, not a secret classifier: owners must approve report-only roots.
    let lower = value.to_ascii_lowercase();
    if [
        "-----begin ",
        "authorization: bearer ",
        "access_token",
        "refresh_token",
        "private_key",
        "client_secret",
        "aws_secret_access_key",
        "password=",
        "password:",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        return Err("artifact sensitive content denied".into());
    }
    Ok(value)
}

fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && ![
            "secret",
            "credential",
            "token",
            "password",
            "private",
            "id_rsa",
            "id_ed25519",
            ".env",
            ".pem",
            ".key",
        ]
        .iter()
        .any(|v| s.to_ascii_lowercase().contains(v))
}

fn parts(path: &str) -> Result<Vec<&str>, String> {
    let parts: Vec<_> = path.split('/').collect();
    if path.len() > 192 || parts.len() > 5 || parts.iter().any(|p| !name_ok(p) || *p == "..") {
        return Err("artifact path denied".into());
    }
    Ok(parts)
}

fn report(name: &str) -> bool {
    name_ok(name)
        && [".md", ".txt", ".log", ".json", ".jsonl"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

fn roots(home: &Path) -> Result<serde_json::Map<String, Value>, String> {
    let mut dir = home_dir(home)?;
    for part in [".config", "relayforge"] {
        dir = child(&dir, part, true)?;
    }
    let file = child(&dir, "artifact-roots.json", false)?;
    if file.metadata().map_err(|_| "artifact denied")?.mode() & 0o077 != 0 {
        return Err("artifact authorization denied".into());
    }
    let value: Value =
        serde_json::from_str(&text(file, 4096)?).map_err(|_| "artifact authorization denied")?;
    let obj = value.as_object().ok_or("artifact authorization denied")?;
    if obj.len() != 1 {
        return Err("artifact authorization denied".into());
    }
    let roots = obj
        .get("roots")
        .and_then(Value::as_object)
        .ok_or("artifact authorization denied")?;
    if roots.is_empty() || roots.len() > 8 {
        return Err("artifact authorization denied".into());
    }
    for (id, path) in roots {
        if !name_ok(id) || id.len() > 32 {
            return Err("artifact authorization denied".into());
        }
        let path = Path::new(path.as_str().ok_or("artifact authorization denied")?);
        let relative = path
            .strip_prefix(home)
            .map_err(|_| "artifact root denied")?;
        let s = relative.to_str().ok_or("artifact root denied")?;
        let suffix = s
            .strip_prefix("Projects/relayforge/.build/")
            .or_else(|| s.strip_prefix(".local/state/relayforge/artifacts/"))
            .ok_or("artifact root denied")?;
        if !name_ok(suffix) || suffix.contains('/') {
            return Err("artifact root denied".into());
        }
        // Reject lexical normalization (including repeated separators and dot components).
        if home.join(s).as_os_str() != path.as_os_str() || s.contains("//") || s.contains("/./") {
            return Err("artifact root denied".into());
        }
    }
    let mut all = roots.clone();
    let config_dir = child(
        &child(&home_dir(home)?, ".config", true)?,
        "relayforge",
        true,
    )?;
    let grants_path = home.join(".config/relayforge").join(ADDITIONAL);
    match fs::symlink_metadata(&grants_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("artifact authorization denied".into()),
        Ok(_) => {
            let grants = child(&config_dir, ADDITIONAL, true)?;
            if grants.metadata().map_err(|_| "artifact denied")?.mode() & 0o077 != 0 {
                return Err("artifact authorization denied".into());
            }
            let mut count = 0;
            for entry in fs::read_dir(pinned(&grants, "")).map_err(|_| "artifact denied")? {
                count += 1;
                if count > 8 {
                    return Err("artifact authorization denied".into());
                }
                let name = entry
                    .map_err(|_| "artifact denied")?
                    .file_name()
                    .into_string()
                    .map_err(|_| "artifact denied")?;
                let id = name
                    .strip_suffix(".json")
                    .ok_or("artifact authorization denied")?;
                if !name_ok(id) || id.len() > 32 || all.contains_key(id) {
                    return Err("artifact authorization denied".into());
                }
                let grant = child(&grants, &name, false)?;
                if grant.metadata().map_err(|_| "artifact denied")?.mode() & 0o077 != 0 {
                    return Err("artifact authorization denied".into());
                }
                let value: Value = serde_json::from_str(&text(grant, 4096)?)
                    .map_err(|_| "artifact authorization denied")?;
                let obj = value.as_object().ok_or("artifact authorization denied")?;
                if obj.len() != 1 {
                    return Err("artifact authorization denied".into());
                }
                let folder = obj
                    .get("directory")
                    .and_then(Value::as_str)
                    .ok_or("artifact authorization denied")?;
                if !name_ok(folder) || folder.len() > 96 {
                    return Err("artifact authorization denied".into());
                }
                all.insert(
                    id.to_string(),
                    json!(home
                        .join("Projects/relayforge/.build")
                        .join(folder)
                        .to_str()
                        .ok_or("artifact authorization denied")?),
                );
            }
        }
    }
    if all.is_empty() || all.len() > 8 {
        return Err("artifact authorization denied".into());
    }
    Ok(all)
}

fn config_directory(home: &Path) -> Result<File, String> {
    child(
        &child(&home_dir(home)?, ".config", true)?,
        "relayforge",
        true,
    )
}

fn approved_directory(home: &Path) -> Result<File, String> {
    let parent = config_directory(home)?;
    let path = home.join(".config/relayforge").join(ADDITIONAL);
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(pinned(&parent, ADDITIONAL))
                .map_err(|_| "artifact approval directory unavailable")?;
            parent
                .sync_all()
                .map_err(|_| "artifact approval sync failed")?;
        }
        Err(_) => return Err("artifact approval directory unavailable".into()),
        Ok(_) => {}
    }
    let dir = child(&parent, ADDITIONAL, true)?;
    if dir.metadata().map_err(|_| "artifact denied")?.mode() & 0o077 != 0 {
        return Err("artifact authorization denied".into());
    }
    Ok(dir)
}

// Linux advisory lock serializes approval commits across HTTP and tunnel processes.
// Lock file persists to keep a stable inode; a process crash releases the kernel lock.
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

fn approval_lock(parent: &File) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(pinned(parent, ".artifact-root-approval.lock"))
        .map_err(|_| "artifact approval lock unavailable")?;
    let metadata = file.metadata().map_err(|_| "artifact approval lock unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != uid()?
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("artifact approval lock unsafe".into());
    }
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        return Err("artifact approval busy".into());
    }
    Ok(file)
}

// Called only by the existing one-time, physical-owner-approved change executor.
pub(crate) fn approve_root(home: &Path, id: &str, folder: &str) -> Result<String, String> {
    if !name_ok(id) || id.len() > 32 || !name_ok(folder) || folder.len() > 96 {
        return Err("artifact root request denied".into());
    }
    let config_dir = config_directory(home)?;
    let _lock = approval_lock(&config_dir)?;
    let configured = roots(home)?;
    if configured.contains_key(id) || configured.len() >= 8 {
        return Err("artifact root collision or capacity reached".into());
    }
    let mut dir = home_dir(home)?;
    for name in ["Projects", "relayforge", ".build", folder] {
        dir = child(&dir, name, true)?;
    }
    // A report-only directory is required; no generic project/HOME authorization.
    text(child(&dir, "AUTHORIZATION.md", false)?, MAX_BYTES)?;
    let grants = approved_directory(home)?;
    let name = format!("{id}.json");
    match fs::symlink_metadata(pinned(&grants, &name)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err("artifact root already approved or unavailable".into()),
    }
    // Stage complete, fsynced bytes *outside* the active grant directory.
    // Interrupted writes cannot poison unrelated artifact reads.
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "artifact approval clock unavailable")?.as_nanos();
    let temporary = format!(".artifact-root-stage-{id}-{}-{stamp}", std::process::id());
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW)
        .open(pinned(&config_dir, &temporary))
        .map_err(|_| "artifact approval staging unavailable")?;
    let data = json!({"directory":folder}).to_string();
    file.write_all(data.as_bytes())
        .and_then(|_| file.sync_all())
        .and_then(|_| config_dir.sync_all())
        .map_err(|_| "artifact approval staging not durable")?;
    fs::rename(pinned(&config_dir, &temporary), pinned(&grants, &name))
        .map_err(|_| "artifact approval publication failed")?;
    grants.sync_all().map_err(|_| "artifact approval sync failed")?;
    config_dir.sync_all().map_err(|_| "artifact approval sync failed")?;
    Ok(json!({"status":"approved","root":id,"read_only":true}).to_string())
}

pub(crate) fn revoke_root(home: &Path, id: &str) -> Result<String, String> {
    if !name_ok(id) || id.len() > 32 {
        return Err("artifact root request denied".into());
    }
    let config_dir = config_directory(home)?;
    let _lock = approval_lock(&config_dir)?;
    let grants = approved_directory(home)?;
    let name = format!("{id}.json");
    let file = child(&grants, &name, false)?;
    if file.metadata().map_err(|_| "artifact denied")?.mode() & 0o077 != 0 {
        return Err("artifact authorization denied".into());
    }
    fs::remove_file(pinned(&grants, &name)).map_err(|_| "artifact revocation failed")?;
    grants
        .sync_all()
        .map_err(|_| "artifact revocation sync failed")?;
    Ok(json!({"status":"revoked","root":id}).to_string())
}

pub fn discovery(home: &Path) -> Value {
    json!({"configured": roots(home).is_ok(), "read_only":true,
        "max_bytes":MAX_BYTES,"max_entries":MAX_FILES,"max_roots":8,
        "authorization_file":CONFIG})
}

pub fn execute(home: &Path, args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("artifact parameters denied")?;
    let op = obj
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("artifact parameters denied")?;
    if !matches!(op, "artifact.list" | "artifact.read")
        || obj.len() != 2
        || !obj.contains_key("path")
    {
        return Err("artifact parameters denied".into());
    }
    let path = obj["path"].as_str().ok_or("artifact path denied")?;
    let components = parts(path)?;
    let roots = roots(home)?;
    let root = roots
        .get(components[0])
        .and_then(Value::as_str)
        .ok_or("artifact root denied")?;
    let relative = Path::new(root)
        .strip_prefix(home)
        .map_err(|_| "artifact root denied")?;
    let mut dir = home_dir(home)?;
    for part in relative.components() {
        let Component::Normal(part) = part else {
            return Err("artifact root denied".into());
        };
        dir = child(&dir, part.to_str().ok_or("artifact root denied")?, true)?;
    }
    let rest = &components[1..];
    let directories = if op == "artifact.read" {
        if rest.is_empty() || !report(rest[rest.len() - 1]) {
            return Err("artifact path denied".into());
        }
        &rest[..rest.len() - 1]
    } else {
        rest
    };
    for part in directories {
        dir = child(&dir, part, true)?;
    }
    if op == "artifact.read" {
        let value = text(child(&dir, rest[rest.len() - 1], false)?, MAX_BYTES)?;
        return Ok(json!({"path":path,"utf8_text":value,"byte_length":value.len()}).to_string());
    }
    let mut files = Vec::new();
    let descriptor = pinned(&dir, "");
    for (count, entry) in fs::read_dir(descriptor)
        .map_err(|_| "artifact denied")?
        .enumerate()
    {
        if count >= MAX_FILES {
            return Err("artifact list too large".into());
        }
        let name = entry
            .map_err(|_| "artifact denied")?
            .file_name()
            .into_string()
            .map_err(|_| "artifact denied")?;
        // Never disclose rejected names or follow directory entries through their paths.
        if report(&name) {
            text(child(&dir, &name, false)?, MAX_BYTES)?;
            files.push(name);
        }
    }
    files.sort();
    Ok(json!({"path":path,"files":files,"limit":MAX_FILES}).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    struct Fixture {
        home: PathBuf,
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let home = std::env::temp_dir().join(format!(
                "artifact-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let root = home.join("Projects/relayforge/.build/activation");
            fs::create_dir_all(&root).unwrap();
            fs::create_dir_all(home.join(".config/relayforge")).unwrap();
            let f = Self { home, root };
            f.config(json!({"roots":{"activation":f.root}}));
            fs::write(f.root.join("AUTHORIZATION.md"), "Approved report\n").unwrap();
            f
        }
        fn config(&self, value: Value) {
            let p = self.home.join(CONFIG);
            fs::write(&p, value.to_string()).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fn call(&self, op: &str, path: &str) -> Result<String, String> {
            execute(&self.home, &json!({"operation":op,"path":path}))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.home).unwrap();
        }
    }

    #[test]
    fn home_boundary_is_owned_nonwritable_and_not_a_symlink() {
        let f = Fixture::new();
        assert!(home_dir(&f.home).is_ok());
        fs::set_permissions(&f.home, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(home_dir(&f.home).is_err());
        fs::set_permissions(&f.home, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = f.home.join("alias");
        symlink(&f.home, &alias).unwrap();
        assert!(home_dir(&alias).is_err());
        // A pinned owner-held HOME remains valid after an ancestor name changes;
        // authority is conferred by HOME/config ownership, never ancestor UIDs.
        let pinned = home_dir(&f.home).unwrap();
        assert_eq!(pinned.metadata().unwrap().uid(), uid().unwrap());
    }

    #[test]
    fn approved_reads_and_default_deny() {
        let f = Fixture::new();
        assert!(f
            .call("artifact.read", "activation/AUTHORIZATION.md")
            .unwrap()
            .contains("Approved report"));
        assert!(f
            .call("artifact.list", "activation")
            .unwrap()
            .contains("AUTHORIZATION.md"));
        assert!(discovery(&f.home)["configured"].as_bool().unwrap());
        fs::remove_file(f.home.join(CONFIG)).unwrap();
        assert!(f
            .call("artifact.read", "activation/AUTHORIZATION.md")
            .is_err());
        assert_eq!(discovery(&f.home)["configured"], false);
    }

    #[test]
    fn paths_secrets_and_roots_fail_closed() {
        let f = Fixture::new();
        for p in [
            "/activation/AUTHORIZATION.md",
            "activation/../AUTHORIZATION.md",
            "activation//AUTHORIZATION.md",
            "activation/./AUTHORIZATION.md",
            "activation/.env",
            "activation/secret.md",
            "activation/id_rsa.txt",
            "activation/key.pem",
            "activation/a.sh",
            "unknown/AUTHORIZATION.md",
            "activation\\AUTHORIZATION.md",
        ] {
            assert!(f.call("artifact.read", p).is_err(), "{p}");
        }
        assert!(execute(
            &f.home,
            &json!({"operation":"artifact.list","path":"activation","parameters":{}})
        )
        .is_err());
        for path in [
            f.home.clone(),
            f.home.join(".ssh"),
            f.home.join("Projects/relayforge"),
            f.home.join("Projects/relayforge/.build/activation/.."),
            PathBuf::from("/etc"),
        ] {
            f.config(json!({"roots":{"activation":path}}));
            assert!(f.call("artifact.list", "activation").is_err());
        }
    }

    #[test]
    fn symlinks_hardlinks_special_files_and_modes_denied() {
        let f = Fixture::new();
        let p = f.root.join("report.md");
        symlink("AUTHORIZATION.md", &p).unwrap();
        assert!(f.call("artifact.read", "activation/report.md").is_err());
        fs::remove_file(&p).unwrap();
        fs::hard_link(f.root.join("AUTHORIZATION.md"), &p).unwrap();
        assert!(f.call("artifact.read", "activation/report.md").is_err());
        fs::remove_file(&p).unwrap();
        fs::create_dir(&p).unwrap();
        assert!(f.call("artifact.read", "activation/report.md").is_err());
        fs::remove_dir(&p).unwrap();
        std::os::unix::net::UnixListener::bind(&p).unwrap();
        assert!(f.call("artifact.read", "activation/report.md").is_err());
        fs::remove_file(&p).unwrap();
        fs::write(&p, "report").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(f.call("artifact.read", "activation/report.md").is_err());
        fs::set_permissions(f.home.join(CONFIG), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.call("artifact.list", "activation").is_err());
    }

    #[test]
    fn size_binary_sensitive_content_and_list_caps() {
        let f = Fixture::new();
        let p = f.root.join("report.md");
        for bytes in [
            vec![b'a'; MAX_BYTES + 1],
            vec![0xff],
            b"text\0binary".to_vec(),
            b"-----BEGIN OPENSSH PRIVATE KEY-----".to_vec(),
            b"access_token: hidden".to_vec(),
        ] {
            fs::write(&p, bytes).unwrap();
            assert!(f.call("artifact.read", "activation/report.md").is_err());
            assert!(f.call("artifact.list", "activation").is_err());
        }
        fs::write(&p, "a".repeat(MAX_BYTES)).unwrap();
        assert!(f.call("artifact.read", "activation/report.md").is_ok());
        for i in 0..MAX_FILES {
            fs::write(f.root.join(format!("receipt-{i}.txt")), "ok").unwrap();
        }
        assert_eq!(
            f.call("artifact.list", "activation").unwrap_err(),
            "artifact list too large"
        );
    }

    #[test]
    fn operation_jsonl_receipts_keep_report_restrictions() {
        let f = Fixture::new();
        let name = "operation-1792634926759214000.jsonl";
        let path = format!("activation/{name}");
        let receipt = "{\"time\":1792634926.759214,\"event\":\"started activate\"}\n{\"time\":1792634927.0,\"event\":\"candidate staged and verified\"}\n";
        fs::write(f.root.join(name), receipt).unwrap();
        let read: Value = serde_json::from_str(&f.call("artifact.read", &path).unwrap()).unwrap();
        assert_eq!(read["utf8_text"], receipt);
        assert_eq!(read["byte_length"], receipt.len());
        assert!(f
            .call("artifact.list", "activation")
            .unwrap()
            .contains(name));
        for bytes in [
            b"{\"event\":\"access_token: hidden\"}\n".to_vec(),
            b"{\"event\":\"-----BEGIN OPENSSH PRIVATE KEY-----\"}\n".to_vec(),
            b"{\"event\":\"bad\x00text\"}\n".to_vec(),
            vec![0xff],
            vec![b'a'; MAX_BYTES + 1],
        ] {
            fs::write(f.root.join(name), bytes).unwrap();
            assert!(f.call("artifact.read", &path).is_err());
            assert!(f.call("artifact.list", "activation").is_err());
        }
    }

    #[test]
    fn directory_descriptors_survive_replacement_and_refuse_symlink_swap() {
        let f = Fixture::new();
        let pinned_root = child(&home_dir(&f.home).unwrap(), "Projects", true).unwrap();
        fs::rename(f.home.join("Projects"), f.home.join("saved")).unwrap();
        let outside = f.home.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("stolen.md"), "must not escape").unwrap();
        symlink(&outside, f.home.join("Projects")).unwrap();
        assert!(f
            .call("artifact.read", "activation/AUTHORIZATION.md")
            .is_err());
        assert!(child(&pinned_root, "stolen.md", false).is_err());
        // File lookup itself never follows a swapped link, even within an approved root.
        let root = f.home.join("saved/relayforge/.build/activation");
        let parent = home_dir(&root).unwrap();
        fs::rename(root.join("AUTHORIZATION.md"), root.join("saved.md")).unwrap();
        symlink(outside.join("stolen.md"), root.join("AUTHORIZATION.md")).unwrap();
        assert!(child(&parent, "AUTHORIZATION.md", false).is_err());
        assert!(text(child(&parent, "saved.md", false).unwrap(), MAX_BYTES)
            .unwrap()
            .contains("Approved"));
    }
    #[test]
    fn pinned_file_survives_swap_and_nested_reads_are_scoped() {
        let f = Fixture::new();
        fs::create_dir(f.root.join("receipts")).unwrap();
        fs::write(f.root.join("receipts/test.json"), "{\"passed\":true}").unwrap();
        assert!(f
            .call("artifact.read", "activation/receipts/test.json")
            .is_ok());
        let dir = home_dir(&f.root).unwrap();
        let file = child(&dir, "AUTHORIZATION.md", false).unwrap();
        fs::rename(f.root.join("AUTHORIZATION.md"), f.root.join("original.md")).unwrap();
        symlink("/etc/passwd", f.root.join("AUTHORIZATION.md")).unwrap();
        assert_eq!(text(file, MAX_BYTES).unwrap(), "Approved report\n");
        assert!(child(&dir, "AUTHORIZATION.md", false).is_err());
        fs::set_permissions(f.root.join("receipts"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(f
            .call("artifact.read", "activation/receipts/test.json")
            .is_err());
    }

    #[test]
    fn approved_root_is_separate_from_pinned_configuration_and_revocable() {
        let f = Fixture::new();
        let folder = f.home.join("Projects/relayforge/.build/issue77");
        fs::create_dir(&folder).unwrap();
        fs::write(folder.join("AUTHORIZATION.md"), "Owner-reviewed handoff\\n").unwrap();
        let config = f.home.join(CONFIG);
        let before = fs::read(&config).unwrap();
        assert!(f.call("artifact.read", "issue77/AUTHORIZATION.md").is_err());
        let config_dir = config_directory(&f.home).unwrap();
        let lock = approval_lock(&config_dir).unwrap();
        assert!(approve_root(&f.home, "issue77", "issue77").is_err());
        drop(lock);
        fs::write(f.home.join(".config/relayforge/.artifact-root-stage-interrupted"),
            "{incomplete").unwrap();
        assert!(f.call("artifact.list", "activation").is_ok());
        approve_root(&f.home, "issue77", "issue77").unwrap();
        assert_eq!(fs::read(&config).unwrap(), before);
        assert!(f.call("artifact.read", "issue77/AUTHORIZATION.md").is_ok());
        assert!(f.call("artifact.list", "issue77").is_ok());
        assert!(approve_root(&f.home, "issue77", "issue77").is_err());
        assert!(approve_root(&f.home, "invalid/alias", "issue77").is_err());
        assert!(approve_root(&f.home, "another", "../issue77").is_err());
        revoke_root(&f.home, "issue77").unwrap();
        assert_eq!(fs::read(&config).unwrap(), before);
        assert!(f.call("artifact.read", "issue77/AUTHORIZATION.md").is_err());
        assert!(revoke_root(&f.home, "issue77").is_err());
    }

    #[test]
    fn unsafe_additional_grants_fail_closed() {
        let f = Fixture::new();
        let config = f.home.join(".config/relayforge");
        fs::create_dir(config.join(ADDITIONAL)).unwrap();
        fs::write(config.join(ADDITIONAL).join("unexpected.txt"), "{}").unwrap();
        assert!(f.call("artifact.list", "activation").is_err());
        fs::remove_file(config.join(ADDITIONAL).join("unexpected.txt")).unwrap();
        fs::remove_dir(config.join(ADDITIONAL)).unwrap();
        symlink("/tmp", config.join(ADDITIONAL)).unwrap();
        assert!(f.call("artifact.list", "activation").is_err());
    }

    #[test]
    fn configuration_symlink_and_ancestor_swap_are_denied() {
        let f = Fixture::new();
        let config = f.home.join(CONFIG);
        let saved = f.home.join("saved.json");
        fs::rename(&config, &saved).unwrap();
        symlink(&saved, &config).unwrap();
        assert!(f.call("artifact.list", "activation").is_err());
        fs::remove_file(&config).unwrap();
        fs::rename(&saved, &config).unwrap();
        fs::rename(f.home.join(".config"), f.home.join("config-saved")).unwrap();
        symlink(f.home.join("config-saved"), f.home.join(".config")).unwrap();
        assert!(f.call("artifact.list", "activation").is_err());
    }
}
