//! Private, fixed-scope text exchange on the ThinkPad, NOT arbitrary host I/O.
//! The parent workstation tool enforces opt-in and mutation audit. No file is
//! executable or mounted into the offline sandbox or Git checkout.
use serde_json::{json, Value};
use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const MAX_BYTES: usize = 48 * 1024;
const MAX_FILES: usize = 64;
const NOFOLLOW: i32 = 0x20000; // O_NOFOLLOW (Linux)

fn owner() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| "user unavailable")?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|s| s.split_ascii_whitespace().next())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "user unavailable".into())
}

fn private_dir_meta(path: &Path, uid: u32) -> Result<(), String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "private state unavailable")?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != uid
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("insecure private state".into());
    }
    Ok(())
}

fn directory(home: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    let uid = owner()?;
    let parent = home.join(".local/state/relayforge");
    private_dir_meta(&parent, uid)?;
    let dir = parent.join("chat-transfer");
    if fs::symlink_metadata(&dir).is_err() {
        if !create {
            return Ok(None);
        }
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|_| "transfer directory unavailable")?;
    }
    private_dir_meta(&dir, uid)?;
    Ok(Some(dir))
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && [".txt", ".md", ".json", ".log", ".rs", ".py", ".toml", ".sh"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

fn bounded_inventory(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    for entry in fs::read_dir(dir).map_err(|_| "transfer directory unavailable")? {
        let entry = entry.map_err(|_| "transfer directory unavailable")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "invalid transfer filename")?;
        if !name_ok(&name) {
            return Err("unexpected transfer directory entry".into());
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(|_| "transfer file unavailable")?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.uid() != owner()?
            || meta.permissions().mode() & 0o077 != 0
            || meta.len() > MAX_BYTES as u64
        {
            return Err("insecure transfer file".into());
        }
        names.push(name);
        if names.len() > MAX_FILES {
            return Err("transfer file count exceeded".into());
        }
    }
    names.sort();
    Ok(names)
}

fn get_name<'a>(params: &'a serde_json::Map<String, Value>) -> Result<&'a str, String> {
    let name = params
        .get("path")
        .and_then(Value::as_str)
        .ok_or("filename required")?;
    if !name_ok(name) {
        return Err("transfer filename denied".into());
    }
    Ok(name)
}

pub fn execute(home: &Path, args: &Value) -> Result<String, String> {
    let params = args.as_object().ok_or("expected object")?;
    let op = params
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("operation required")?;
    match op {
        "workspace.list" if params.len() == 1 => {
            let Some(dir) = directory(home, false)? else {
                return Ok(json!({"files":[],"limit":MAX_FILES}).to_string());
            };
            Ok(json!({"files":bounded_inventory(&dir)?,"limit":MAX_FILES}).to_string())
        }
        "workspace.read" if params.len() == 2 => {
            let name = get_name(params)?;
            let dir = directory(home, false)?.ok_or("transfer directory unavailable")?;
            if !bounded_inventory(&dir)?.iter().any(|f| f == name) {
                return Err("transfer file unavailable".into());
            }
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(NOFOLLOW)
                .open(dir.join(name))
                .map_err(|_| "transfer file unavailable")?;
            let mut bytes = Vec::new();
            file.take((MAX_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| "transfer file unreadable")?;
            if bytes.len() > MAX_BYTES {
                return Err("transfer file too large".into());
            }
            let utf8 = String::from_utf8(bytes).map_err(|_| "non-utf8 transfer file")?;
            Ok(json!({"path":name,"utf8_text":utf8,"byte_length":utf8.len()}).to_string())
        }
        "workspace.put" if params.len() == 3 => {
            let name = get_name(params)?;
            let text = params
                .get("content")
                .and_then(Value::as_str)
                .ok_or("UTF-8 content required")?;
            if text.len() > MAX_BYTES {
                return Err("transfer file too large".into());
            }
            let dir = directory(home, true)?.ok_or("transfer directory unavailable")?;
            if bounded_inventory(&dir)?.len() >= MAX_FILES {
                return Err("transfer file count exceeded".into());
            }
            // Never overwrite another item: creates are atomic and unique.
            let path = dir.join(name);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(NOFOLLOW)
                .open(&path)
                .map_err(|_| "transfer filename already exists or is denied")?;
            if file
                .write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .is_err()
            {
                let _ = fs::remove_file(path);
                return Err("transfer write failed".into());
            }
            Ok(json!({"created":true,"path":name,"byte_length":text.len()}).to_string())
        }
        "workspace.remove" if params.len() == 2 => {
            let name = get_name(params)?;
            let dir = directory(home, false)?.ok_or("transfer directory unavailable")?;
            if !bounded_inventory(&dir)?.iter().any(|f| f == name) {
                return Err("transfer file unavailable".into());
            }
            fs::remove_file(dir.join(name)).map_err(|_| "transfer removal failed")?;
            Ok(json!({"removed":true,"path":name}).to_string())
        }
        _ => Err("operation or parameters denied".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_path_traversal_and_hidden_files() {
        for name in [
            ".env",
            "../private.md",
            "dir/file.rs",
            "/etc/passwd",
            "secret.key",
            "bad\\name.rs",
            "x y.txt",
            "file.txt/..",
            "",
        ] {
            assert!(!name_ok(name), "{name}");
        }
        for name in ["note.md", "report.json", "build.log", "snippet.rs"] {
            assert!(name_ok(name), "{name}");
        }
    }
    #[test]
    fn private_transfer_round_trip_and_symlink_denial() {
        let suffix = format!(
            "relayforge-transfer-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let home = std::env::temp_dir().join(suffix);
        let state = home.join(".local/state/relayforge");
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();

        let create = json!({"operation":"workspace.put","path":"sample.md","content":"hello"});
        let receipt: Value = serde_json::from_str(&execute(&home, &create).unwrap()).unwrap();
        assert_eq!(receipt["created"], true);
        assert!(execute(&home, &create).is_err()); // no overwrite

        let list: Value = serde_json::from_str(
            &execute(&home, &json!({"operation":"workspace.list"})).unwrap()
        ).unwrap();
        assert_eq!(list["files"], json!(["sample.md"]));
        let read: Value = serde_json::from_str(
            &execute(&home, &json!({"operation":"workspace.read","path":"sample.md"})).unwrap()
        ).unwrap();
        assert_eq!(read["utf8_text"], "hello");

        let transfer = state.join("chat-transfer");
        fs::write(home.join("outside.md"), "secret").unwrap();
        std::os::unix::fs::symlink(home.join("outside.md"), transfer.join("private.md")).unwrap();
        assert!(execute(&home, &json!({"operation":"workspace.list"})).is_err());
        assert!(execute(&home, &json!({"operation":"workspace.read","path":"private.md"})).is_err());
        fs::remove_file(transfer.join("private.md")).unwrap();
        assert!(execute(&home, &json!({"operation":"workspace.remove","path":"sample.md"})).is_ok());
        assert!(execute(&home, &json!({"operation":"workspace.read","path":"sample.md"})).is_err());
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn rejects_unrecognized_arguments_and_operations() {
        let h = Path::new("/definitely-not-existing");
        assert!(execute(h, &json!({"operation":"workspace.exec"})).is_err());
        assert!(execute(
            h,
            &json!({"operation":"workspace.put","path":"foo.rs",
            "content":"x","shell":true})
        )
        .is_err());
        assert!(execute(
            h,
            &json!({"operation":"workspace.read","path":"../../.ssh/key"})
        )
        .is_err());
    }
}
