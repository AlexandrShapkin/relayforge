//! Read-only OS metadata and a dedicated, explicitly limited scratch area.
//! Never treat a client-supplied absolute path as a filesystem authority.
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const SANDBOX: &str = "/home/shapkin_as/.local/share/relayforge/pilot-files";
const MAX_READ: usize = 8 * 1024;
const MAX_CREATE: usize = 2 * 1024;
const MAX_FILES: usize = 32;
const OS_ALLOWLIST: &[&str] = &[
    "/etc/hostname",
    "/etc/os-release",
    "/proc/loadavg",
    "/proc/meminfo",
    "/proc/uptime",
];

pub fn valid_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(c))
        && [".txt", ".md", ".json"]
            .iter()
            .any(|extension| name.ends_with(extension))
}

fn sandbox() -> io::Result<&'static Path> {
    let path = Path::new(SANDBOX);
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "scratch directory is not private",
        ));
    }
    Ok(path)
}

pub fn read_file(path: &str) -> io::Result<Value> {
    let actual = if OS_ALLOWLIST.contains(&path) {
        Path::new(path).to_owned()
    } else if valid_name(path) {
        sandbox()?.join(path)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file denied",
        ));
    };
    if !OS_ALLOWLIST.contains(&path) {
        let metadata = fs::symlink_metadata(&actual)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "file denied",
            ));
        }
    }
    let file = File::open(actual)?;
    let mut bytes = Vec::new();
    file.take((MAX_READ + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_READ {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-8 data"))?;
    Ok(json!({"path": path, "content": content}))
}

pub fn list_files() -> io::Result<Value> {
    let dir = sandbox()?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)?.take(MAX_FILES + 1) {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if valid_name(&name) {
            entries.push(name);
        }
    }
    entries.sort();
    if entries.len() > MAX_FILES {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "scratch file quota",
        ));
    }
    Ok(json!({"files":entries,"max_files":MAX_FILES}))
}

pub fn create_file(name: &str, content: &str) -> io::Result<Value> {
    if !valid_name(name) || content.len() > MAX_CREATE {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file denied",
        ));
    }
    let dir = sandbox()?;
    // A small quota and create_new prevent a client from clobbering an
    // existing file (including symlinks) or exhausting the disk.
    let count = fs::read_dir(dir)?.take(MAX_FILES).count();
    if count >= MAX_FILES {
        return Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "scratch file quota",
        ));
    }
    let path = dir.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    Ok(json!({"created":name,"bytes":content.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_names_cannot_escape_private_sandbox() {
        for name in [
            "../secret.txt",
            ".env",
            "a/b.txt",
            "/etc/passwd",
            "--foo",
            "note.sh",
            " spaced.txt",
            "x\\y.md",
            "note.md;id",
        ] {
            assert!(!valid_name(name), "{name}");
        }
        for name in ["test.txt", "2026-report.md", "a_b.json"] {
            assert!(valid_name(name));
        }
    }
    #[test]
    fn only_public_os_files_can_be_read() {
        let os = read_file("/etc/os-release").unwrap();
        assert!(os["content"].as_str().unwrap().contains("NAME="));
        assert!(read_file("/etc/shadow").is_err());
        assert!(read_file("/home/shapkin_as/.ssh/id_ed25519").is_err());
        assert!(read_file("/proc/self/environ").is_err());
    }
}
