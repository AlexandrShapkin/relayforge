//! Privacy-filtered read-only inventory of retired-node references.
//! Scans ONLY fixed local config/source roots; returns no file contents.
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    fs::{self, File},
    io::Read,
    os::unix::fs::MetadataExt,
    path::Path,
};

const MAX_FILES: usize = 256;
const MAX_BYTES: u64 = 128 * 1024;
const MAX_FINDINGS: usize = 30;
const MAX_DEPTH: usize = 5;

fn real_uid() -> Result<u32, String> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| "uid unavailable")?;
    status
        .lines()
        .find_map(|s| s.strip_prefix("Uid:"))
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .ok_or("uid unavailable".to_owned())
}

fn safe_file(path: &Path, uid: u32) -> Option<u64> {
    let m = fs::symlink_metadata(path).ok()?;
    if !m.is_file() || m.file_type().is_symlink() || m.uid() != uid || m.len() > MAX_BYTES {
        return None;
    }
    Some(m.len())
}

fn allowed_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    !name.starts_with('.')
        && name.len() <= 96
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn source_ext(path: &Path) -> bool {
    [
        ".rs", ".py", ".toml", ".yaml", ".yml", ".json", ".service", ".timer", ".socket", ".conf",
        ".sh", ".md",
    ]
    .iter()
    .any(|s| path.to_string_lossy().ends_with(s))
}

fn count_reference(path: &Path) -> Option<usize> {
    let mut file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > MAX_BYTES as usize {
        return None;
    }
    let content = String::from_utf8(bytes).ok()?;
    Some(content.to_ascii_lowercase().match_indices("ru1").count())
}

fn add_finding(out: &mut Vec<Value>, category: &str, file: &str, count: usize) {
    if count > 0 && out.len() < MAX_FINDINGS {
        out.push(json!({"category":category,"file":file,"references":count}));
    }
}

fn examine(
    path: &Path,
    category: &str,
    name: &str,
    uid: u32,
    checked: &mut usize,
    incomplete: &mut bool,
    out: &mut Vec<Value>,
) {
    if *checked >= MAX_FILES || out.len() >= MAX_FINDINGS {
        *incomplete = true;
        return;
    }
    if safe_file(path, uid).is_none() {
        if path.exists() {
            *incomplete = true;
        }
        return;
    }
    *checked += 1;
    match count_reference(path) {
        Some(count) => add_finding(out, category, name, count),
        None => *incomplete = true,
    }
}

fn scan_tree(
    root: &Path,
    category: &str,
    uid: u32,
    checked: &mut usize,
    incomplete: &mut bool,
    out: &mut Vec<Value>,
) {
    if !root.is_dir() {
        return;
    }
    let Ok(root_meta) = fs::symlink_metadata(root) else {
        return;
    };
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() || root_meta.uid() != uid {
        *incomplete = true;
        return;
    }
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = fs::read_dir(&dir) else {
            *incomplete = true;
            continue;
        };
        for entry in entries {
            if *checked >= MAX_FILES || out.len() >= MAX_FINDINGS {
                *incomplete = true;
                return;
            }
            let Ok(entry) = entry else {
                *incomplete = true;
                continue;
            };
            let path = entry.path();
            if !allowed_name(&path) {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                *incomplete = true;
                continue;
            }
            if meta.uid() != uid {
                continue;
            }
            if meta.is_dir() {
                if depth < MAX_DEPTH {
                    queue.push_back((path, depth + 1));
                } else {
                    *incomplete = true;
                }
            } else if meta.is_file() && source_ext(&path) {
                let relative = path
                    .strip_prefix(root)
                    .ok()
                    .and_then(|v| v.to_str())
                    .unwrap_or("");
                examine(&path, category, relative, uid, checked, incomplete, out);
            }
        }
    }
}

pub fn snapshot(home: &Path) -> Result<String, String> {
    let uid = real_uid()?;
    let mut matches = Vec::new();
    let mut checked = 0;
    let mut incomplete = false;
    for (category, path) in [
        ("ssh", home.join(".ssh/config")),
        ("ssh", home.join(".ssh/known_hosts")),
    ] {
        examine(
            &path,
            category,
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown"),
            uid,
            &mut checked,
            &mut incomplete,
            &mut matches,
        );
    }
    scan_tree(
        &home.join(".config/systemd/user"),
        "user-systemd",
        uid,
        &mut checked,
        &mut incomplete,
        &mut matches,
    );
    scan_tree(
        &home.join("Projects/assistant-hub/src"),
        "assistant-hub-src",
        uid,
        &mut checked,
        &mut incomplete,
        &mut matches,
    );
    scan_tree(
        &home.join("Projects/assistant-hub/deploy"),
        "assistant-hub-deploy",
        uid,
        &mut checked,
        &mut incomplete,
        &mut matches,
    );
    scan_tree(
        &home.join("Projects/assistant-hub/scripts"),
        "assistant-hub-scripts",
        uid,
        &mut checked,
        &mut incomplete,
        &mut matches,
    );
    Ok(json!({
        "retired_host":"ru1","checked_files":checked,"incomplete":incomplete,
        "matches":matches,"max_findings":MAX_FINDINGS,
        "external_checks_required":[
            "DNS and hosting provider", "SSH/config on ru0 and srv0",
            "third-party monitors", "external scheduled jobs", "cloud connectors"
        ]
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_are_counted_without_content_disclosure() {
        let root = std::env::temp_dir().join(format!("relayforge-refaudit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let uid = real_uid().unwrap();
        fs::write(root.join("config.sh"), b"ssh ru1\necho ru1\nAPI_KEY=SECRET").unwrap();
        fs::write(root.join(".secrets"), b"ru1").unwrap();
        let mut checked = 0;
        let mut incomplete = false;
        let mut out = Vec::new();
        scan_tree(&root, "test", uid, &mut checked, &mut incomplete, &mut out);
        assert_eq!(checked, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["references"], 2);
        assert!(!out.to_string().contains("SECRET"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn filenames_and_symlinks_are_restricted() {
        assert!(!allowed_name(Path::new("../private key.json")));
        assert!(allowed_name(Path::new("foo.service")));
        assert!(!source_ext(Path::new("secret.key")));
        assert!(source_ext(Path::new("script.py")));
    }
}
