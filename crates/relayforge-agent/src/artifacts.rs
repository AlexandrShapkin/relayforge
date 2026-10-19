//! Sensitive, local-only artifact checks. The SSH agent reads fixed application
//! paths, but returns ONLY allowlisted health booleans and aggregate counters.
//! No SQL rows, calendar events, backup bytes, owner verifier or probe payload
//! are returned to the MCP client. This module cannot create or change files.
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::SystemTime,
};

const MAX_SQLITE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_GZIP_BYTES: u64 = 8 * 1024 * 1024;
const MAX_JSON_BYTES: u64 = 16 * 1024;
const MAX_OWNER_BYTES: u64 = 4096;
const MAX_SNAPSHOTS: usize = 128;
const SQLITE_CHECK: &str = r#"
import gzip, sqlite3, sys, urllib.parse
kind, path = sys.argv[1:3]
try:
    if kind == "plain":
        uri = "file:" + urllib.parse.quote(path, safe="/") + "?mode=ro&immutable=1"
        db = sqlite3.connect(uri, uri=True, timeout=1)
    elif kind == "gzip":
        with gzip.open(path, "rb") as src:
            blob = src.read(16 * 1024 * 1024 + 1)
        if not 100 <= len(blob) <= 16 * 1024 * 1024:
            raise ValueError("invalid decompressed size")
        db = sqlite3.connect(":memory:")
        db.deserialize(blob)
    else:
        raise ValueError("unknown mode")
    valid = (db.execute("PRAGMA quick_check(1)").fetchone() == ("ok",)
             and db.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0] > 0)
    db.close()
    print("ok" if valid else "bad")
except Exception:
    print("bad")
"#;

fn report(name: &str, status: &str, reason: &str, age: Option<u64>) -> Value {
    json!({"name":name, "status":status, "reason":reason, "age_minutes":age})
}

fn safe_file(path: &Path, size_limit: u64) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.file_type().is_file()
        && !meta.file_type().is_symlink()
        && (1..=size_limit).contains(&meta.len())
        && (meta.permissions().mode() & 0o022) == 0
}

fn safe_dir(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    meta.file_type().is_dir()
        && !meta.file_type().is_symlink()
        && (meta.permissions().mode() & 0o022) == 0
}

fn age_minutes(path: &Path) -> Option<u64> {
    let mtime = fs::symlink_metadata(path).ok()?.modified().ok()?;
    SystemTime::now()
        .duration_since(mtime)
        .ok()
        .map(|d| d.as_secs() / 60)
}

fn latest_entry(
    dir: &Path,
    suffix: &str,
    valid: fn(&str) -> bool,
    directories: bool,
) -> Result<Option<PathBuf>, &'static str> {
    if !safe_dir(dir) {
        return Err("backup_directory_insecure");
    }
    let mut selected: Option<PathBuf> = None;
    for (index, entry) in fs::read_dir(dir)
        .map_err(|_| "backup_directory_unreadable")?
        .enumerate()
    {
        // Entries may arrive in any filesystem order. Never present an
        // arbitrary older backup as the latest when the listing exceeds
        // our bounded inspection budget.
        if index >= MAX_SNAPSHOTS {
            return Err("backup_inventory_over_limit");
        }
        let entry = entry.map_err(|_| "backup_entry_unreadable")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "backup_name_invalid")?;
        if name.ends_with(suffix) && valid(&name) {
            let path = entry.path();
            if selected
                .as_ref()
                .is_none_or(|previous| path.file_name() > previous.file_name())
            {
                selected = Some(path);
            }
        }
    }
    if let Some(ref path) = selected {
        // Important: never silently fall back to an older snapshot if the
        // newest entry is a symlink, oversized or malformed archive.
        if !(if directories {
            safe_dir(path)
        } else {
            safe_file(path, MAX_GZIP_BYTES)
        }) {
            return Err("latest_snapshot_path_insecure");
        }
    }
    Ok(selected)
}

fn dated_ru0_dir(name: &str) -> bool {
    name.len() == 16
        && name.ends_with('Z')
        && name.bytes().take(15).enumerate().all(|(i, c)| {
            if i == 8 {
                c == b'T'
            } else {
                c.is_ascii_digit()
            }
        })
}
fn sqlite_quick_check(kind: &str, path: &Path) -> bool {
    if !matches!(kind, "plain" | "gzip") {
        return false;
    }
    let limit = if kind == "plain" {
        MAX_SQLITE_BYTES
    } else {
        MAX_GZIP_BYTES
    };
    if !safe_file(path, limit) {
        return false;
    }
    // No shell, caller inputs, SQL row output or writable SQLite connection.
    // timeout bounds corrupt files and decompression; Python -I -S isolates
    // the check from user-provided PYTHONPATH and site startup hooks.
    let Ok(output) = Command::new("timeout")
        .args([
            "6s",
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            SQLITE_CHECK,
            kind,
        ])
        .arg(path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    output.status.success() && output.stdout == b"ok\n"
}

fn ru0_backup(home: &Path) -> Value {
    const NAME: &str = "ru0_private_backup";
    let base = home.join(".local/share/assistant-hub-private");
    let snapshot = match latest_entry(&base.join("backups"), "Z", dated_ru0_dir, true) {
        Ok(Some(path)) => path,
        Ok(None) => return report(NAME, "unverified", "backup_snapshot_missing", None),
        Err(_) => return report(NAME, "failed", "latest_backup_path_invalid", None),
    };
    let age = age_minutes(&snapshot);
    let sqlite = snapshot.join("hub.sqlite3");
    let copied_owner = snapshot.join("owner.json");
    let current_owner = base.join("owner.json");
    if !safe_file(&copied_owner, MAX_OWNER_BYTES)
        || !safe_file(&current_owner, MAX_OWNER_BYTES)
        || !safe_file(&sqlite, MAX_SQLITE_BYTES)
    {
        return report(NAME, "failed", "backup_files_missing_or_insecure", age);
    }
    let owner_matches = match (fs::read(&copied_owner), fs::read(&current_owner)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !owner_matches {
        return report(NAME, "failed", "owner_verifier_mismatch", age);
    }
    if !sqlite_quick_check("plain", &sqlite) {
        return report(NAME, "failed", "sqlite_integrity_failed", age);
    }
    match age {
        Some(n) if n <= 48 * 60 => report(
            NAME,
            "verified",
            "snapshot_sqlite_and_owner_copy_valid",
            age,
        ),
        _ => report(NAME, "stale", "backup_snapshot_too_old", age),
    }
}

fn private_json(path: &Path) -> Option<Value> {
    if !safe_file(path, MAX_JSON_BYTES) {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn ru0_university(home: &Path) -> Value {
    const NAME: &str = "ru0_university_mirror";
    let path = home.join(".local/share/assistant-hub-private/google-university-feed-status.json");
    let age = age_minutes(&path);
    let Some(data) = private_json(&path) else {
        return report(NAME, "unverified", "feed_status_missing_or_invalid", age);
    };
    let counts = [
        "total_mirrored_events",
        "current_week_events",
        "next_week_events",
    ];
    let valid = counts
        .iter()
        .all(|key| data[*key].as_u64().is_some_and(|v| v <= 100_000))
        && data["checked_at_utc"]
            .as_str()
            .is_some_and(|s| (20..=48).contains(&s.len()))
        && data["freshness"].is_string();
    if !valid {
        return report(NAME, "failed", "feed_status_schema_invalid", age);
    }
    if age.is_none_or(|a| a > 240) {
        return report(NAME, "stale", "feed_status_outdated", age);
    }
    // Even fresh local counters are not evidence of an independently fresh
    // university subscription. Never upgrade this to verified without a
    // separately designed upstream provenance attestation.
    let mut outcome = report(
        NAME,
        "unverified",
        "university_source_not_independently_verified",
        age,
    );
    outcome["mirrored_event_count"] = data["total_mirrored_events"].clone();
    outcome
}

fn ru0_google_store(home: &Path) -> Value {
    const NAME: &str = "ru0_google_main_mirror";
    let path = home.join(".local/share/assistant-hub-private/hub.sqlite3");
    let age = age_minutes(&path);
    if !sqlite_quick_check("plain", &path) {
        return report(NAME, "failed", "local_calendar_store_integrity_failed", age);
    }
    // SQLite is shared with other Assistant Hub sources. A recent mtime or
    // valid database does not attest that Google Main itself just synced.
    report(
        NAME,
        "unverified",
        "shared_store_lacks_source_scoped_sync_receipt",
        age,
    )
}

/// Only these fixed, host-specific checks exist. Callers cannot choose paths,
/// SQL, JSON keys or services. Every failure returns non-green metadata.
pub fn summary(host: &str, home: &Path) -> Vec<Value> {
    match host {
        "ru0.alexandrshapkin.ru" => vec![
            ru0_backup(home),
            ru0_google_store(home),
            ru0_university(home),
        ],
        "srv0" => vec![],
        _ => vec![report(
            "unknown_host",
            "unverified",
            "host_not_allowlisted",
            None,
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn naming_restrictions_reject_traversal_and_untrusted_backups() {
        assert!(dated_ru0_dir("20261018T032755Z"));
        assert!(!dated_ru0_dir("../20261018T032755Z"));
        assert!(!dated_ru0_dir("20261018T032755X"));
    }
    #[test]
    fn missing_artifacts_are_never_verified() {
        let path = std::env::temp_dir().join("relayforge-artifacts-nonexistent-fixed");
        assert!(summary("ru0.alexandrshapkin.ru", &path)
            .iter()
            .all(|v| v["status"] != "verified"));
        assert!(summary("srv0", &path).is_empty());
    }
    #[test]
    fn newest_symlink_does_not_fall_back_to_older_valid_archive() {
        let dir = std::env::temp_dir().join(format!(
            "relayforge-artifact-selection-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let older = dir.join("state-2026-10-17.sqlite3.gz");
        fs::write(&older, b"older gzip placeholder").unwrap();
        let newer = dir.join("state-2026-10-18.sqlite3.gz");
        std::os::unix::fs::symlink(&older, &newer).unwrap();
        assert_eq!(
            latest_entry(&dir, ".sqlite3.gz", |v| v.ends_with(".sqlite3.gz"), false).unwrap_err(),
            "latest_snapshot_path_insecure"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn over_limit_backup_listing_fails_closed() {
        let dir = std::env::temp_dir().join(format!(
            "relayforge-artifact-overflow-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        for i in 0..=MAX_SNAPSHOTS {
            fs::write(dir.join(format!("ignored-{i}.txt")), b"x").unwrap();
        }
        assert_eq!(
            latest_entry(&dir, ".sqlite3.gz", |v| v.ends_with(".sqlite3.gz"), false).unwrap_err(),
            "backup_inventory_over_limit"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sqlite_checks_validate_real_and_corrupt_snapshots() {
        let dir =
            std::env::temp_dir().join(format!("relayforge-sqlite-fixture-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let raw = dir.join("fixture.sqlite3");
        let compressed = dir.join("fixture.sqlite3.gz");
        let made=Command::new("/usr/bin/python3").args(["-I","-S","-c",
            "import sqlite3,gzip,sys; db=sqlite3.connect(sys.argv[1]); db.execute('CREATE TABLE marker(x INTEGER)'); db.commit(); db.close(); gzip.open(sys.argv[2],'wb').write(open(sys.argv[1],'rb').read())"])
            .arg(&raw).arg(&compressed).status().unwrap();
        assert!(made.success());
        assert!(sqlite_quick_check("plain", &raw));
        assert!(sqlite_quick_check("gzip", &compressed));
        fs::write(&raw, b"not a database").unwrap();
        fs::write(&compressed, b"not gzip").unwrap();
        assert!(!sqlite_quick_check("plain", &raw));
        assert!(!sqlite_quick_check("gzip", &compressed));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlinked_artifacts_are_rejected() {
        let temp = std::env::temp_dir();
        let link = temp.join(format!("relayforge-artifact-link-{}", std::process::id()));
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
        assert!(!safe_file(&link, MAX_JSON_BYTES));
        fs::remove_file(link).unwrap();
    }
}
