//! Background jobs must use the same frozen versioned image as the caller.
//! No Cargo output, mutable current selector or caller-supplied executable.
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

fn artifact_path(home: &Path, executable: &Path) -> bool {
    let store = home.join(".local/libexec/relayforge/runtime/artifacts");
    let Ok(relative) = executable.strip_prefix(store) else {
        return false;
    };
    let parts: Vec<_> = relative.components().collect();
    if parts.len() != 2 || parts[1].as_os_str() != "relayforge-mcp" {
        return false;
    }
    let Some(id) = parts[0].as_os_str().to_str() else {
        return false;
    };
    id.len() == 105
        && id.as_bytes()[40] == b'-'
        && id
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 40 || b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn current_image(home: &Path) -> Result<PathBuf, String> {
    let executable = std::env::current_exe().map_err(|_| "runtime image unavailable")?;
    if !artifact_path(home, &executable) {
        return Err("operation requires a migrated runtime image".into());
    }
    let uid = fs::metadata("/proc/self")
        .map_err(|_| "runtime identity unavailable")?
        .uid();
    let root = home.join(".local/libexec/relayforge/runtime");
    for path in [
        root.clone(),
        root.join("artifacts"),
        executable.parent().ok_or("invalid artifact")?.to_owned(),
        executable.clone(),
    ] {
        let meta = fs::symlink_metadata(&path).map_err(|_| "runtime image unavailable")?;
        if meta.file_type().is_symlink() || meta.uid() != uid || meta.mode() & 0o022 != 0 {
            return Err("unsafe runtime image".into());
        }
        if path == executable && (!meta.is_file() || meta.mode() & 0o222 != 0) {
            return Err("runtime image is not frozen".into());
        }
    }
    Ok(executable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_versioned_runtime_paths_are_candidates() {
        let home = Path::new("/home/operator");
        let id = format!("{}-{}", "a".repeat(40), "b".repeat(64));
        assert!(artifact_path(
            home,
            &home.join(format!(
                ".local/libexec/relayforge/runtime/artifacts/{id}/relayforge-mcp"
            ))
        ));
        for path in [
            "Projects/relayforge/target/release/relayforge-mcp",
            ".local/libexec/relayforge/runtime/current/relayforge-mcp",
            ".local/libexec/relayforge/runtime/artifacts/../relayforge-mcp",
        ] {
            assert!(!artifact_path(home, &home.join(path)));
        }
    }
}
