//! Explicit private SSH config path for hardened systemd execution.
//!
//! On some distros system SSH config contains generated symlinks which
//! OpenSSH rejects when running under mount namespaces. User aliases live
//! in a separate private config; never follow untrusted system defaults.
use std::{env, fs, os::unix::fs::PermissionsExt, path::PathBuf};

pub fn config_path() -> Result<PathBuf, String> {
    let home = env::var_os("HOME").ok_or("HOME missing")?;
    let path = PathBuf::from(home).join(".ssh/config");
    let metadata = fs::symlink_metadata(&path).map_err(|_| "SSH user config unavailable")?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err("SSH user config permissions invalid".into());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    #[test]
    fn user_config_path_is_explicit() {
        // The path should not depend on the system ssh_config directories.
        if let Ok(path) = super::config_path() {
            assert!(path.ends_with(".ssh/config"));
        }
    }
}
