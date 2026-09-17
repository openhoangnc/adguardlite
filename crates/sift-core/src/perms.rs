//! The file modes AdGuard Home creates its data with.
//!
//! Upstream's `aghos.DefaultPermDir` and `aghos.DefaultPermFile` are `0o700`
//! and `0o600`, and it uses them for the data directory, the filter cache,
//! `querylog.json` and the config file alike.
//!
//! This is not cosmetic. `querylog.json` records every name every client on
//! the network looked up; leaving it world-readable on a shared host, or in a
//! volume mounted into another container, discloses that. The Go build does
//! not, so neither should this one.

use std::path::Path;

/// The mode upstream creates directories with.
pub const DIR: u32 = 0o700;

/// The mode upstream creates files with.
pub const FILE: u32 = 0o600;

/// Creates a directory and any missing parent, with upstream's mode.
///
/// As with Go's `os.MkdirAll`, a directory that already exists keeps the mode
/// it has: this sets the mode of what it creates, and nothing else.
#[cfg(unix)]
pub fn create_dir_all(path: impl AsRef<Path>) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR)
        .create(path)
}

/// Creates a directory and any missing parent.
#[cfg(not(unix))]
pub fn create_dir_all(path: impl AsRef<Path>) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Narrows an existing file to upstream's mode.
///
/// A missing file is not an error: callers use this right after a write that
/// may have been skipped, and a file that is not there cannot leak.
#[cfg(unix)]
pub fn restrict_file(path: impl AsRef<Path>) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::set_permissions(path, std::fs::Permissions::from_mode(FILE)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Narrows an existing file to upstream's mode: nothing to do off Unix.
#[cfg(not(unix))]
pub fn restrict_file(_path: impl AsRef<Path>) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn directories_and_files_match_the_go_build() {
        // Captured from adguard/adguardhome:v0.107.79 running on a bind mount:
        //   drwx------  work/data
        //   drwx------  work/data/filters
        //   -rw-------  work/data/querylog.json
        let base = std::env::temp_dir().join(format!("sift-perms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        let nested = base.join("data").join("filters");
        create_dir_all(&nested).unwrap();
        assert_eq!(mode_of(&nested), DIR, "the leaf directory");
        assert_eq!(mode_of(&base.join("data")), DIR, "a parent it created");

        let f = nested.join("1.txt");
        std::fs::write(&f, b"||ads.example.com^\n").unwrap();
        restrict_file(&f).unwrap();
        assert_eq!(
            mode_of(&f),
            FILE,
            "a filter list holds no secret, but Go is 0600"
        );

        // A file that is not there is not an error.
        restrict_file(nested.join("absent.txt")).unwrap();

        let _ = std::fs::remove_dir_all(&base);
    }
}
