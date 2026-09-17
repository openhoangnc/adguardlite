//! Operating-system settings: the user to run as, the descriptor limit and
//! the PID file.
//!
//! These are applied before the async runtime starts, while the process is
//! still single-threaded.  On Linux the `setuid` and `setgid` syscalls act on
//! the calling thread, so dropping privileges after the runtime has spawned
//! its worker threads would leave most of them privileged.

use std::io;
use std::path::Path;

/// A failure applying an operating-system setting.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The named user or group does not exist.
    #[error("no such {kind} {name:?}")]
    NotFound {
        /// Either `user` or `group`.
        kind: &'static str,
        /// The name that was looked up.
        name: String,
    },

    /// The system call failed, usually for want of privilege.
    #[error("{what}: {source}")]
    Syscall {
        /// What was being attempted.
        what: &'static str,
        /// The underlying error.
        #[source]
        source: io::Error,
    },

    /// The platform does not support the setting.
    #[error("{0} is not supported on this platform")]
    Unsupported(&'static str),
}

/// Looks a user name up, accepting a numeric id directly.
///
/// `/etc/passwd` is read rather than the name service: in the container this
/// ships in, that file is the whole directory, and a numeric id — which is
/// what a container image normally uses — needs no lookup at all.
pub fn lookup_uid(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }

    let text = std::fs::read_to_string("/etc/passwd").ok()?;

    field_of(&text, name, 2)
}

/// Looks a group name up, accepting a numeric id directly.
pub fn lookup_gid(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }

    let text = std::fs::read_to_string("/etc/group").ok()?;

    field_of(&text, name, 2)
}

/// Reads the numeric field at `index` from the line naming `name`.
///
/// Both `/etc/passwd` and `/etc/group` are colon-separated with the name
/// first and the numeric id third.
fn field_of(text: &str, name: &str, index: usize) -> Option<u32> {
    text.lines().find_map(|line| {
        let mut f = line.split(':');
        if f.next()? != name {
            return None;
        }

        f.nth(index - 1)?.parse().ok()
    })
}

/// Switches the process to a group.
#[cfg(unix)]
pub fn set_group(name: &str) -> Result<u32, Error> {
    let gid = lookup_gid(name).ok_or_else(|| Error::NotFound {
        kind: "group",
        name: name.to_string(),
    })?;

    set_gid(gid)?;

    Ok(gid)
}

/// Switches the process to a user.
#[cfg(unix)]
pub fn set_user(name: &str) -> Result<u32, Error> {
    let uid = lookup_uid(name).ok_or_else(|| Error::NotFound {
        kind: "user",
        name: name.to_string(),
    })?;

    set_uid(uid)?;

    Ok(uid)
}

/// Applies the group id.
#[cfg(all(unix, target_os = "linux"))]
fn set_gid(gid: u32) -> Result<(), Error> {
    // Safe wrappers; on Linux these act on the calling thread, which is why
    // this runs before the runtime spawns any others.
    rustix::thread::set_thread_gid(rustix::thread::Gid::from_raw(gid)).map_err(|e| Error::Syscall {
        what: "setting the group id",
        source: e.into(),
    })
}

/// Applies the user id.
#[cfg(all(unix, target_os = "linux"))]
fn set_uid(uid: u32) -> Result<(), Error> {
    rustix::thread::set_thread_uid(rustix::thread::Uid::from_raw(uid)).map_err(|e| Error::Syscall {
        what: "setting the user id",
        source: e.into(),
    })
}

/// Applies the group id.
///
/// rustix only exposes the thread-scoped form on Linux, so elsewhere the
/// setting is reported as unsupported rather than silently ignored.
#[cfg(all(unix, not(target_os = "linux")))]
fn set_gid(_gid: u32) -> Result<(), Error> {
    Err(Error::Unsupported("os.group"))
}

/// Applies the user id.
#[cfg(all(unix, not(target_os = "linux")))]
fn set_uid(_uid: u32) -> Result<(), Error> {
    Err(Error::Unsupported("os.user"))
}

/// Switches the process to a group.
#[cfg(not(unix))]
pub fn set_group(_name: &str) -> Result<u32, Error> {
    Err(Error::Unsupported("os.group"))
}

/// Switches the process to a user.
#[cfg(not(unix))]
pub fn set_user(_name: &str) -> Result<u32, Error> {
    Err(Error::Unsupported("os.user"))
}

/// Raises the limit on open file descriptors.
#[cfg(unix)]
pub fn set_rlimit_nofile(limit: u64) -> Result<(), Error> {
    use rustix::process::{Resource, Rlimit, setrlimit};

    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(limit),
            maximum: Some(limit),
        },
    )
    .map_err(|e| Error::Syscall {
        what: "setting the descriptor limit",
        source: e.into(),
    })
}

/// Raises the limit on open file descriptors.
#[cfg(not(unix))]
pub fn set_rlimit_nofile(_limit: u64) -> Result<(), Error> {
    Err(Error::Unsupported("os.rlimit_nofile"))
}

/// Applies the `os` block of the configuration.
///
/// A setting the platform cannot honour is a warning rather than a failure, as
/// upstream treats it: the server is still usable, just not confined.
pub fn apply(os: &sift_config::model::OsConfig) {
    if os.rlimit_nofile != 0 {
        match set_rlimit_nofile(os.rlimit_nofile) {
            Ok(()) => tracing::info!(limit = os.rlimit_nofile, "descriptor limit set"),
            Err(e) => tracing::warn!(error = %e, "setting the descriptor limit"),
        }
    }

    // The group must be dropped first: once the user is no longer root, the
    // group can no longer be changed.
    if !os.group.is_empty() {
        match set_group(&os.group) {
            Ok(gid) => tracing::info!(group = %os.group, gid, "group set"),
            Err(e) => tracing::warn!(error = %e, "setting the group"),
        }
    }

    if !os.user.is_empty() {
        match set_user(&os.user) {
            Ok(uid) => tracing::info!(user = %os.user, uid, "user set"),
            Err(e) => tracing::warn!(error = %e, "setting the user"),
        }
    }
}

/// Writes the process identifier to a file.
pub fn write_pidfile(path: &Path) -> io::Result<()> {
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }

    std::fs::write(path, format!("{}\n", std::process::id()))
}

/// Removes the PID file, ignoring a missing one.
pub fn remove_pidfile(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
adguardhome:x:1001:1001::/opt/adguardhome:/sbin/nologin
";

    const GROUP: &str = "\
root:x:0:
adguardhome:x:1001:
";

    #[test]
    fn names_resolve_to_ids() {
        assert_eq!(field_of(PASSWD, "adguardhome", 2), Some(1001));
        assert_eq!(field_of(PASSWD, "root", 2), Some(0));
        assert_eq!(field_of(PASSWD, "nobody", 2), None);
        assert_eq!(field_of(GROUP, "adguardhome", 2), Some(1001));
    }

    #[test]
    fn a_numeric_id_needs_no_lookup() {
        // A container image usually has no passwd entry for the id it runs as.
        assert_eq!(lookup_uid("65534"), Some(65534));
        assert_eq!(lookup_gid("0"), Some(0));
    }

    #[test]
    fn a_pidfile_is_written_and_removed() {
        let dir = std::env::temp_dir().join(format!("sift-pid-{}", std::process::id()));
        let path = dir.join("agh.pid");

        write_pidfile(&path).expect("the pid file should be writable");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.trim(), std::process::id().to_string());

        remove_pidfile(&path);
        assert!(!path.exists());
        // Removing a missing file is not an error.
        remove_pidfile(&path);

        std::fs::remove_dir_all(&dir).ok();
    }
}
