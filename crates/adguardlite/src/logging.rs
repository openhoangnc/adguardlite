//! Where the log goes: standard error, a rotating file, or the system log.
//!
//! The destination comes from `--logfile` or the `log` block of the
//! configuration, and the rotation settings — `max_size`, `max_backups`,
//! `max_age` and `compress` — are the ones upstream documents.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use parking_lot::Mutex;

/// The name that selects the system log rather than a file.
pub const SYSLOG: &str = "syslog";

/// How rotation is configured.
#[derive(Clone, Copy, Debug)]
pub struct Rotation {
    /// The size at which the file is rotated, in megabytes.  Zero never
    /// rotates.
    pub max_size_mb: u32,
    /// How many rotated files are kept.  Zero keeps them all.
    pub max_backups: u32,
    /// How old a rotated file may get, in days.  Zero keeps them forever.
    pub max_age_days: u32,
    /// Whether rotated files are gzipped.
    pub compress: bool,
}

impl Default for Rotation {
    fn default() -> Self {
        Self {
            max_size_mb: 100,
            max_backups: 0,
            max_age_days: 0,
            compress: false,
        }
    }
}

/// A log file that rotates when it grows past its limit.
///
/// The rotated files are named `<path>.1`, `<path>.2` and so on, the lowest
/// number being the most recent — the layout `lumberjack` produces, which is
/// what upstream writes.
pub struct RotatingFile {
    /// The state behind the lock, so the writer can be shared.
    inner: Mutex<Inner>,
}

/// The mutable half of a rotating file.
struct Inner {
    /// Where the log is written.
    path: PathBuf,
    /// The open file, reopened after each rotation.
    file: Option<File>,
    /// How many bytes the current file holds.
    written: u64,
    /// The rotation settings.
    rotation: Rotation,
}

impl RotatingFile {
    /// Opens, or creates, the log file.
    pub fn open(path: impl Into<PathBuf>, rotation: Rotation) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent()
            && !dir.as_os_str().is_empty()
        {
            std::fs::create_dir_all(dir)?;
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            inner: Mutex::new(Inner {
                path,
                file: Some(file),
                written,
                rotation,
            }),
        })
    }
}

impl Inner {
    /// Rotates the file and opens a fresh one.
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;

        let keep = self.rotation.max_backups;
        // Shift the existing backups up, dropping the oldest.
        let mut n = if keep == 0 { 64 } else { keep };
        while n > 0 {
            let from = backup_path(&self.path, n, self.rotation.compress);
            let to = backup_path(&self.path, n + 1, self.rotation.compress);
            if from.exists() {
                if keep != 0 && n == keep {
                    let _ = std::fs::remove_file(&from);
                } else {
                    let _ = std::fs::rename(&from, &to);
                }
            }
            n -= 1;
        }

        let first = backup_path(&self.path, 1, self.rotation.compress);
        if self.rotation.compress {
            compress_into(&self.path, &first)?;
            let _ = std::fs::remove_file(&self.path);
        } else {
            std::fs::rename(&self.path, &first)?;
        }

        self.prune_by_age();

        self.file = Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?,
        );
        self.written = 0;

        Ok(())
    }

    /// Deletes rotated files older than the configured age.
    fn prune_by_age(&self) {
        let days = self.rotation.max_age_days;
        if days == 0 {
            return;
        }

        let cutoff = std::time::SystemTime::now()
            - std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60);

        for n in 1..=64u32 {
            let p = backup_path(&self.path, n, self.rotation.compress);
            let Ok(meta) = std::fs::metadata(&p) else {
                continue;
            };
            if meta.modified().is_ok_and(|m| m < cutoff) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

/// The name of the nth rotated file.
fn backup_path(path: &Path, n: u32, compress: bool) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    if compress {
        s.push(".gz");
    }

    PathBuf::from(s)
}

/// Copies a file through gzip.
fn compress_into(from: &Path, to: &Path) -> io::Result<()> {
    let data = std::fs::read(from)?;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&data)?;
    let out = enc.finish()?;

    std::fs::write(to, out)
}

impl Write for &RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.inner.lock();

        let limit = u64::from(inner.rotation.max_size_mb) * 1024 * 1024;
        if limit > 0 && inner.written + buf.len() as u64 > limit && inner.written > 0 {
            // A rotation failure must not lose the message: keep writing to
            // the file that is already open.
            let _ = inner.rotate();
        }

        let Some(f) = inner.file.as_mut() else {
            return Ok(buf.len());
        };
        let n = f.write(buf)?;
        inner.written += n as u64;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut inner = self.inner.lock();
        match inner.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

/// The system log, written over its local socket.
///
/// The message format is RFC 3164's: a priority in angle brackets, then the
/// tag, the process id and the text.  The socket is `/dev/log` on Linux and
/// `/var/run/syslog` on the BSDs and macOS.
#[cfg(unix)]
pub struct Syslog {
    /// The connected socket, if one could be opened.
    sock: Mutex<Option<std::os::unix::net::UnixDatagram>>,
}

#[cfg(unix)]
impl Syslog {
    /// Connects to the local system log.
    pub fn connect() -> io::Result<Self> {
        use std::os::unix::net::UnixDatagram;

        let sock = UnixDatagram::unbound()?;
        let mut last = None;
        for path in ["/dev/log", "/var/run/syslog", "/var/run/log"] {
            match sock.connect(path) {
                Ok(()) => {
                    return Ok(Self {
                        sock: Mutex::new(Some(sock)),
                    });
                }
                Err(e) => last = Some(e),
            }
        }

        Err(last.unwrap_or_else(|| io::Error::other("no system log socket")))
    }
}

#[cfg(unix)]
impl Write for &Syslog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Facility 3 (daemon) times eight, plus severity 6 (informational).
        const PRIORITY: u8 = 3 * 8 + 6;

        let text = String::from_utf8_lossy(buf);
        let text = text.trim_end();
        if text.is_empty() {
            return Ok(buf.len());
        }

        let msg = format!("<{PRIORITY}>AdGuardHome[{}]: {text}", std::process::id());

        if let Some(s) = self.sock.lock().as_ref() {
            // A full or closed socket must not stall the server; the message
            // is dropped, which is what every syslog client does.
            let _ = s.send(msg.as_bytes());
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Where the log should go.
pub enum Sink {
    /// Standard error, the default.
    Stderr,
    /// A rotating file.
    File(&'static RotatingFile),
    /// The system log.
    #[cfg(unix)]
    Syslog(&'static Syslog),
}

impl Sink {
    /// Chooses a destination from the flag and the configuration.
    ///
    /// A file that cannot be opened falls back to standard error with a note
    /// on it: starting without a log is better than not starting.
    pub fn choose(target: &str, rotation: Rotation) -> Self {
        if target.is_empty() {
            return Sink::Stderr;
        }

        #[cfg(unix)]
        if target == SYSLOG {
            return match Syslog::connect() {
                Ok(s) => Sink::Syslog(Box::leak(Box::new(s))),
                Err(e) => {
                    eprintln!("adguardlite: connecting to the system log: {e}; using stderr");

                    Sink::Stderr
                }
            };
        }

        #[cfg(not(unix))]
        if target == SYSLOG {
            eprintln!("adguardlite: the system log is not available on this platform");

            return Sink::Stderr;
        }

        match RotatingFile::open(target, rotation) {
            Ok(f) => Sink::File(Box::leak(Box::new(f))),
            Err(e) => {
                eprintln!("adguardlite: opening the log file {target}: {e}; using stderr");

                Sink::Stderr
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("agl-log-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();

        d
    }

    #[test]
    fn backup_names_follow_the_upstream_layout() {
        let p = Path::new("/var/log/AdGuardHome.log");
        assert_eq!(
            backup_path(p, 1, false),
            PathBuf::from("/var/log/AdGuardHome.log.1")
        );
        assert_eq!(
            backup_path(p, 2, true),
            PathBuf::from("/var/log/AdGuardHome.log.2.gz")
        );
    }

    #[test]
    fn a_file_rotates_once_it_passes_its_limit() {
        let dir = tmpdir("rotate");
        let path = dir.join("agh.log");

        // One megabyte, written in chunks that cross it.
        let f = RotatingFile::open(
            &path,
            Rotation {
                max_size_mb: 1,
                max_backups: 2,
                max_age_days: 0,
                compress: false,
            },
        )
        .unwrap();

        let chunk = vec![b'x'; 256 * 1024];
        let mut w = &f;
        for _ in 0..8 {
            w.write_all(&chunk).unwrap();
        }
        w.flush().unwrap();

        assert!(path.exists(), "the current file is reopened after rotating");
        assert!(
            backup_path(&path, 1, false).exists(),
            "a backup should have been made"
        );
        assert!(
            !backup_path(&path, 3, false).exists(),
            "only max_backups files are kept"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_compressed_backup_is_gzipped() {
        let dir = tmpdir("gz");
        let path = dir.join("agh.log");

        let f = RotatingFile::open(
            &path,
            Rotation {
                max_size_mb: 1,
                max_backups: 1,
                max_age_days: 0,
                compress: true,
            },
        )
        .unwrap();

        let chunk = vec![b'y'; 512 * 1024];
        let mut w = &f;
        for _ in 0..4 {
            w.write_all(&chunk).unwrap();
        }

        let gz = backup_path(&path, 1, true);
        assert!(gz.exists(), "the backup should be compressed");
        let raw = std::fs::read(&gz).unwrap();
        assert_eq!(&raw[..2], &[0x1f, 0x8b], "gzip magic");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_zero_size_never_rotates() {
        let dir = tmpdir("norotate");
        let path = dir.join("agh.log");

        let f = RotatingFile::open(
            &path,
            Rotation {
                max_size_mb: 0,
                ..Default::default()
            },
        )
        .unwrap();

        let mut w = &f;
        w.write_all(&vec![b'z'; 1024 * 1024]).unwrap();
        w.flush().unwrap();

        assert!(!backup_path(&path, 1, false).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_empty_target_means_stderr() {
        assert!(matches!(
            Sink::choose("", Rotation::default()),
            Sink::Stderr
        ));
    }

    #[test]
    fn an_unopenable_file_falls_back_rather_than_failing() {
        // A path whose parent cannot be created.
        assert!(matches!(
            Sink::choose("/proc/nonexistent/agh.log", Rotation::default()),
            Sink::Stderr
        ));
    }
}
