//! Replacing this binary with a published release.
//!
//! The shape of this is upstream's `internal/updater`, because the files it
//! leaves behind are ones a user may already have: the new release is unpacked
//! into `<work>/agh-update-<version>`, the running binary and the config file
//! are copied into `<work>/agh-backup`, and the update directory is removed
//! afterwards.  Somebody who has used AdGuard Home's update button finds the
//! same directory in the same place.
//!
//! Two things are done here that upstream does not do, both because the
//! failure they prevent is a resolver that no longer starts:
//!
//!   * the archive is checked against the `checksums.txt` published beside it;
//!   * the unpacked binary is run twice before anything is moved — once for
//!     its version, and once over the real configuration with
//!     `--check-config`.
//!
//! The binary is replaced by *renaming*, never by writing over the running
//! file: an executable cannot be written to while it is running, and a
//! half-written one is worse than an old one.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sift_api::state::{SelfUpdater, UpdateFuture};

/// Where the archives are published.
const RELEASES: &str = "https://github.com/openhoangnc/sift/releases/download";

/// The environment variable that points the download somewhere else.
///
/// For a private mirror, and for proving this path works against a build that
/// is not published yet.  It moves only *where* the archive comes from: the
/// `checksums.txt` beside it still has to match, so pointing this at a mirror
/// that serves the wrong bytes fails rather than installs them.
pub const RELEASES_ENV: &str = "SIFT_RELEASES_URL";

/// Where release archives are downloaded from.
fn releases_base() -> String {
    std::env::var(RELEASES_ENV)
        .ok()
        .map(|v| v.trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| RELEASES.to_string())
}

/// The largest archive that will be downloaded.
///
/// Upstream's limit is 32 MiB for a package about a third that size; ours are
/// around 5 MiB compressed, and the headroom is for a build that grows.
const MAX_PACKAGE: u64 = 32 * 1024 * 1024;

/// The largest an unpacked archive may be.
const MAX_UNPACKED: u64 = 128 * 1024 * 1024;

/// How long the archive download may take.
///
/// Generous, because this runs on home connections and the alternative to a
/// slow download is no update at all.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// How long the checksum file download may take.
const CHECKSUM_TIMEOUT: Duration = Duration::from_secs(30);

/// Replaces this binary with a published release.
pub struct Updater {
    /// Whether `--no-check-update` was given, which switches the whole
    /// feature off.
    pub disabled: bool,
    /// The working directory: where `agh-update-*` and `agh-backup` go.
    pub work: PathBuf,
    /// The config file, copied into the backup before anything moves.
    pub config: PathBuf,
    /// Where this binary is, captured at startup.
    ///
    /// It has to be captured before the update rather than asked for after
    /// it: on Linux `current_exe` reads `/proc/self/exe`, which names the
    /// *inode* that is running, and the update moves that inode into
    /// `agh-backup`.  Asking afterwards therefore answers the backup's path,
    /// and starting it puts the old binary straight back -- with the same
    /// process id and no restart for anyone to notice.  Upstream keeps the
    /// path for the same reason; see AdGuardHome issue 4735.
    pub exe: Option<PathBuf>,
}

impl SelfUpdater for Updater {
    fn can_update(&self, needs_privileged_ports: bool) -> bool {
        if self.disabled {
            return false;
        }

        // In a container the image is the unit of update: a binary replaced
        // inside a running container is thrown away by the next `docker run`,
        // so offering the button there teaches the wrong habit.
        if Path::new("/.dockerenv").exists() {
            return false;
        }

        // A restart that cannot bind port 53 again is worse than no update.
        if needs_privileged_ports && !can_bind_privileged() {
            return false;
        }

        // Replacing the binary means creating a file in its directory.
        match exe_dir() {
            Some(dir) => is_writable(&dir),
            None => false,
        }
    }

    fn update(&self, version: String) -> UpdateFuture {
        let exe = self.exe.clone();
        let work = self.work.clone();
        let config = self.config.clone();

        Box::pin(async move {
            let exe = exe.ok_or_else(|| "this executable has no path".to_string())?;

            perform(&exe, &work, &config, &version).await
        })
    }

    fn restart(&self) -> String {
        match &self.exe {
            Some(exe) => restart_into(exe),
            None => "this executable has no path".to_string(),
        }
    }
}

/// Downloads `version`, checks it, and puts it in place of this binary.
async fn perform(exe: &Path, work: &Path, config: &Path, version: &str) -> Result<(), String> {
    let Some(asset) = asset_name() else {
        return Err(format!(
            "no release is published for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    };

    let update_dir = work.join(format!("agh-update-{version}"));
    let backup_dir = work.join("agh-backup");

    // A directory left by an interrupted attempt would otherwise be unpacked
    // into on top of.
    let _ = std::fs::remove_dir_all(&update_dir);
    std::fs::create_dir_all(&update_dir)
        .map_err(|e| format!("creating {}: {e}", update_dir.display()))?;

    let out = match stage(&update_dir, work, config, version, &asset).await {
        Ok(staged) => install(exe, &staged, config, &backup_dir),
        Err(e) => Err(e),
    };

    // The update directory is temporary whether or not this worked.
    let _ = std::fs::remove_dir_all(&update_dir);

    out
}

/// Downloads and verifies the release, leaving the new binary in `dir`.
async fn stage(
    dir: &Path,
    work: &Path,
    config: &Path,
    version: &str,
    asset: &str,
) -> Result<PathBuf, String> {
    let base = format!("{}/{version}", releases_base());

    tracing::info!(version, asset, "downloading the release");

    let archive = crate::fetch::get(&format!("{base}/{asset}"), MAX_PACKAGE, DOWNLOAD_TIMEOUT)
        .await
        .map_err(|e| format!("downloading {asset}: {e}"))?;

    let checksums = crate::fetch::get(
        &format!("{base}/checksums.txt"),
        64 * 1024,
        CHECKSUM_TIMEOUT,
    )
    .await
    .map_err(|e| format!("downloading checksums.txt: {e}"))?;

    verify(&archive, &checksums, asset)?;

    let binary = unpack(&archive)?;

    let staged = dir.join("AdGuardHome");
    std::fs::write(&staged, &binary).map_err(|e| format!("writing {}: {e}", staged.display()))?;
    make_executable(&staged)?;

    check(&staged, work, config)?;

    Ok(staged)
}

/// Checks the archive against the digest published beside it.
fn verify(archive: &[u8], checksums: &[u8], asset: &str) -> Result<(), String> {
    let text =
        std::str::from_utf8(checksums).map_err(|_| "checksums.txt is not text".to_string())?;

    let expected = text
        .lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .find(|(_, name)| name.trim().trim_start_matches('*') == asset)
        .map(|(digest, _)| digest.trim().to_ascii_lowercase())
        .ok_or_else(|| format!("checksums.txt does not name {asset}"))?;

    let actual = hex(ring::digest::digest(&ring::digest::SHA256, archive).as_ref());

    if actual != expected {
        return Err(format!(
            "{asset} does not match its published checksum: expected {expected}, got {actual}"
        ));
    }

    Ok(())
}

/// Lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }

    s
}

/// Extracts `AdGuardHome/AdGuardHome` from a gzipped tar archive.
fn unpack(archive: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(archive)
        .take(MAX_UNPACKED)
        .read_to_end(&mut raw)
        .map_err(|e| format!("decompressing the archive: {e}"))?;

    tar_find(&raw, "AdGuardHome/AdGuardHome")
        .ok_or_else(|| "the archive does not contain AdGuardHome/AdGuardHome".to_string())
}

/// Returns the contents of `wanted` from an uncompressed tar stream.
///
/// A whole tar reader is more than this needs: the archive is one this project
/// published, holding three short-named regular files.  Entries that are not
/// regular files, and long-name extensions, are stepped over by their recorded
/// size rather than understood.
fn tar_find(raw: &[u8], wanted: &str) -> Option<Vec<u8>> {
    /// A tar block, and the header's length.
    const BLOCK: usize = 512;

    let mut at = 0usize;
    while at + BLOCK <= raw.len() {
        let header = &raw[at..at + BLOCK];

        // Two zero blocks end the archive; one is enough to stop on.
        if header.iter().all(|&b| b == 0) {
            return None;
        }

        let name = field(&header[0..100]);
        let prefix = field(&header[345..500]);
        let full = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };

        let size = octal(&header[124..136])?;
        let kind = header[156];
        at += BLOCK;

        // '0' and NUL both mean a regular file; ustar writes one or the other.
        if (kind == b'0' || kind == 0) && full == wanted {
            let end = at.checked_add(usize::try_from(size).ok()?)?;

            return raw.get(at..end).map(<[u8]>::to_vec);
        }

        // Contents are padded to a whole number of blocks.
        at = at.checked_add(usize::try_from(size.next_multiple_of(BLOCK as u64)).ok()?)?;
    }

    None
}

/// Reads a NUL-terminated header field.
fn field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());

    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// Reads a tar header's octal number field.
fn octal(bytes: &[u8]) -> Option<u64> {
    let text = field(bytes);
    let digits = text.trim_matches(|c: char| c == ' ' || c == '\0');
    if digits.is_empty() {
        return Some(0);
    }

    u64::from_str_radix(digits, 8).ok()
}

/// Runs the downloaded binary, over the real configuration, before it is
/// anywhere near the path the service starts from.
fn check(staged: &Path, work: &Path, config: &Path) -> Result<(), String> {
    let out = std::process::Command::new(staged)
        .arg("--version")
        .output()
        .map_err(|e| format!("running the downloaded binary: {e}"))?;

    let reported = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !reported.starts_with("Sift, version ") {
        return Err(format!(
            "the downloaded binary does not run here; it reported {reported:?}"
        ));
    }

    tracing::info!(reported = %reported, "the downloaded binary runs");

    let out = std::process::Command::new(staged)
        .arg("--check-config")
        .arg("-c")
        .arg(config)
        .arg("-w")
        .arg(work)
        .output()
        .map_err(|e| format!("checking the configuration with the new binary: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "the downloaded binary rejects this configuration: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    Ok(())
}

/// Backs up what is there and moves the new binary into place.
fn install(exe: &Path, staged: &Path, config: &Path, backup_dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(backup_dir)
        .map_err(|e| format!("creating {}: {e}", backup_dir.display()))?;

    if config.exists() {
        let to = backup_dir.join("AdGuardHome.yaml");
        std::fs::copy(config, &to).map_err(|e| format!("copying the config file: {e}"))?;
    }

    // The running binary is moved rather than copied: the file that is
    // executing keeps executing under its new name, and the path it came from
    // is then free for a file of the same name.
    let kept = backup_dir.join("AdGuardHome");
    move_file(exe, &kept).map_err(|e| format!("keeping the running binary: {e}"))?;

    if let Err(e) = move_file(staged, exe) {
        // Nothing has started the new binary yet, so the old one going back is
        // a complete undo.
        let _ = move_file(&kept, exe);

        return Err(format!("putting the new binary in place: {e}"));
    }

    make_executable(exe)?;

    tracing::info!(
        exe = %exe.display(),
        kept = %kept.display(),
        "replaced the running binary"
    );

    Ok(())
}

/// Moves a file, falling back to a copy when the two ends are on different
/// filesystems and `rename` therefore cannot work.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)?;

            Ok(())
        }
    }
}

/// Gives a file the mode an executable needs.
fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| format!("setting the mode of {}: {e}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// The name of the archive published for this machine.
fn asset_name() -> Option<String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        _ => return None,
    };

    let cpu = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        // Rust spells both 32-bit Arm variants `arm`; the published build is
        // the hard-float v7 one.
        "arm" => "armv7",
        "x86" => "386",
        _ => return None,
    };

    Some(format!("sift_{os}_{cpu}.tar.gz"))
}

/// The directory holding this executable.
fn exe_dir() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);

    exe.parent().map(PathBuf::from)
}

/// Reports whether a directory can be written to, by writing to it.
///
/// The mode bits are not the answer on their own: the filesystem may be
/// read-only, or the process may hold a capability the bits do not describe.
fn is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".sift-write-test-{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);

            true
        }
        Err(_) => false,
    }
}

/// Reports whether this process could bind a port below 1024 again.
fn can_bind_privileged() -> bool {
    #[cfg(unix)]
    {
        // Deliberately conservative: a non-root process may hold
        // CAP_NET_BIND_SERVICE and still be able to, but reading capabilities
        // is more machinery than the answer is worth, and the cost of being
        // wrong the other way is a resolver that does not come back.
        rustix::process::geteuid().is_root()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Starts the binary at `exe` in place of this process.
///
/// Returns only on failure: on success this image is gone.  The arguments and
/// the environment are this process's, so the new binary is started exactly
/// the way the old one was -- which is what makes it work under a unit file
/// nobody here wrote.
fn restart_into(exe: &Path) -> String {
    tracing::info!(exe = %exe.display(), "restarting into the new binary");

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        let err = std::process::Command::new(exe)
            .args(std::env::args_os().skip(1))
            .exec();

        format!("restarting: {err}")
    }
    #[cfg(not(unix))]
    {
        let _ = exe;

        "restarting in place is not supported on this platform".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a tar stream holding one regular file.
    fn tar_of(name: &str, body: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        let size = format!("{:011o}\0", body.len());
        header[124..124 + size.len()].copy_from_slice(size.as_bytes());
        header[156] = b'0';
        header[257..262].copy_from_slice(b"ustar");

        // The checksum field is spaces while the checksum is computed; this
        // reader does not check it, and neither does GNU tar by default.
        for b in &mut header[148..156] {
            *b = b' ';
        }

        let mut out = header.to_vec();
        out.extend_from_slice(body);
        out.resize(out.len().next_multiple_of(512), 0);
        out.extend_from_slice(&[0u8; 1024]);

        out
    }

    #[test]
    fn finds_the_binary_in_an_archive() {
        let raw = tar_of("AdGuardHome/AdGuardHome", b"not really a binary");

        assert_eq!(
            tar_find(&raw, "AdGuardHome/AdGuardHome").as_deref(),
            Some(&b"not really a binary"[..])
        );
        assert_eq!(tar_find(&raw, "AdGuardHome/LICENSE.txt"), None);
    }

    #[test]
    fn steps_over_the_entries_it_is_not_looking_for() {
        let mut raw = tar_of("AdGuardHome/README.md", b"a readme, 21 bytes---");
        // Drop the end-of-archive blocks of the first one and append another.
        raw.truncate(raw.len() - 1024);
        raw.extend_from_slice(&tar_of("AdGuardHome/AdGuardHome", b"the binary"));

        assert_eq!(
            tar_find(&raw, "AdGuardHome/AdGuardHome").as_deref(),
            Some(&b"the binary"[..])
        );
    }

    #[test]
    fn a_truncated_archive_yields_nothing_rather_than_panicking() {
        // A download cut short is the ordinary failure here, and a reader
        // that indexes a header's recorded size into a shorter buffer aborts
        // the process rather than reporting it.
        let body = b"the binary";
        let raw = tar_of("AdGuardHome/AdGuardHome", body);
        let complete = 512 + body.len();

        for cut in [0, 1, 100, 511, 512, 513, complete - 1] {
            assert_eq!(
                tar_find(&raw[..cut], "AdGuardHome/AdGuardHome"),
                None,
                "{cut} bytes is not a whole entry"
            );
        }

        assert!(tar_find(&raw[..complete], "AdGuardHome/AdGuardHome").is_some());
    }

    #[test]
    fn the_checksum_is_the_one_published_for_this_archive() {
        let archive = b"pretend this is an archive";
        let digest = hex(ring::digest::digest(&ring::digest::SHA256, archive).as_ref());
        let sums = format!(
            "0000000000000000000000000000000000000000000000000000000000000000  sift_linux_amd64.tar.gz\n\
             {digest}  sift_linux_arm64.tar.gz\n"
        );

        assert!(verify(archive, sums.as_bytes(), "sift_linux_arm64.tar.gz").is_ok());
        assert!(verify(archive, sums.as_bytes(), "sift_linux_amd64.tar.gz").is_err());
        assert!(verify(archive, sums.as_bytes(), "sift_darwin_arm64.tar.gz").is_err());
    }

    #[test]
    fn the_asset_is_named_for_this_machine() {
        // Whatever this is built for, the name has to be one the release
        // workflow produces.
        if let Some(name) = asset_name() {
            assert!(name.starts_with("sift_"), "{name}");
            assert!(name.ends_with(".tar.gz"), "{name}");
        }
    }
}
