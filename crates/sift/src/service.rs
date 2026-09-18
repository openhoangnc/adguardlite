//! Installing and controlling the system service.
//!
//! `-s install` writes a unit for the platform's init system and enables it;
//! the other actions hand the request to that init system.  The unit names the
//! binary by its absolute path and passes the same arguments this invocation
//! got, so the installed service runs with the configuration the operator was
//! just using.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::cli::Args;

/// The service name, matching upstream's.
pub const NAME: &str = "AdGuardHome";

/// A service control failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The action is not one of the ones defined.
    #[error("unknown service action {action:?}; expected one of {}", ACTIONS.join(", "))]
    UnknownAction {
        /// What was asked for.
        action: String,
    },

    /// The platform has no supported init system.
    #[error("service control is not supported on this platform")]
    Unsupported,

    /// A file could not be written or removed.
    #[error("{what}: {source}")]
    Io {
        /// What was being attempted.
        what: String,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// The init system refused the request.
    #[error("{command} failed: {output}")]
    Command {
        /// The command that was run.
        command: String,
        /// What it printed.
        output: String,
    },
}

/// The action an init system passes to run the server in the foreground.
///
/// Upstream's own generated unit runs `AdGuardHome "-s" "run"`, so a build
/// that refuses it cannot be dropped into an existing installation: systemd
/// would restart it for ever against a unit the operator never wrote.  It is
/// deliberately not in [`ACTIONS`], because it is not something [`run`]
/// performs — `main` recognises it and simply starts the server.
pub const RUN: &str = "run";

/// The control actions the flag accepts, as upstream documents them.
pub const ACTIONS: [&str; 7] = [
    "install",
    "uninstall",
    "start",
    "stop",
    "restart",
    "reload",
    "status",
];

/// Which init system to drive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Init {
    /// systemd, on Linux.
    Systemd,
    /// launchd, on macOS.
    ///
    /// Built on every platform, not only the one that can run it: the plist
    /// generator and the tests that check it are worth compiling and running
    /// wherever the suite runs, and only `detect` is platform-specific.  That
    /// leaves nothing constructing this on a build that is not for macOS --
    /// `Systemd` escapes the same lint only by accident, because `uninstall`
    /// happens to compare against it.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Launchd,
}

impl Init {
    /// The init system of the platform this was built for.
    pub const fn detect() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            Some(Init::Systemd)
        }
        #[cfg(target_os = "macos")]
        {
            Some(Init::Launchd)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            None
        }
    }

    /// Where the unit file lives.
    pub fn unit_path(self) -> PathBuf {
        match self {
            Init::Systemd => PathBuf::from("/etc/systemd/system/AdGuardHome.service"),
            Init::Launchd => PathBuf::from("/Library/LaunchDaemons/com.adguard.AdGuardHome.plist"),
        }
    }
}

impl fmt::Display for Init {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Init::Systemd => "systemd",
            Init::Launchd => "launchd",
        })
    }
}

/// Performs a service action, returning what to print.
pub fn run(action: &str, args: &Args) -> Result<String, Error> {
    if !ACTIONS.contains(&action) {
        return Err(Error::UnknownAction {
            action: action.to_string(),
        });
    }

    let init = Init::detect().ok_or(Error::Unsupported)?;

    match action {
        "install" => install(init, args),
        "uninstall" => uninstall(init),
        other => control(init, other),
    }
}

/// The arguments the installed service should run with.
///
/// The paths are made absolute, because a unit file runs with no working
/// directory of its own.
///
/// `--no-check-update` is passed on only when this invocation had it, as
/// upstream's generated unit does.  Writing it in unconditionally switched
/// the release check off for every natively installed server -- and with it
/// the update button, which has nothing to offer without a check.  The Docker
/// `CMD` still passes it, because there the image is what gets updated.
pub fn service_args(args: &Args) -> Vec<String> {
    let mut out = Vec::new();

    if args.no_check_update {
        out.push("--no-check-update".to_string());
    }

    out.push("-c".to_string());
    out.push(absolute(&args.config_or_default()));
    out.push("-w".to_string());
    out.push(absolute(&args.work_dir_or_default()));

    if args.verbose {
        out.push("--verbose".to_string());
    }
    if let Some(l) = &args.logfile {
        out.push("-l".to_string());
        out.push(l.clone());
    }
    if let Some(p) = &args.pidfile {
        out.push("--pidfile".to_string());
        out.push(absolute(p));
    }

    out
}

/// Renders a path absolutely, leaving it alone if that is not possible.
fn absolute(p: &Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| {
            std::env::current_dir()
                .map(|d| d.join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        })
        .display()
        .to_string()
}

/// The systemd unit for a binary and its arguments.
pub fn systemd_unit(exe: &str, args: &[String]) -> String {
    let quoted: Vec<String> = args.iter().map(|a| format!("{a:?}")).collect();

    format!(
        "[Unit]\n\
         Description=AdGuard Home: Network-level blocker\n\
         ConditionFileIsExecutable={exe}\n\
         After=syslog.target network-online.target\n\
         \n\
         [Service]\n\
         StartLimitInterval=5\n\
         StartLimitBurst=10\n\
         ExecStart={exe} {}\n\
         Restart=always\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        quoted.join(" ")
    )
}

/// The launchd property list for a binary and its arguments.
pub fn launchd_plist(exe: &str, args: &[String]) -> String {
    let mut items = String::new();
    for a in std::iter::once(&exe.to_string()).chain(args) {
        items.push_str(&format!("    <string>{}</string>\n", escape_xml(a)));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \x20 <key>Label</key><string>com.adguard.AdGuardHome</string>\n\
         \x20 <key>ProgramArguments</key>\n\
         \x20 <array>\n{items}\
         \x20 </array>\n\
         \x20 <key>RunAtLoad</key><true/>\n\
         \x20 <key>KeepAlive</key><true/>\n\
         </dict>\n\
         </plist>\n"
    )
}

/// Escapes the characters XML cannot carry literally.
fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Writes the unit file and enables the service.
fn install(init: Init, args: &Args) -> Result<String, Error> {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .map_err(|source| Error::Io {
            what: "finding this executable".into(),
            source,
        })?;
    let service_args = service_args(args);

    let path = init.unit_path();
    let text = match init {
        Init::Systemd => systemd_unit(&exe, &service_args),
        Init::Launchd => launchd_plist(&exe, &service_args),
    };

    write(&path, &text)?;

    match init {
        Init::Systemd => {
            exec("systemctl", &["daemon-reload"])?;
            exec("systemctl", &["enable", NAME])?;
        }
        Init::Launchd => {
            exec("launchctl", &["load", "-w", &path.display().to_string()])?;
        }
    }

    Ok(format!(
        "installed the {init} service; unit written to {}",
        path.display()
    ))
}

/// Stops the service and removes its unit file.
fn uninstall(init: Init) -> Result<String, Error> {
    let path = init.unit_path();

    match init {
        Init::Systemd => {
            // Stopping a service that is not running is not a failure worth
            // reporting; removing the unit is what was asked for.
            let _ = exec("systemctl", &["stop", NAME]);
            let _ = exec("systemctl", &["disable", NAME]);
        }
        Init::Launchd => {
            let _ = exec("launchctl", &["unload", "-w", &path.display().to_string()]);
        }
    }

    if path.exists() {
        std::fs::remove_file(&path).map_err(|source| Error::Io {
            what: format!("removing {}", path.display()),
            source,
        })?;
    }

    if init == Init::Systemd {
        let _ = exec("systemctl", &["daemon-reload"]);
    }

    Ok(format!("removed the {init} service"))
}

/// Hands start, stop, restart, reload or status to the init system.
fn control(init: Init, action: &str) -> Result<String, Error> {
    let path = init.unit_path().display().to_string();

    let out = match (init, action) {
        (Init::Systemd, a) => exec("systemctl", &[a, NAME])?,
        (Init::Launchd, "start") => exec("launchctl", &["load", "-w", &path])?,
        (Init::Launchd, "stop") => exec("launchctl", &["unload", "-w", &path])?,
        (Init::Launchd, "restart") => {
            let _ = exec("launchctl", &["unload", "-w", &path]);

            exec("launchctl", &["load", "-w", &path])?
        }
        // launchd has no reload; a restart is the closest thing.
        (Init::Launchd, "reload") => {
            let _ = exec("launchctl", &["unload", "-w", &path]);

            exec("launchctl", &["load", "-w", &path])?
        }
        (Init::Launchd, _) => exec("launchctl", &["list", "com.adguard.AdGuardHome"])?,
    };

    Ok(if out.trim().is_empty() {
        format!("{action}: ok")
    } else {
        out
    })
}

/// Writes a unit file, creating its directory.
fn write(path: &Path, text: &str) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|source| Error::Io {
            what: format!("creating {}", dir.display()),
            source,
        })?;
    }

    std::fs::write(path, text).map_err(|source| Error::Io {
        what: format!("writing {}", path.display()),
        source,
    })
}

/// Runs an init-system command and returns what it printed.
fn exec(program: &str, args: &[&str]) -> Result<String, Error> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| Error::Io {
            what: format!("running {program}"),
            source,
        })?;

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() {
        return Ok(stdout);
    }

    let stderr = String::from_utf8_lossy(&out.stderr);

    Err(Error::Command {
        command: format!("{program} {}", args.join(" ")),
        output: if stderr.trim().is_empty() {
            stdout
        } else {
            stderr.into_owned()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn an_unknown_action_is_refused() {
        let args = Args::parse_from(["AdGuardHome"]);
        let err = run("frobnicate", &args).unwrap_err();
        assert!(matches!(err, Error::UnknownAction { .. }));
    }

    #[test]
    fn the_documented_actions_are_accepted() {
        assert_eq!(ACTIONS.len(), 7);
        for a in [
            "install",
            "uninstall",
            "start",
            "stop",
            "restart",
            "reload",
            "status",
        ] {
            assert!(ACTIONS.contains(&a), "{a} should be an action");
        }
    }

    #[test]
    fn the_service_runs_with_the_same_paths_this_invocation_used() {
        let args = Args::parse_from([
            "AdGuardHome",
            "--no-check-update",
            "-c",
            "/opt/adguardhome/conf/AdGuardHome.yaml",
            "-w",
            "/opt/adguardhome/work",
        ]);
        let got = service_args(&args);

        assert!(
            got.contains(&"--no-check-update".to_string()),
            "it was given, so it is passed on"
        );
        assert!(
            got.windows(2)
                .any(|w| w[0] == "-c" && w[1].ends_with("AdGuardHome.yaml"))
        );
        assert!(got.windows(2).any(|w| w[0] == "-w"));
    }

    #[test]
    fn the_unit_only_switches_the_release_check_off_if_asked_to() {
        // Writing --no-check-update into every generated unit switched the
        // check off for every natively installed server, and with it the
        // update button, which has nothing to offer without a check.
        let args = Args::parse_from(["AdGuardHome", "-w", "/srv/agh"]);

        assert!(!service_args(&args).contains(&"--no-check-update".to_string()));
    }

    #[test]
    fn the_systemd_unit_names_the_binary_and_restarts_it() {
        let unit = systemd_unit(
            "/opt/adguardhome/AdGuardHome",
            &["-c".into(), "/c.yaml".into()],
        );

        assert!(unit.contains("ExecStart=/opt/adguardhome/AdGuardHome"));
        assert!(unit.contains("Restart=always"));
        assert!(unit.contains("WantedBy=multi-user.target"));
        assert!(
            unit.contains("\"-c\" \"/c.yaml\""),
            "arguments are quoted so a path with spaces survives: {unit}"
        );
    }

    #[test]
    fn the_launchd_plist_lists_the_binary_first() {
        let plist = launchd_plist("/opt/AdGuardHome", &["-c".into(), "/c.yaml".into()]);

        assert!(plist.contains("<string>/opt/AdGuardHome</string>"));
        assert!(plist.contains("<string>-c</string>"));
        assert!(plist.contains("com.adguard.AdGuardHome"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
    }

    #[test]
    fn xml_special_characters_are_escaped() {
        let plist = launchd_plist("/opt/a&b", &["<x>".into()]);
        assert!(plist.contains("/opt/a&amp;b"));
        assert!(plist.contains("&lt;x&gt;"));
    }

    #[test]
    fn the_unit_path_matches_the_init_system() {
        assert!(Init::Systemd.unit_path().ends_with("AdGuardHome.service"));
        assert!(
            Init::Launchd
                .unit_path()
                .ends_with("com.adguard.AdGuardHome.plist")
        );
    }
}
