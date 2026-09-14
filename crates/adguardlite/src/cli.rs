//! Command-line interface, matching the Go binary's flags.
//!
//! The Docker image invokes the binary as
//! `AdGuardHome --no-check-update -c <conf> -w <work>`, so those three must
//! keep working exactly as they do upstream.

use std::path::PathBuf;

use clap::Parser;

/// Network-wide ads and trackers blocking DNS server.
#[derive(Parser, Debug, Clone)]
#[command(name = "AdGuardHome", version, disable_help_flag = false)]
pub struct Args {
    /// Path to the config file.
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// Path to the working directory.
    #[arg(short = 'w', long = "work-dir")]
    pub work_dir: Option<PathBuf>,

    /// Address to serve the web UI on, in the host:port format.
    #[arg(long = "web-addr")]
    pub web_addr: Option<String>,

    /// Deprecated.  Host address to bind the HTTP server on.
    #[arg(long = "host")]
    pub host: Option<String>,

    /// Deprecated.  Port to serve HTTP pages on.
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    /// Path to the log file.  Empty writes to stdout; "syslog" writes to the
    /// system log.
    #[arg(short = 'l', long = "logfile")]
    pub logfile: Option<String>,

    /// Path to a file where the process ID is stored.
    #[arg(long = "pidfile")]
    pub pidfile: Option<PathBuf>,

    /// Check the configuration and exit.
    #[arg(long = "check-config")]
    pub check_config: bool,

    /// Do not check for updates.
    #[arg(long = "no-check-update")]
    pub no_check_update: bool,

    /// Deprecated.  Disable memory optimization.
    #[arg(long = "no-mem-optimization")]
    pub no_mem_optimization: bool,

    /// Deprecated.  Do not use the OS-provided hosts file.
    #[arg(long = "no-etc-hosts")]
    pub no_etc_hosts: bool,

    /// Use local frontend directories.
    #[arg(long = "local-frontend")]
    pub local_frontend: bool,

    /// Enable verbose output.
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Run in GL-Inet compatibility mode.
    #[arg(long = "glinet")]
    pub glinet: bool,

    /// Skip checking and migration of permissions of sensitive files.
    #[arg(long = "no-permcheck")]
    pub no_permcheck: bool,

    /// Service control action: status, install, uninstall, start, stop,
    /// restart, reload.
    #[arg(short = 's', long = "service")]
    pub service: Option<String>,

    /// Update the current binary and restart the service.
    #[arg(long = "update")]
    pub update: bool,
}

impl Args {
    /// The working directory, defaulting to the current one.
    pub fn work_dir_or_default(&self) -> PathBuf {
        self.work_dir
            .clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }

    /// The config path, defaulting to `AdGuardHome.yaml` in the working
    /// directory.
    pub fn config_or_default(&self) -> PathBuf {
        self.config
            .clone()
            .unwrap_or_else(|| self.work_dir_or_default().join("AdGuardHome.yaml"))
    }

    /// The web address requested on the command line, if any.
    ///
    /// `--web-addr` wins; the deprecated `--host`/`--port` pair is honoured
    /// for compatibility.
    pub fn web_override(&self) -> Option<String> {
        if let Some(a) = &self.web_addr {
            return Some(a.clone());
        }

        match (&self.host, self.port) {
            (Some(h), Some(p)) => Some(format!("{h}:{p}")),
            (Some(h), None) => Some(format!("{h}:3000")),
            (None, Some(p)) => Some(format!("0.0.0.0:{p}")),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_docker_command_line() {
        // Exactly what docker/build.Dockerfile's CMD passes.
        let a = Args::parse_from([
            "AdGuardHome",
            "--no-check-update",
            "-c",
            "/opt/adguardhome/conf/AdGuardHome.yaml",
            "-w",
            "/opt/adguardhome/work",
        ]);

        assert!(a.no_check_update);
        assert_eq!(
            a.config.unwrap().to_str().unwrap(),
            "/opt/adguardhome/conf/AdGuardHome.yaml"
        );
        assert_eq!(
            a.work_dir.unwrap().to_str().unwrap(),
            "/opt/adguardhome/work"
        );
    }

    #[test]
    fn config_defaults_into_the_work_dir() {
        let a = Args::parse_from(["AdGuardHome", "-w", "/srv/agh"]);
        assert_eq!(
            a.config_or_default().to_str().unwrap(),
            "/srv/agh/AdGuardHome.yaml"
        );
    }

    #[test]
    fn web_address_overrides() {
        let a = Args::parse_from(["AdGuardHome", "--web-addr", "127.0.0.1:8080"]);
        assert_eq!(a.web_override().as_deref(), Some("127.0.0.1:8080"));

        let a = Args::parse_from(["AdGuardHome", "--host", "127.0.0.1", "-p", "8080"]);
        assert_eq!(a.web_override().as_deref(), Some("127.0.0.1:8080"));

        let a = Args::parse_from(["AdGuardHome", "-p", "8080"]);
        assert_eq!(a.web_override().as_deref(), Some("0.0.0.0:8080"));

        let a = Args::parse_from(["AdGuardHome"]);
        assert_eq!(a.web_override(), None);
    }

    #[test]
    fn accepts_every_flag_the_go_binary_documents() {
        // A parse failure here would break an existing user's invocation.
        let a = Args::parse_from([
            "AdGuardHome",
            "--no-check-update",
            "--no-permcheck",
            "--check-config",
            "--local-frontend",
            "--glinet",
            "--verbose",
            "--no-mem-optimization",
            "--no-etc-hosts",
            "--pidfile",
            "/run/agh.pid",
            "-l",
            "syslog",
            "-s",
            "status",
        ]);

        assert!(a.check_config);
        assert!(a.verbose);
        assert_eq!(a.service.as_deref(), Some("status"));
        assert_eq!(a.logfile.as_deref(), Some("syslog"));
    }
}
