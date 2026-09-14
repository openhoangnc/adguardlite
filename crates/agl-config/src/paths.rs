//! The on-disk layout of the working directory.
//!
//! This must match the Go implementation exactly, because an existing
//! installation's data lives here:
//!
//! ```text
//! <work>/data/querylog.json          the current query log
//! <work>/data/querylog.json.1        the rotated one
//! <work>/data/stats.db               the statistics database
//! <work>/data/sessions.db            web sessions
//! <work>/data/filters/<id>.txt       downloaded filter lists
//! <work>/data/userfilters/           filesystem-backed user lists
//! ```

use std::path::{Path, PathBuf};

/// Resolved paths for one installation.
#[derive(Clone, Debug)]
pub struct Paths {
    /// The working directory.
    pub work: PathBuf,
    /// The configuration file.
    pub config: PathBuf,
}

impl Paths {
    /// Builds the layout for a working directory and config file.
    pub fn new(work: impl Into<PathBuf>, config: impl Into<PathBuf>) -> Self {
        Self {
            work: work.into(),
            config: config.into(),
        }
    }

    /// The data directory.
    pub fn data(&self) -> PathBuf {
        self.work.join("data")
    }

    /// The directory holding downloaded filter lists.
    pub fn filters(&self) -> PathBuf {
        self.data().join("filters")
    }

    /// The directory holding filesystem-backed user lists.
    pub fn user_filters(&self) -> PathBuf {
        self.data().join("userfilters")
    }

    /// The file a filter list with the given identifier is stored in.
    pub fn filter_file(&self, id: i64) -> PathBuf {
        self.filters().join(format!("{id}.txt"))
    }

    /// The query log, honouring a configured override directory.
    pub fn query_log(&self, dir_override: &str) -> PathBuf {
        self.dir_or_data(dir_override).join("querylog.json")
    }

    /// The rotated query log.
    pub fn query_log_rotated(&self, dir_override: &str) -> PathBuf {
        self.dir_or_data(dir_override).join("querylog.json.1")
    }

    /// The statistics database, honouring a configured override directory.
    pub fn stats_db(&self, dir_override: &str) -> PathBuf {
        self.dir_or_data(dir_override).join("stats.db")
    }

    /// The web session database.
    pub fn sessions_db(&self) -> PathBuf {
        self.data().join("sessions.db")
    }

    /// Returns the override directory if set, else the data directory.
    fn dir_or_data(&self, dir_override: &str) -> PathBuf {
        if dir_override.is_empty() {
            self.data()
        } else {
            PathBuf::from(dir_override)
        }
    }

    /// Creates the directories an installation needs, with upstream's mode.
    ///
    /// `0o700`, as `aghos.DefaultPermDir` is: the data directory holds
    /// `querylog.json`, which is every name every client looked up.
    pub fn ensure(&self) -> std::io::Result<()> {
        agl_core::perms::create_dir_all(self.filters())?;
        agl_core::perms::create_dir_all(self.user_filters())?;
        if let Some(parent) = self.config.parent() {
            agl_core::perms::create_dir_all(parent)?;
        }

        Ok(())
    }

    /// Reports whether this looks like a fresh installation.
    pub fn is_first_run(&self) -> bool {
        !Path::new(&self.config).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        Paths::new(
            "/opt/adguardhome/work",
            "/opt/adguardhome/conf/AdGuardHome.yaml",
        )
    }

    #[test]
    fn matches_the_docker_image_layout() {
        let p = paths();
        assert_eq!(p.data().to_str().unwrap(), "/opt/adguardhome/work/data");
        assert_eq!(
            p.filters().to_str().unwrap(),
            "/opt/adguardhome/work/data/filters"
        );
        assert_eq!(
            p.filter_file(1).to_str().unwrap(),
            "/opt/adguardhome/work/data/filters/1.txt"
        );
        assert_eq!(
            p.query_log("").to_str().unwrap(),
            "/opt/adguardhome/work/data/querylog.json"
        );
        assert_eq!(
            p.query_log_rotated("").to_str().unwrap(),
            "/opt/adguardhome/work/data/querylog.json.1"
        );
        assert_eq!(
            p.stats_db("").to_str().unwrap(),
            "/opt/adguardhome/work/data/stats.db"
        );
        assert_eq!(
            p.sessions_db().to_str().unwrap(),
            "/opt/adguardhome/work/data/sessions.db"
        );
    }

    #[test]
    fn honours_the_configured_override_directories() {
        let p = paths();
        assert_eq!(
            p.query_log("/var/log/agh").to_str().unwrap(),
            "/var/log/agh/querylog.json"
        );
        assert_eq!(
            p.stats_db("/var/lib/agh").to_str().unwrap(),
            "/var/lib/agh/stats.db"
        );
    }

    #[test]
    fn detects_a_fresh_installation() {
        let p = Paths::new("/nonexistent/work", "/nonexistent/conf/AdGuardHome.yaml");
        assert!(p.is_first_run());
    }
}
