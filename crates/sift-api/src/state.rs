//! Shared state for the HTTP API.

use std::sync::Arc;

use jiff::Timestamp;
use parking_lot::RwLock;
use sift_config::{Config, Paths};
use sift_dns::resolver::Resolver;
use sift_filter::lists::Manager;
use sift_querylog::log::QueryLog;
use sift_stats::stats::Stats;

/// A future returned by a list fetch.
pub type FetchFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>;

/// Downloads filter lists.
///
/// Implemented by the binary so this crate needs no HTTP client of its own.
pub trait ListFetcher: Send + Sync + 'static {
    /// Fetches the contents of a list.
    fn fetch(&self, url: String) -> FetchFuture;
}

/// A fetcher that always fails, for tests.
pub struct NoFetcher;

impl ListFetcher for NoFetcher {
    fn fetch(&self, _url: String) -> FetchFuture {
        Box::pin(async { Err("downloading is not available".to_string()) })
    }
}

/// A future returned by a version check.
pub type VersionFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, String>> + Send>>;

/// Fetches the release announcement.
///
/// Implemented by the binary so this crate needs no HTTP client of its own.
pub trait VersionChecker: Send + Sync + 'static {
    /// Downloads the announcement document.
    fn fetch(&self) -> VersionFuture;

    /// Reports whether checking is switched off, by `--no-check-update`.
    fn disabled(&self) -> bool;
}

/// A checker that reports the feature as switched off, for tests.
pub struct NoVersionCheck;

impl VersionChecker for NoVersionCheck {
    fn fetch(&self) -> VersionFuture {
        Box::pin(async { Err("version checking is not available".to_string()) })
    }

    fn disabled(&self) -> bool {
        true
    }
}

/// A future returned by a self-update.
pub type UpdateFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

/// Replaces this binary with a published release.
///
/// Implemented by the binary, which is the only part of the tree that knows
/// where it lives on disk, can download an archive, and can hand its process
/// over to what it downloaded.
pub trait SelfUpdater: Send + Sync + 'static {
    /// Reports whether replacing the binary could work on this machine.
    ///
    /// `needs_privileged_ports` says whether the running configuration binds
    /// anything below 1024; the answer is no if a restart could not bind them
    /// again, because an update that leaves the resolver unable to start is
    /// worse than no update.
    fn can_update(&self, needs_privileged_ports: bool) -> bool;

    /// Downloads `version` and puts it in place of the running binary.
    ///
    /// Returns once the file has been replaced.  The process is still the old
    /// one until [`SelfUpdater::restart`] is called.
    fn update(&self, version: String) -> UpdateFuture;

    /// Hands this process over to the new binary.
    ///
    /// Returns only on failure, with what went wrong: on success this image no
    /// longer exists.
    fn restart(&self) -> String;
}

/// An updater that refuses, for tests and for builds that cannot update.
pub struct NoSelfUpdate;

impl SelfUpdater for NoSelfUpdate {
    fn can_update(&self, _needs_privileged_ports: bool) -> bool {
        false
    }

    fn update(&self, _version: String) -> UpdateFuture {
        Box::pin(async { Err("updating is not available in this build".to_string()) })
    }

    fn restart(&self) -> String {
        "updating is not available in this build".to_string()
    }
}

/// Applies configuration changes to the running server.
///
/// The API mutates the config; something has to push those changes into the
/// resolver, the listeners and the collectors.  The binary owns that wiring.
pub trait Reloader: Send + Sync + 'static {
    /// Called after the configuration changed and was saved.
    fn reload(&self, cfg: &Config);

    /// Called after the filter lists changed.
    fn reload_filters(&self, filters: &Manager);
}

/// A reloader that does nothing, for tests.
pub struct NoReloader;

impl Reloader for NoReloader {
    fn reload(&self, _cfg: &Config) {}
    fn reload_filters(&self, _filters: &Manager) {}
}

/// Everything the handlers need.
pub struct AppState {
    /// Where things live on disk.
    pub paths: Paths,
    /// The current configuration.
    pub config: RwLock<Config>,
    /// The resolver, for cache control and protection state.
    pub resolver: Arc<Resolver>,
    /// The DNS front end, so DNS-over-HTTPS takes the same path as UDP and
    /// TCP: the same rate limits, access control, query log and statistics.
    pub dns_server: Arc<sift_dns::server::Server>,
    /// The filter lists.
    pub filters: RwLock<Manager>,
    /// The query log.
    pub querylog: Arc<QueryLog>,
    /// The statistics collector.
    pub stats: Arc<Stats>,
    /// Web sessions.
    pub sessions: crate::auth::Sessions,
    /// Throttles password guessing, against the login form and against the
    /// Basic credentials every other endpoint accepts.
    pub login_limiter: crate::auth::LoginLimiter,
    /// When the server started.
    pub started: Timestamp,
    /// Downloads filter lists.
    pub fetcher: Arc<dyn ListFetcher>,
    /// Pushes configuration changes into the running server.
    pub reloader: Arc<dyn Reloader>,
    /// The addresses the DNS server listens on, for `/control/status`.
    pub dns_addresses: RwLock<Vec<String>>,
    /// Checks for a newer release.
    pub version: Arc<dyn VersionChecker>,
    /// Replaces this binary with one.
    pub updater: Arc<dyn SelfUpdater>,
    /// The last announcement seen, and when it was fetched.
    ///
    /// Upstream rechecks at most every eight hours; asking the announcement
    /// server on every page load would be rude and slow.
    pub version_cache: RwLock<Option<(Timestamp, serde_json::Value)>>,
}

impl AppState {
    /// Saves the configuration and tells the server to pick it up.
    ///
    /// Returns an error string suitable for an HTTP 500 body.
    pub fn save_config(&self) -> Result<(), String> {
        let cfg = self.config.read().clone();
        sift_config::save(&self.paths.config, &cfg).map_err(|e| e.to_string())?;
        self.reloader.reload(&cfg);

        Ok(())
    }

    /// Rebuilds the filtering engine from the current lists, and saves the
    /// list configuration.
    pub fn save_filters(&self) -> Result<(), String> {
        {
            let filters = self.filters.read();
            let mut cfg = self.config.write();
            cfg.filters = filters.blocklists.iter().map(|l| l.to_config()).collect();
            cfg.whitelist_filters = filters.allowlists.iter().map(|l| l.to_config()).collect();
            cfg.user_rules = filters.user_rules.clone();
        }

        self.save_config()?;
        self.reloader.reload_filters(&self.filters.read());

        Ok(())
    }

    /// How long protection stays off, in milliseconds, or zero.
    ///
    /// Read from the deadline rather than counted down, so a pause survives a
    /// restart: one set before the process went down still ends when it was
    /// meant to, not `duration` milliseconds after it came back.
    pub fn protection_pause_left(&self) -> i64 {
        let cfg = self.config.read();
        if cfg.filtering.protection_enabled {
            return 0;
        }

        pause_left(
            cfg.filtering.protection_disabled_until.as_deref(),
            jiff::Timestamp::now(),
        )
    }

    /// Turns protection back on if its pause has elapsed.
    ///
    /// Driven from the maintenance tick rather than from the query path: a
    /// pause runs to minutes, and checking a deadline on every DNS query to
    /// notice a second sooner is not a trade worth making.  Returns whether
    /// anything changed.
    pub fn expire_protection_pause(&self) -> bool {
        {
            let cfg = self.config.read();
            if cfg.filtering.protection_enabled || cfg.filtering.protection_disabled_until.is_none()
            {
                return false;
            }
        }

        if self.protection_pause_left() > 0 {
            return false;
        }

        {
            let mut cfg = self.config.write();
            cfg.filtering.protection_enabled = true;
            cfg.filtering.protection_disabled_until = None;
        }

        // Saving pushes the new settings into the resolver; see `save_config`.
        if let Err(e) = self.save_config() {
            tracing::warn!(error = %e, "re-enabling protection after its pause");

            return false;
        }

        tracing::info!("protection re-enabled: its pause elapsed");

        true
    }

    /// Reports whether the installation still needs the setup wizard.
    pub fn needs_install(&self) -> bool {
        self.config.read().users.is_empty()
    }
}

/// A reference-counted state handle, as axum passes it to handlers.
pub type Shared = Arc<AppState>;

/// How long a pause has left at `now`, in milliseconds.
///
/// Zero for a deadline that has passed, is missing, or cannot be parsed: the
/// caller's question is "how much longer", and every one of those means none.
pub fn pause_left(until: Option<&str>, now: jiff::Timestamp) -> i64 {
    let Some(until) = until.and_then(sift_core::gotime::parse_rfc3339) else {
        return 0;
    };

    (until.as_millisecond() - now.as_millisecond()).max(0)
}

/// The deadline to store for a protection change.
///
/// `None` for every case that has no end: protection being turned *on*, and
/// protection being turned off with no duration or a zero one.  Returning a
/// stale deadline in those cases would turn protection back on by itself.
pub fn pause_deadline(
    enabled: bool,
    duration: Option<u64>,
    now: jiff::Timestamp,
) -> Option<String> {
    match duration {
        Some(ms) if !enabled && ms > 0 => Some(sift_core::gotime::format_utc(
            now + std::time::Duration::from_millis(ms),
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> jiff::Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn a_pause_counts_down_from_its_deadline() {
        let now = at("2026-01-01T00:00:00Z");

        assert_eq!(pause_left(Some("2026-01-01T00:00:30Z"), now), 30_000);
        assert_eq!(pause_left(Some("2026-01-01T01:00:00Z"), now), 3_600_000);
    }

    #[test]
    fn an_elapsed_pause_has_nothing_left() {
        // Never negative: the interface renders this as a countdown, and a
        // negative one would read as time owed.
        let now = at("2026-01-01T00:00:00Z");

        assert_eq!(pause_left(Some("2025-12-31T23:59:30Z"), now), 0);
        assert_eq!(pause_left(Some("2026-01-01T00:00:00Z"), now), 0);
    }

    #[test]
    fn a_missing_or_broken_deadline_has_nothing_left() {
        let now = at("2026-01-01T00:00:00Z");

        assert_eq!(pause_left(None, now), 0);
        assert_eq!(pause_left(Some(""), now), 0);
        assert_eq!(pause_left(Some("not a time"), now), 0);
    }

    #[test]
    fn a_deadline_is_stored_only_for_a_timed_pause() {
        let now = at("2026-01-01T00:00:00Z");

        // Off for a while: a deadline that far ahead.
        let until = pause_deadline(false, Some(30_000), now).expect("a timed pause has a deadline");
        assert_eq!(pause_left(Some(&until), now), 30_000);

        // Off with no end named, and off for no time at all.
        assert_eq!(pause_deadline(false, None, now), None);
        assert_eq!(pause_deadline(false, Some(0), now), None);

        // Turning protection *on* clears it, duration or not -- a leftover
        // deadline would later turn protection on again by itself, which the
        // user has already done.
        assert_eq!(pause_deadline(true, None, now), None);
        assert_eq!(pause_deadline(true, Some(30_000), now), None);
    }

    #[test]
    fn a_deadline_survives_being_read_back_later() {
        // The pause is stored as a moment, not a length, so a restart part
        // way through resumes rather than starting over.
        let set_at = at("2026-01-01T00:00:00Z");
        let until = pause_deadline(false, Some(60_000), set_at).unwrap();

        assert_eq!(pause_left(Some(&until), at("2026-01-01T00:00:45Z")), 15_000);
        assert_eq!(pause_left(Some(&until), at("2026-01-01T00:01:30Z")), 0);
    }
}
