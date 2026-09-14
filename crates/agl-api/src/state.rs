//! Shared state for the HTTP API.

use std::sync::Arc;

use agl_config::{Config, Paths};
use agl_dns::resolver::Resolver;
use agl_filter::lists::Manager;
use agl_querylog::log::QueryLog;
use agl_stats::stats::Stats;
use jiff::Timestamp;
use parking_lot::RwLock;

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
    pub dns_server: Arc<agl_dns::server::Server>,
    /// The filter lists.
    pub filters: RwLock<Manager>,
    /// The query log.
    pub querylog: Arc<QueryLog>,
    /// The statistics collector.
    pub stats: Arc<Stats>,
    /// Web sessions.
    pub sessions: crate::auth::Sessions,
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
        agl_config::save(&self.paths.config, &cfg).map_err(|e| e.to_string())?;
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

    /// Reports whether the installation still needs the setup wizard.
    pub fn needs_install(&self) -> bool {
        self.config.read().users.is_empty()
    }
}

/// A reference-counted state handle, as axum passes it to handlers.
pub type Shared = Arc<AppState>;
