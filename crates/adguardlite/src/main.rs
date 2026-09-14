//! adguardlite — a drop-in Rust backend for AdGuard Home.

mod app;
mod cli;
mod fetch;
mod lists;
mod wiring;

use std::sync::Arc;
use std::time::Duration;

use agl_api::state::{AppState, Shared};
use agl_config::Paths;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::app::App;
use crate::cli::Args;

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    init_logging(&args);

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("adguardlite: starting the runtime: {e}");

            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal");

            std::process::ExitCode::FAILURE
        }
    }
}

/// Configures tracing from the flags and the environment.
///
/// The default filter sets a global level rather than naming this crate: the
/// binary target is `AdGuardHome`, so `module_path!` reports that rather than
/// the package name, and a per-crate filter spelled `adguardlite=info` would
/// silently drop every message the server logs.
fn init_logging(args: &Args) {
    let default = if args.verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Quiet the dependencies that are chatty at these levels.
        EnvFilter::new(format!(
            "{default},hyper=warn,rustls=warn,h2=warn,hickory_proto=warn,tokio_util=warn"
        ))
    });

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

/// Starts the server and runs until a shutdown signal arrives.
async fn run(args: Args) -> anyhow::Result<()> {
    // rustls needs a process-wide crypto provider before any TLS is set up.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let paths = Paths::new(args.work_dir_or_default(), args.config_or_default());
    let mut config = app::load_or_init(&paths)?;

    if let Some(addr) = args.web_override()
        && let Ok(parsed) = addr.parse::<std::net::SocketAddr>()
    {
        config.http.address = agl_config::types::AddrPort(parsed);
    }

    if args.check_config {
        println!("configuration at {} is valid", paths.config.display());

        return Ok(());
    }

    tracing::info!(
        version = agl_core::AGH_VERSION,
        config = %paths.config.display(),
        work_dir = %paths.work.display(),
        "starting adguardlite"
    );

    // The query log and statistics are shared between the DNS observer and the
    // HTTP API, so they are built before either.
    let querylog = Arc::new(agl_querylog::log::QueryLog::new(
        paths.query_log(&config.querylog.dir_path),
        paths.query_log_rotated(&config.querylog.dir_path),
        agl_querylog::log::Config {
            enabled: config.querylog.enabled,
            file_enabled: config.querylog.file_enabled,
            size_memory: config.querylog.size_memory as usize,
            ignored: config.querylog.ignored.clone(),
            ignored_enabled: config.querylog.ignored_enabled,
            anonymize_client_ip: config.dns.anonymize_client_ip,
        },
    ));

    let stats = Arc::new(agl_stats::stats::Stats::new(agl_stats::stats::Config {
        enabled: config.statistics.enabled,
        limit_hours: config.statistics.interval.as_hours().max(0) as u32,
        ignored: config.statistics.ignored.clone(),
        ignored_enabled: config.statistics.ignored_enabled,
    }));

    // Pick up the statistics a previous run left behind, including one
    // written by the Go implementation.
    let stats_path = paths.stats_db(&config.statistics.dir_path);
    match agl_stats::store::load(&stats_path) {
        Ok(units) if !units.is_empty() => {
            tracing::info!(units = units.len(), "loaded statistics");
            stats.load(units);
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, path = %stats_path.display(), "loading statistics"),
    }

    let recorder = Arc::new(wiring::Recorder::new(
        querylog.clone(),
        stats.clone(),
        config.dns.anonymize_client_ip,
    ));

    let web_addr = config.http.address.0;
    let max_list_bytes = config.filtering.max_http_size.bytes();

    let application = App::build(paths.clone(), config, recorder).await?;

    tracing::info!(
        rules = application.filters.rules_count(),
        lists = application.filters.blocklists.len() + application.filters.allowlists.len(),
        "filter lists loaded"
    );

    let dns_addrs: Vec<String> = application
        .dns_addrs()
        .iter()
        .map(|a| a.to_string())
        .collect();

    let state: Shared = Arc::new(AppState {
        paths: application.paths.clone(),
        config: parking_lot::RwLock::new(application.config.clone()),
        resolver: application.resolver.clone(),
        filters: parking_lot::RwLock::new(application.filters.clone()),
        querylog: querylog.clone(),
        stats: stats.clone(),
        sessions: agl_api::auth::Sessions::new(),
        started: jiff::Timestamp::now(),
        fetcher: Arc::new(wiring::Downloader {
            paths: application.paths.clone(),
            max_bytes: max_list_bytes,
            timeout: app::LIST_TIMEOUT,
        }),
        reloader: Arc::new(wiring::LiveReloader {
            resolver: application.resolver.clone(),
        }),
        dns_addresses: parking_lot::RwLock::new(dns_addrs),
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = application.serve_dns(shutdown_rx.clone()).await?;

    for addr in application.dns_addrs() {
        tracing::info!(%addr, "serving dns");
    }

    // The web interface.
    let listener = tokio::net::TcpListener::bind(web_addr).await?;
    tracing::info!(addr = %web_addr, "serving web interface");
    if state.needs_install() {
        tracing::info!("no user configured yet; open the web interface to finish setup");
    }

    let app_router = agl_api::routes::router(state.clone());
    let mut web_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        let _ = axum::serve(listener, app_router)
            .with_graceful_shutdown(async move {
                let _ = web_shutdown.changed().await;
            })
            .await;
    }));

    // Periodic maintenance: flush the log, prune statistics, refresh lists.
    tasks.push(tokio::spawn(maintenance(
        state.clone(),
        stats_path.clone(),
        shutdown_rx.clone(),
    )));

    wait_for_shutdown().await;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);

    // Persist whatever is still buffered before the process exits.
    if let Err(e) = querylog.flush() {
        tracing::warn!(error = %e, "flushing the query log");
    }
    if let Err(e) = agl_stats::store::save(&stats_path, &stats.snapshot()) {
        tracing::warn!(error = %e, "saving statistics");
    }

    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }

    Ok(())
}

/// Runs the periodic upkeep the server needs.
async fn maintenance(
    state: Shared,
    stats_path: std::path::PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut minutes: u64 = 0;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }

        minutes += 1;

        if let Err(e) = state.querylog.flush() {
            tracing::warn!(error = %e, "flushing the query log");
        }
        state.stats.prune();
        state.sessions.sweep();

        if let Err(e) = agl_stats::store::save(&stats_path, &state.stats.snapshot()) {
            tracing::warn!(error = %e, "saving statistics");
        }

        // Refresh filter lists on the configured interval.
        let hours = state.config.read().filtering.filters_update_interval;
        if hours > 0 && minutes.is_multiple_of(u64::from(hours) * 60) {
            refresh_lists(&state).await;
        }
    }
}

/// Downloads every enabled list and rebuilds the engine.
async fn refresh_lists(state: &Shared) {
    let ids = state.filters.read().enabled_ids();
    let mut updated = 0;

    for id in ids {
        let Some(url) = state.filters.read().url_of(id) else {
            continue;
        };
        match state.fetcher.fetch(url.clone()).await {
            Ok(text) => {
                let mut filters = state.filters.write();
                if filters.apply_fetched(&state.paths, id, text).is_ok() {
                    updated += 1;
                }
            }
            Err(e) => tracing::warn!(list = id, %url, error = %e, "refreshing filter list"),
        }
    }

    if updated > 0 {
        tracing::info!(updated, "filter lists refreshed");
        if let Err(e) = state.save_filters() {
            tracing::warn!(error = %e, "saving filter lists");
        }
    }
}

/// Resolves when the process is asked to stop.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;

                return;
            }
        };

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use tracing::Level;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::{EnvFilter, Registry};

    /// The default filter, as `init_logging` builds it when RUST_LOG is unset.
    fn default_filter(verbose: bool) -> EnvFilter {
        let default = if verbose { "debug" } else { "info" };

        EnvFilter::new(format!(
            "{default},hyper=warn,rustls=warn,h2=warn,hickory_proto=warn,tokio_util=warn"
        ))
    }

    /// Reports whether the filter would let an INFO event from `target`
    /// through.
    fn enables(filter: EnvFilter, target: &str, level: Level) -> bool {
        use tracing::subscriber::with_default;

        let subscriber = Registry::default().with(filter);
        with_default(subscriber, || {
            tracing::dispatcher::get_default(|d| {
                let meta = tracing::Metadata::new(
                    "probe",
                    target,
                    level,
                    None,
                    None,
                    None,
                    tracing::field::FieldSet::new(&[], tracing::callsite::Identifier(&PROBE)),
                    tracing::metadata::Kind::EVENT,
                );

                d.enabled(&meta)
            })
        })
    }

    /// A callsite stand-in for the probe metadata.
    struct Probe;
    impl tracing::Callsite for Probe {
        fn set_interest(&self, _: tracing::subscriber::Interest) {}
        fn metadata(&self) -> &tracing::Metadata<'_> {
            unreachable!("the probe metadata is constructed directly")
        }
    }
    static PROBE: Probe = Probe;

    #[test]
    fn the_default_filter_does_not_silence_the_binarys_own_logs() {
        // The binary target is named AdGuardHome, so `module_path!` reports
        // that -- not the package name.  A filter spelled `adguardlite=info`
        // compiles and matches nothing, which is how every startup message
        // once went missing.
        assert!(
            enables(default_filter(false), "AdGuardHome", Level::INFO),
            "the server's own INFO messages must reach the log"
        );
        assert!(enables(default_filter(false), "agl_dns", Level::INFO));
        assert!(enables(default_filter(false), "agl_api", Level::INFO));
    }

    #[test]
    fn verbose_enables_debug() {
        assert!(enables(default_filter(true), "AdGuardHome", Level::DEBUG));
        assert!(!enables(default_filter(false), "AdGuardHome", Level::DEBUG));
    }

    #[test]
    fn chatty_dependencies_stay_quiet() {
        for dep in ["hyper", "rustls", "h2", "hickory_proto"] {
            assert!(
                !enables(default_filter(false), dep, Level::INFO),
                "{dep} should be filtered to warnings"
            );
        }
    }
}
