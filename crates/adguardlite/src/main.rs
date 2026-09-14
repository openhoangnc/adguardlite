//! adguardlite — a drop-in Rust backend for AdGuard Home.

mod app;
mod cli;
mod discovery;
mod fetch;
mod ipset;
mod lists;
mod logging;
mod osconf;
mod service;
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

    let paths = Paths::new(args.work_dir_or_default(), args.config_or_default());

    // The configuration is read before the runtime starts, because two of the
    // things it decides — where the log goes and which user to run as — have
    // to be settled while the process is still single-threaded.
    let config = match app::load_or_init(&paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("adguardlite: reading {}: {e}", paths.config.display());

            return std::process::ExitCode::FAILURE;
        }
    };

    init_logging(&args, &config.log);

    // A service action neither starts the server nor needs the runtime.
    if let Some(action) = args.service.as_deref() {
        return match service::run(action, &args) {
            Ok(message) => {
                println!("{message}");

                std::process::ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("adguardlite: {e}");

                std::process::ExitCode::FAILURE
            }
        };
    }

    // Checking the configuration is a read-only action: it neither drops
    // privileges nor needs a runtime.
    if args.check_config {
        println!("configuration at {} is valid", paths.config.display());

        return std::process::ExitCode::SUCCESS;
    }

    osconf::apply(&config.os);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("adguardlite: starting the runtime: {e}");

            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(run(args, paths, config)) {
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
fn init_logging(args: &Args, log: &agl_config::model::LogConfig) {
    let default = if args.verbose || log.verbose {
        "debug"
    } else {
        "info"
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Quiet the dependencies that are chatty at these levels.
        EnvFilter::new(format!(
            "{default},hyper=warn,rustls=warn,h2=warn,hickory_proto=warn,tokio_util=warn"
        ))
    });

    // `--logfile` wins over the configured file, which is what upstream does:
    // the flag is how an init script overrides the file for one run.
    let target = args.logfile.clone().unwrap_or_else(|| {
        if log.enabled {
            log.file.clone()
        } else {
            String::new()
        }
    });

    let rotation = logging::Rotation {
        max_size_mb: log.max_size,
        max_backups: log.max_backups,
        max_age_days: log.max_age,
        compress: log.compress,
    };

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);

    match logging::Sink::choose(&target, rotation) {
        logging::Sink::Stderr => builder.init(),
        logging::Sink::File(f) => builder.with_ansi(false).with_writer(move || f).init(),
        #[cfg(unix)]
        logging::Sink::Syslog(s) => builder
            .with_ansi(false)
            // The system log stamps its own time and level.
            .without_time()
            .with_writer(move || s)
            .init(),
    }
}

/// Starts the server and runs until a shutdown signal arrives.
async fn run(args: Args, paths: Paths, mut config: agl_config::Config) -> anyhow::Result<()> {
    // rustls needs a process-wide crypto provider before any TLS is set up.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(addr) = args.web_override()
        && let Ok(parsed) = addr.parse::<std::net::SocketAddr>()
    {
        config.http.address = agl_config::types::AddrPort(parsed);
    }

    tracing::info!(
        version = agl_core::AGH_VERSION,
        config = %paths.config.display(),
        work_dir = %paths.work.display(),
        "starting adguardlite"
    );

    if let Some(p) = &args.pidfile {
        match osconf::write_pidfile(p) {
            Ok(()) => tracing::info!(path = %p.display(), "pid file written"),
            Err(e) => tracing::warn!(path = %p.display(), error = %e, "writing the pid file"),
        }
    }

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
    let recorder_handle = recorder.clone();

    let web_addr = config.http.address.0;
    let max_list_bytes = config.filtering.max_http_size.bytes();

    let application = App::build(paths.clone(), config, recorder).await?;

    tracing::info!(
        rules = application.filters.rules_count(),
        lists = application.filters.blocklists.len() + application.filters.allowlists.len(),
        "filter lists loaded"
    );

    let certificate = Arc::new(agl_dns::tls::Reloadable::new());

    let dns_addrs: Vec<String> = application
        .dns_addrs()
        .iter()
        .map(|a| a.to_string())
        .collect();

    let state: Shared = Arc::new(AppState {
        paths: application.paths.clone(),
        config: parking_lot::RwLock::new(application.config.clone()),
        resolver: application.resolver.clone(),
        dns_server: application.server.clone(),
        filters: parking_lot::RwLock::new(application.filters.clone()),
        querylog: querylog.clone(),
        stats: stats.clone(),
        sessions: agl_api::auth::Sessions::open(application.paths.sessions_db()),
        started: jiff::Timestamp::now(),
        fetcher: Arc::new(wiring::Downloader {
            paths: application.paths.clone(),
            max_bytes: max_list_bytes,
            timeout: app::LIST_TIMEOUT,
        }),
        reloader: Arc::new(wiring::LiveReloader {
            resolver: application.resolver.clone(),
            server: application.server.clone(),
            certificate: certificate.clone(),
        }),
        dns_addresses: parking_lot::RwLock::new(dns_addrs),
        version: Arc::new(wiring::ReleaseChecker {
            disabled: args.no_check_update,
        }),
        version_cache: parking_lot::RwLock::new(None),
    });

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = application.serve_dns(shutdown_rx.clone()).await?;

    // ipset, if any sets are configured.
    let ipset_lines = ipset::lines(
        &application.config.dns.ipset,
        &application.config.dns.ipset_file,
    );
    if let Some(m) = ipset::Manager::new(ipset::parse(&ipset_lines)) {
        tracing::info!(rules = ipset_lines.len(), "ipset enabled");
        recorder_handle.set_ipset(Some(Arc::new(m)));
    }

    // Client discovery: names for the addresses that show up in the log.
    let discoverer = Arc::new(discovery::Discoverer {
        resolver: application.resolver.clone(),
        runtime: application.resolver.runtime.clone(),
    });
    let (queue, discovery_task) = discoverer.start(shutdown_rx.clone());
    recorder_handle.set_discovery(queue, application.resolver.runtime.clone());
    tasks.push(discovery_task);

    // Safe browsing and parental control, whose lookups go to AdGuard's own
    // family resolver.  Resolving it can block, so it happens in the
    // background: a slow network must not hold up the DNS listeners.
    tasks.push(tokio::spawn(start_hashprefix_checkers(
        application.resolver.clone(),
        application.config.filtering.safebrowsing_enabled,
        application.config.filtering.parental_enabled,
        application.config.filtering.cache_time,
        application.config.filtering.safebrowsing_cache_size as usize,
        application.config.filtering.parental_cache_size as usize,
    )));

    for addr in application.dns_addrs() {
        tracing::info!(%addr, "serving dns");
    }

    // Encryption, if a usable certificate is configured.  A broken one is a
    // warning rather than a fatal error: plain DNS and the web interface
    // should keep working while the operator fixes it.
    //
    // The listeners are given a resolver rather than a certificate, so one
    // replaced through the API reaches them without a restart.
    let tls = load_tls(&application.config, &certificate)
        .then(|| agl_dns::tls::reloadable(certificate.clone()));

    // The web interface over plain HTTP.
    let listener = tokio::net::TcpListener::bind(web_addr).await?;
    tracing::info!(addr = %web_addr, "serving web interface");
    if state.needs_install() {
        tracing::info!("no user configured yet; open the web interface to finish setup");
    }

    let app_router = agl_api::routes::router(state.clone(), false);
    let mut web_shutdown = shutdown_rx.clone();
    tasks.push(tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = web_shutdown.changed().await;
        })
        .await;
    }));

    if let Some(tls) = tls {
        let cfg = &application.config;
        // A ClientID reaches an encrypted listener as a label below the name
        // the certificate is for.
        let server_name = Arc::new(cfg.tls.server_name.clone());

        // HTTPS carries both the web interface and DNS-over-HTTPS, as upstream
        // serves them.
        if cfg.tls.port_https != 0 {
            for ip in &cfg.dns.bind_hosts {
                let addr = std::net::SocketAddr::new(*ip, cfg.tls.port_https);
                match agl_api::https::serve(
                    addr,
                    tls.https.clone(),
                    agl_api::routes::router(state.clone(), true),
                    shutdown_rx.clone(),
                )
                .await
                {
                    Ok(t) => {
                        tracing::info!(%addr, "serving https and dns-over-https");
                        tasks.push(t);
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "binding https"),
                }

                // HTTP/3 runs over QUIC, so it needs its own listener on the
                // same port number — the UDP one rather than the TCP one.
                if cfg.dns.serve_http3 {
                    match agl_api::http3::endpoint(addr, tls.h3.clone()) {
                        Ok(ep) => {
                            tracing::info!(%addr, "serving http/3");
                            let router = agl_api::routes::router(state.clone(), true);
                            let mut rx = shutdown_rx.clone();
                            tasks.push(tokio::spawn(async move {
                                agl_api::http3::serve(ep, router, async move {
                                    let _ = rx.changed().await;
                                })
                                .await;
                            }));
                        }
                        Err(e) => tracing::error!(%addr, error = %e, "binding http/3"),
                    }
                }
            }
        }

        if cfg.tls.port_dns_over_quic != 0 {
            for ip in &cfg.dns.bind_hosts {
                let addr = std::net::SocketAddr::new(*ip, cfg.tls.port_dns_over_quic);
                match agl_dns::doq::endpoint(addr, tls.doq.clone()) {
                    Ok(ep) => {
                        tracing::info!(%addr, "serving dns-over-quic");
                        let server = application.server.clone();
                        let name = server_name.clone();
                        let mut rx = shutdown_rx.clone();
                        tasks.push(tokio::spawn(async move {
                            agl_dns::doq::serve(ep, server, name, async move {
                                let _ = rx.changed().await;
                            })
                            .await;
                        }));
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "binding dns-over-quic"),
                }
            }
        }

        if cfg.tls.port_dns_over_tls != 0 {
            for ip in &cfg.dns.bind_hosts {
                let addr = std::net::SocketAddr::new(*ip, cfg.tls.port_dns_over_tls);
                match agl_dns::server::bind_tcp(addr).await {
                    Ok(l) => {
                        tracing::info!(%addr, "serving dns-over-tls");
                        let server = application.server.clone();
                        let dot = tls.dot.clone();
                        let name = server_name.clone();
                        let mut rx = shutdown_rx.clone();
                        tasks.push(tokio::spawn(async move {
                            let _ = agl_dns::server::serve_dot(l, dot, server, name, async move {
                                let _ = rx.changed().await;
                            })
                            .await;
                        }));
                    }
                    Err(e) => tracing::error!(%addr, error = %e, "binding dns-over-tls"),
                }
            }
        }
    }

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
    state.sessions.persist();
    if let Err(e) = querylog.flush() {
        tracing::warn!(error = %e, "flushing the query log");
    }
    if let Err(e) = agl_stats::store::save(&stats_path, &stats.snapshot()) {
        tracing::warn!(error = %e, "saving statistics");
    }

    for t in tasks {
        let _ = tokio::time::timeout(Duration::from_secs(5), t).await;
    }

    if let Some(p) = &args.pidfile {
        osconf::remove_pidfile(p);
    }

    Ok(())
}

/// Builds the safe browsing and parental control checkers.
///
/// Each is a DNS-over-HTTPS client to AdGuard's family resolver; a failure to
/// reach it leaves the feature off for this run rather than stopping the
/// server, and is logged so the operator can see why nothing is being
/// blocked.
async fn start_hashprefix_checkers(
    resolver: Arc<agl_dns::resolver::Resolver>,
    safebrowsing: bool,
    parental: bool,
    cache_minutes: u32,
    sb_cache: usize,
    pc_cache: usize,
) {
    use agl_dns::hashprefix::{Checker, PARENTAL_SUFFIX, SAFE_BROWSING_SUFFIX};

    if !safebrowsing && !parental {
        return;
    }

    let ttl = Duration::from_secs(u64::from(cache_minutes.max(1)) * 60);

    if safebrowsing {
        match Checker::connect(SAFE_BROWSING_SUFFIX, ttl, sb_cache).await {
            Ok(c) => {
                tracing::info!("safe browsing enabled");
                resolver.set_safebrowsing(Some(Arc::new(c)));
            }
            Err(e) => tracing::error!(error = %e, "safe browsing is on but unreachable"),
        }
    }

    if parental {
        match Checker::connect(PARENTAL_SUFFIX, ttl, pc_cache).await {
            Ok(c) => {
                tracing::info!("parental control enabled");
                resolver.set_parental(Some(Arc::new(c)));
            }
            Err(e) => tracing::error!(error = %e, "parental control is on but unreachable"),
        }
    }
}

/// Installs the configured certificate, reporting whether encryption can run.
fn load_tls(cfg: &agl_config::Config, into: &agl_dns::tls::Reloadable) -> bool {
    if !cfg.tls.enabled {
        return false;
    }

    let src = agl_dns::tls::Source {
        certificate_chain: cfg.tls.certificate_chain.clone(),
        private_key: cfg.tls.private_key.clone(),
        certificate_path: cfg.tls.certificate_path.clone(),
        private_key_path: cfg.tls.private_key_path.clone(),
    };

    if src.is_empty() {
        tracing::warn!("encryption is enabled but no certificate is configured");

        return false;
    }

    match agl_dns::tls::install(&src, into) {
        Ok(st) => {
            tracing::info!(names = ?st.dns_names, "certificate loaded");

            true
        }
        Err(e) => {
            tracing::error!(error = %e, "encryption is enabled but the certificate is unusable");

            false
        }
    }
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
