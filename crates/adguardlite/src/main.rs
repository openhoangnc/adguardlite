//! adguardlite — a drop-in Rust backend for AdGuard Home.

mod app;
mod cli;
mod fetch;
mod filters;
mod paths;

use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::app::App;
use crate::cli::Args;
use crate::paths::Paths;

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
fn init_logging(args: &Args) {
    let default = if args.verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("adguardlite={default},agl_dns={default}")));

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

    let application = App::build(
        paths.clone(),
        config,
        Arc::new(agl_dns::server::NoopObserver),
    )
    .await?;

    tracing::info!(
        rules = application.filters.rules_count(),
        lists = application.filters.blocklists.len() + application.filters.allowlists.len(),
        "filter lists loaded"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let tasks = application.serve_dns(shutdown_rx).await?;

    for addr in application.dns_addrs() {
        tracing::info!(%addr, "serving dns");
    }

    wait_for_shutdown().await;
    tracing::info!("shutting down");
    let _ = shutdown_tx.send(true);

    for t in tasks {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), t).await;
    }

    Ok(())
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
