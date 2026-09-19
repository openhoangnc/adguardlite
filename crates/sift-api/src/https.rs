//! Serving the router over TLS.
//!
//! axum's own `serve` takes a plain listener, so the TLS handshake is done
//! here and each accepted connection is handed to hyper directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use tokio::net::TcpListener;

/// How long a TLS handshake may take before the connection is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Binds `addr` and serves `app` over TLS until `shutdown` changes.
///
/// Returns the task driving the listener, so the caller can await it on
/// shutdown.
pub async fn serve(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    probes: Arc<sift_dns::probe::Guard>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);

    Ok(tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! {
                r = listener.accept() => match r {
                    Ok(v) => v,
                    // One failed accept should not take the listener down.
                    Err(_) => continue,
                },
                _ = shutdown.changed() => return,
            };

            // A source that has proved it only ever connects and leaves is
            // turned away before the handshake, which is what it costs us.
            // This port carries DoH and the web interface, so anything that
            // makes a single request -- a query, a page, an asset -- clears
            // its record.
            if !probes.admits(peer.ip()) {
                continue;
            }

            let acceptor = acceptor.clone();
            let probes = probes.clone();
            // Each connection gets the router with its peer address attached,
            // so handlers can see who is asking.
            let svc = app
                .clone()
                .into_make_service_with_connect_info::<SocketAddr>();

            tokio::spawn(async move {
                stream.set_nodelay(true).ok();

                let accepted = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream));
                let Ok(Ok(tls_stream)) = accepted.await else {
                    // A handshake that never finished asked nothing, and TCP
                    // has already proved the address.
                    probes.record(peer.ip(), 0);

                    return;
                };

                let tower_svc = match tower::util::ServiceExt::oneshot(svc, peer).await {
                    Ok(s) => s,
                    Err(_) => return,
                };

                let served = Arc::new(AtomicU32::new(0));
                let counted = served.clone();
                let hyper_svc = hyper::service::service_fn(move |req| {
                    let tower_svc = tower_svc.clone();
                    counted.fetch_add(1, Ordering::Relaxed);

                    async move { tower::util::ServiceExt::oneshot(tower_svc, req).await }
                });

                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection_with_upgrades(TokioIo::new(tls_stream), hyper_svc)
                    .await;

                probes.record(peer.ip(), served.load(Ordering::Relaxed));
            });
        }
    }))
}
