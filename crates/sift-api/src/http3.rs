//! Serving the web interface and DNS-over-HTTPS over HTTP/3.
//!
//! This is the `serve_http3` setting.  HTTP/3 runs over QUIC rather than TCP,
//! so it needs its own listener on the HTTPS port; requests are then handed to
//! the same router the HTTP/1.1 and HTTP/2 listener uses, which is what keeps
//! DNS-over-HTTPS behaving identically whichever version a client speaks.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use bytes::Bytes;
use http_body_util::BodyExt as _;
use quinn::Endpoint;
use tower::ServiceExt as _;

/// The largest request body accepted, matching the DoH limit.
const MAX_BODY: usize = 64 * 1024;

/// How long a connection may sit idle before it is closed.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Why the listener could not start.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The rustls configuration cannot be used for QUIC, which needs TLS 1.3.
    #[error("quic tls: {0}")]
    Tls(String),

    /// The socket could not be bound.
    #[error("binding {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// Builds a QUIC endpoint that offers HTTP/3.
pub fn endpoint(addr: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Endpoint, Error> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| Error::Tls(e.to_string()))?;

    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport =
        Arc::get_mut(&mut cfg.transport).expect("the transport config is not yet shared");
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT.try_into().expect("the idle timeout fits"),
    ));

    Endpoint::server(cfg, addr).map_err(|source| Error::Bind { addr, source })
}

/// Serves HTTP/3 until `shutdown` resolves.
pub async fn serve(
    endpoint: Endpoint,
    router: Router,
    probes: Arc<sift_dns::probe::Guard>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) {
    tokio::pin!(shutdown);

    loop {
        let incoming = tokio::select! {
            i = endpoint.accept() => match i {
                Some(i) => i,
                // The endpoint was closed.
                None => return,
            },
            () = &mut shutdown => {
                endpoint.close(0u32.into(), b"shutting down");

                return;
            }
        };

        // A source that has proved it only ever connects and leaves is
        // ignored -- not refused -- so nothing is sent back to an address
        // that may have been forged.
        if !probes.admits(incoming.remote_address().ip()) {
            incoming.ignore();

            continue;
        }

        let router = router.clone();
        let probes = probes.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else {
                // Nothing is recorded against an address whose handshake did
                // not complete: a QUIC initial packet can carry a forged
                // source, and counting one would let a spoofer shut a victim
                // out of this listener.
                return;
            };
            let peer = conn.remote_address();

            let served = serve_connection(conn, router, peer).await;
            probes.record(peer.ip(), served);
        });
    }
}

/// Handles every request on one connection.
/// Returns how many requests the connection asked for, which is what tells a
/// client from something probing the port.
async fn serve_connection(conn: quinn::Connection, router: Router, peer: SocketAddr) -> u32 {
    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
    else {
        return 0;
    };

    let mut served = 0;
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                served += 1;

                let router = router.clone();
                tokio::spawn(async move {
                    let _ = serve_request(resolver, router, peer).await;
                });
            }
            // The client is going away, or the connection broke.
            _ => return served,
        }
    }
}

/// Handles one request.
async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    router: Router,
    peer: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (req, mut stream) = resolver.resolve_request().await?;

    // Collect the body up front: a DNS message is small, and the router
    // expects a body it can read without borrowing the stream.
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        use bytes::Buf as _;

        if body.len() + chunk.remaining() > MAX_BODY {
            let resp = http::Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(())?;
            stream.send_response(resp).await?;

            return Ok(stream.finish().await?);
        }

        body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
    }

    let (parts, ()) = req.into_parts();
    let mut request = http::Request::from_parts(parts, Body::from(body));
    // The router's handlers read the client address from here; with the
    // HTTP/1 listener axum inserts it, and nothing does so for HTTP/3.
    request.extensions_mut().insert(ConnectInfo(peer));

    let response = router.oneshot(request).await?;
    let (parts, body) = response.into_parts();

    stream
        .send_response(http::Response::from_parts(parts, ()))
        .await?;

    let collected = body.collect().await?.to_bytes();
    if !collected.is_empty() {
        stream.send_data(collected).await?;
    }

    Ok(stream.finish().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate, for binding tests.
    fn test_tls() -> sift_dns::tls::Loaded {
        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generating a certificate");

        sift_dns::tls::load(&sift_dns::tls::Source {
            certificate_chain: c.cert.pem(),
            private_key: c.signing_key.serialize_pem(),
            certificate_path: String::new(),
            private_key_path: String::new(),
        })
        .expect("the pair should load")
    }

    #[tokio::test]
    async fn an_endpoint_binds_and_offers_http3() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tls = test_tls();
        assert_eq!(tls.h3.alpn_protocols, vec![b"h3".to_vec()]);

        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.h3)
            .expect("binding an ephemeral port should work");
        assert_ne!(ep.local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn a_request_round_trips_over_http3() {
        use axum::routing::post;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let c = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let key_pem = c.signing_key.serialize_pem();

        let tls = sift_dns::tls::load(&sift_dns::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: key_pem,
            certificate_path: String::new(),
            private_key_path: String::new(),
        })
        .unwrap();

        let router = Router::new().route(
            "/echo",
            post(|body: Bytes| async move { format!("got {}", body.len()) }),
        );

        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.h3).unwrap();
        let addr = ep.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve(
                ep,
                router,
                Arc::new(sift_dns::probe::Guard::default()),
                async {
                    let _ = rx.await;
                },
            )
            .await;
        });

        let body = client_post(addr, &cert_pem, "/echo", b"0123456789").await;
        assert_eq!(body, "got 10");

        let _ = tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
    }

    /// Sends one HTTP/3 POST, trusting the given certificate.
    async fn client_post(addr: SocketAddr, cert_pem: &str, path: &str, body: &[u8]) -> String {
        use bytes::Buf as _;

        let mut roots = rustls::RootCertStore::empty();
        for der in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(der.unwrap()).unwrap();
        }

        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h3".to_vec()];

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(cfg)).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        let conn = client.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let req = http::Request::builder()
            .method("POST")
            .uri(format!("https://localhost{path}"))
            .body(())
            .unwrap();

        let mut stream = sender.send_request(req).await.unwrap();
        stream.send_data(Bytes::from(body.to_vec())).await.unwrap();
        stream.finish().await.unwrap();

        let resp = stream.recv_response().await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        let mut out = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            out.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        drive.abort();

        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn binding_a_privileged_port_is_reported_not_panicked() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let r = endpoint("127.0.0.1:443".parse().unwrap(), test_tls().h3);
        // Running as root would succeed; either way it must not panic.
        if let Err(e) = r {
            assert!(matches!(e, Error::Bind { .. }));
        }
    }
}
