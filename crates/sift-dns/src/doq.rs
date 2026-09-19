//! The DNS-over-QUIC listener, as specified by RFC 9250.
//!
//! Each query arrives on its own bidirectional stream, carrying the same
//! two-byte-length framing that TCP and DNS-over-TLS use, so the message
//! handling is shared with them. What differs is the transport: a client may
//! have many queries in flight on one connection without head-of-line
//! blocking, and it closes its send side once the query is written.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use quinn::{Endpoint, ServerConfig};

use crate::resolver::Proto;
use crate::server::Server;

/// The largest query this will read from a stream.
const MAX_MSG: usize = 64 * 1024;

/// How long a connection may sit idle before it is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The most streams a single connection may have open at once.
///
/// A bound is needed: without one a client can open streams until the server
/// runs out of memory.
const MAX_CONCURRENT_STREAMS: u32 = 512;

/// Why the listener could not start.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The rustls configuration cannot be used for QUIC.
    ///
    /// QUIC requires TLS 1.3; a certificate usable over TCP may still be
    /// refused here.
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

/// Builds a QUIC endpoint from a rustls configuration.
pub fn endpoint(addr: SocketAddr, tls: Arc<rustls::ServerConfig>) -> Result<Endpoint, Error> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| Error::Tls(e.to_string()))?;

    let mut cfg = ServerConfig::with_crypto(Arc::new(crypto));
    let transport =
        Arc::get_mut(&mut cfg.transport).expect("the transport config is not yet shared");
    transport.max_concurrent_bidi_streams(MAX_CONCURRENT_STREAMS.into());
    // Unidirectional streams carry nothing in DoQ.
    transport.max_concurrent_uni_streams(0u32.into());
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT.try_into().expect("the idle timeout fits"),
    ));

    Endpoint::server(cfg, addr).map_err(|source| Error::Bind { addr, source })
}

/// Serves DNS-over-QUIC until `shutdown` resolves.
pub async fn serve(
    endpoint: Endpoint,
    server: Arc<Server>,
    server_name: Arc<String>,
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
        // ignored -- not refused -- so nothing at all is sent back to an
        // address that may have been forged.
        if !server.probes.admits(incoming.remote_address().ip()) {
            incoming.ignore();

            continue;
        }

        let server = server.clone();
        let name = server_name.clone();
        tokio::spawn(async move {
            let Ok(conn) = incoming.await else {
                // Nothing is recorded against an address whose handshake did
                // not complete: a QUIC initial packet can carry a forged
                // source, and counting one would let a spoofer shut a victim
                // out of DoQ.
                return;
            };
            let peer = conn.remote_address();

            // A client that connects as `<id>.<server_name>` is asking to be
            // treated as the client named `<id>`, the same as over DoT.
            let client_id = conn
                .handshake_data()
                .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|d| d.server_name.clone())
                .and_then(|sni| crate::server::client_id_from_sni(&sni, &name));

            // Each stream is one query; serve them concurrently, which is the
            // point of using QUIC.
            let served = Arc::new(AtomicU32::new(0));
            loop {
                let Ok((send, recv)) = conn.accept_bi().await else {
                    // The connection is over, and the handshake has proved
                    // the address, so what it did or did not ask counts.
                    server
                        .probes
                        .record(peer.ip(), served.load(Ordering::Relaxed));

                    return;
                };

                let server = server.clone();
                let id = client_id.clone();
                let served = served.clone();
                tokio::spawn(async move {
                    if serve_stream(send, recv, server, peer, id).await {
                        served.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
    }
}

/// Handles one query stream, reporting whether it was answered.
async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    server: Arc<Server>,
    peer: SocketAddr,
    client_id: Option<String>,
) -> bool {
    // The client closes its send side after the query, so reading to the end
    // yields exactly one framed message.
    let Ok(buf) = recv.read_to_end(MAX_MSG + 2).await else {
        return false;
    };

    if buf.len() < 2 {
        return false;
    }

    let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if len == 0 || buf.len() < 2 + len {
        return false;
    }
    let wire = &buf[2..2 + len];

    let Some(resp) = server.handle_as(wire, peer, Proto::Quic, client_id).await else {
        // Refused or dropped; closing without an answer is the DoQ equivalent
        // of not replying.
        let _ = send.finish();

        return false;
    };

    let Ok(len) = u16::try_from(resp.len()) else {
        let _ = send.finish();

        return false;
    };

    let mut framed = Vec::with_capacity(resp.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&resp);

    if send.write_all(&framed).await.is_err() {
        return false;
    }
    let _ = send.finish();

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate for `dns.example.com`.
    fn test_tls() -> crate::tls::Loaded {
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()])
            .expect("generating a certificate");

        crate::tls::load(&crate::tls::Source {
            certificate_chain: c.cert.pem(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .expect("the test pair must load")
    }

    #[tokio::test]
    async fn an_endpoint_binds_and_reports_its_address() {
        let tls = test_tls();
        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.doq)
            .expect("a TLS 1.3 capable certificate must build an endpoint");

        let addr = ep.local_addr().expect("the endpoint has an address");
        assert_ne!(
            addr.port(),
            0,
            "an ephemeral port should have been assigned"
        );
        ep.close(0u32.into(), b"done");
    }

    #[tokio::test]
    async fn binding_a_privileged_port_is_reported_not_panicked() {
        let tls = test_tls();
        // Port 1 needs privileges this test does not have.
        let r = endpoint("127.0.0.1:1".parse().unwrap(), tls.doq);
        assert!(matches!(r, Err(Error::Bind { .. })), "got {r:?}");
    }

    /// Builds a QUIC client that trusts only the given certificate.
    fn client_endpoint(cert_pem: &str) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert_pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }

        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"doq".to_vec()];

        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(cfg)
            .expect("the client config must suit QUIC");
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
            .expect("binding the client endpoint");
        ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

        ep
    }

    /// Frames a query the way DoQ carries it.
    fn framed(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, Query};
        use hickory_proto::rr::{Name, RecordType};
        use hickory_proto::serialize::binary::BinEncodable as _;

        let mut m = Message::query();
        // RFC 9250 asks for a zero ID, since QUIC streams already correlate.
        m.metadata.id = 0;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

        let wire = m.to_bytes().unwrap();
        let mut out = Vec::with_capacity(wire.len() + 2);
        out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        out.extend_from_slice(&wire);

        out
    }

    /// Starts a listener blocking `ads.example.com`, returning its address.
    async fn start(tls: &crate::tls::Loaded) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
        use crate::cache::{Cache, Config as CacheConfig};
        use crate::pool::{Mode, Pool, SharedPool};
        use crate::ratelimit::{Config as RlConfig, Limiter};
        use crate::resolver::{Resolver, Settings};
        use crate::rewrite::Table;
        use crate::server::NoopObserver;
        use sift_filter::engine::Engine;

        let resolver = Resolver::new(
            Engine::build(
                [(1i64, "||ads.example.com^")],
                sift_filter::engine::NO_LISTS,
            ),
            Table::default(),
            Cache::new(CacheConfig::default()),
            SharedPool::new(Pool::new(
                vec![],
                vec![],
                vec![],
                Mode::LoadBalance,
                Duration::from_millis(50),
                Duration::from_millis(50),
            )),
            Settings::default(),
        );

        let server = Arc::new(Server::new(
            Arc::new(resolver),
            Arc::new(Limiter::new(RlConfig {
                per_second: 0,
                ..Default::default()
            })),
            Arc::new(NoopObserver),
        ));

        let ep = endpoint("127.0.0.1:0".parse().unwrap(), tls.doq.clone()).unwrap();
        let addr = ep.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            serve(ep, server, Arc::new(String::new()), async {
                let _ = rx.await;
            })
            .await;
        });

        (addr, tx)
    }

    /// Sends one query on its own stream and returns the framed reply.
    async fn ask(conn: &quinn::Connection, name: &str) -> Vec<u8> {
        let (mut send, mut recv) = conn.open_bi().await.expect("opening a stream");
        send.write_all(&framed(name))
            .await
            .expect("writing the query");
        // Closing the send side is what tells the server the query is whole.
        send.finish().expect("finishing the stream");

        recv.read_to_end(MAX_MSG).await.expect("reading the reply")
    }

    #[tokio::test]
    async fn a_query_round_trips_over_quic() {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinDecodable as _;

        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();

        let (addr, stop) = start(&tls).await;
        let client = client_endpoint(&cert_pem);
        let conn = client
            .connect(addr, "dns.example.com")
            .expect("connecting")
            .await
            .expect("handshake");

        let reply = ask(&conn, "ads.example.com.").await;
        assert!(reply.len() > 2, "the reply should be framed");
        let len = usize::from(u16::from_be_bytes([reply[0], reply[1]]));
        assert_eq!(
            reply.len(),
            len + 2,
            "the frame length should match the body"
        );

        let m = Message::from_bytes(&reply[2..]).expect("a DNS message");
        assert_eq!(m.answers.len(), 1, "the blocked name should be answered");

        let _ = stop.send(());
    }

    #[tokio::test]
    async fn many_queries_share_one_connection() {
        use hickory_proto::op::Message;
        use hickory_proto::serialize::binary::BinDecodable as _;

        // Carrying several queries at once without head-of-line blocking is
        // the reason to use QUIC at all.
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()]).unwrap();
        let cert_pem = c.cert.pem();
        let tls = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert_pem.clone(),
            private_key: c.signing_key.serialize_pem(),
            ..Default::default()
        })
        .unwrap();

        let (addr, stop) = start(&tls).await;
        let client = client_endpoint(&cert_pem);
        let conn = client
            .connect(addr, "dns.example.com")
            .expect("connecting")
            .await
            .expect("handshake");

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let conn = conn.clone();
            set.spawn(async move { ask(&conn, "ads.example.com.").await });
        }

        let mut answered = 0;
        while let Some(r) = set.join_next().await {
            let reply = r.expect("the task should not panic");
            let m = Message::from_bytes(&reply[2..]).expect("a DNS message");
            assert_eq!(m.answers.len(), 1);
            answered += 1;
        }
        assert_eq!(answered, 16);

        let _ = stop.send(());
    }

    #[test]
    fn the_doq_config_advertises_the_rfc_9250_protocol() {
        // A client that offers only `doq` must be able to negotiate.
        assert_eq!(test_tls().doq.alpn_protocols, vec![b"doq".to_vec()]);
    }
}
