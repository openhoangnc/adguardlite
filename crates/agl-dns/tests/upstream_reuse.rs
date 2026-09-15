//! One connection, many queries.
//!
//! Every test here starts its own server on loopback, with a certificate
//! generated in the process, and counts what that server sees.  Counting the
//! server's accepts is the only way to tell a connection that is being reused
//! from one that is being reopened — the client cannot be asked, and asking
//! it would only prove that it agrees with itself.
//!
//! Nothing here touches the network: the upstreams are written with a literal
//! address, so no name is resolved and the client contacts exactly the
//! listener the test started.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use agl_dns::client::Client;
use bytes::Bytes;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use http_body_util::{BodyExt, Full};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long an exchange in these tests is given.
///
/// Generous, because what is being measured is how many connections were
/// opened and not how quickly: a test that fails on a slow machine teaches
/// nothing.
const PATIENT: Duration = Duration::from_secs(5);

/// What a test server saw.
#[derive(Default)]
struct Seen {
    /// Connections accepted.
    accepted: AtomicUsize,
    /// TLS handshakes that completed.
    handshakes: AtomicUsize,
    /// Queries answered.
    queries: AtomicUsize,
    /// Connections that have since ended.
    closed: AtomicUsize,
    /// The identifier of the last query, as it arrived on the wire.
    wire_id: parking_lot::Mutex<Option<u16>>,
}

impl Seen {
    /// A fresh tally.
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// How many connections were accepted.
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    /// How many queries were answered.
    fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

/// A query with a distinctive identifier, so a reply can be traced to it.
fn query(id: u16, name: &str) -> Message {
    let mut m = Message::query();
    m.metadata.id = id;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_utf8(name).expect("a name"),
        RecordType::A,
    ));

    m
}

/// Answers a wire-format query with a fixed address.
fn answer(wire: &[u8], seen: &Seen) -> Vec<u8> {
    let req = Message::from_bytes(wire).expect("a query");
    *seen.wire_id.lock() = Some(req.metadata.id);
    seen.queries.fetch_add(1, Ordering::SeqCst);

    agl_dns::msg::with_addrs(&req, &["1.2.3.4".parse().expect("static addr")], 60)
        .to_bytes()
        .expect("encoding")
}

/// A self-signed certificate for `127.0.0.1`, for both ends of a test.
///
/// The address is also the server name here, since the upstream is written
/// as a literal, so the certificate carries an IP name rather than a DNS one
/// and the client is given a root store holding nothing else.
fn certificates() -> (agl_dns::tls::Loaded, Arc<rustls::ClientConfig>) {
    let mut params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("parameters");
    params.subject_alt_names.push(rcgen::SanType::IpAddress(
        "127.0.0.1".parse().expect("an address"),
    ));
    let key = rcgen::KeyPair::generate().expect("a key");
    let cert = params.self_signed(&key).expect("a certificate");

    let server = agl_dns::tls::load(&agl_dns::tls::Source {
        certificate_chain: cert.pem(),
        private_key: key.serialize_pem(),
        ..Default::default()
    })
    .expect("the test pair must load");

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).expect("trusting the test CA");
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (server, Arc::new(client))
}

/// Builds a client for an upstream written as `spec`.
async fn client(spec: &str, tls: &Arc<rustls::ClientConfig>) -> Client {
    let up = agl_dns::addr::parse(spec)
        .expect("parsing")
        .upstream
        .expect("an upstream");

    Client::connect(up, &[], PATIENT, false, tls.clone())
        .await
        .expect("connecting")
}

/// Waits for `cond` to hold, for up to two seconds.
async fn settle(cond: impl Fn() -> bool) -> bool {
    for _ in 0..200 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    cond()
}

/// Starts a DNS-over-HTTPS server on loopback.
///
/// `retire_after`, when set, has the server send a GOAWAY once it has
/// answered that many queries on a connection — what a public resolver does
/// to a connection that has lived long enough.
async fn doh_server(
    tls: Arc<rustls::ServerConfig>,
    seen: Arc<Seen>,
    retire_after: Option<usize>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binding");
    let addr = listener.local_addr().expect("an address");

    tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        while let Ok((tcp, _)) = listener.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                seen.handshakes.fetch_add(1, Ordering::SeqCst);

                let served = Arc::new(AtomicUsize::new(0));
                let retire = Arc::new(tokio::sync::Notify::new());
                let service = {
                    let seen = seen.clone();
                    let served = served.clone();
                    let retire = retire.clone();
                    hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let seen = seen.clone();
                        let served = served.clone();
                        let retire = retire.clone();
                        async move {
                            let wire = req.into_body().collect().await.expect("a body").to_bytes();
                            let body = answer(&wire, &seen);
                            if retire_after == Some(served.fetch_add(1, Ordering::SeqCst) + 1) {
                                retire.notify_one();
                            }

                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .header("content-type", "application/dns-message")
                                    .body(Full::new(Bytes::from(body)))
                                    .expect("a response"),
                            )
                        }
                    })
                };

                let conn =
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service);
                tokio::pin!(conn);

                tokio::select! {
                    _ = conn.as_mut() => {}
                    () = retire.notified() => {
                        conn.as_mut().graceful_shutdown();
                        let _ = conn.await;
                    }
                }
                seen.closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });

    addr
}

/// Starts a DNS-over-TLS server on loopback.
///
/// `close_after`, when set, has it hang up once it has answered that many
/// queries on a connection.
async fn dot_server(
    tls: Arc<rustls::ServerConfig>,
    seen: Arc<Seen>,
    close_after: Option<usize>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binding");
    let addr = listener.local_addr().expect("an address");

    tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        while let Ok((tcp, _)) = listener.accept().await {
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                seen.handshakes.fetch_add(1, Ordering::SeqCst);

                let mut served = 0;
                loop {
                    let mut lenbuf = [0u8; 2];
                    if tls.read_exact(&mut lenbuf).await.is_err() {
                        break;
                    }
                    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
                    if tls.read_exact(&mut buf).await.is_err() {
                        break;
                    }

                    let body = answer(&buf, &seen);
                    let len = u16::try_from(body.len()).expect("a small answer");
                    if tls.write_all(&len.to_be_bytes()).await.is_err()
                        || tls.write_all(&body).await.is_err()
                        || tls.flush().await.is_err()
                    {
                        break;
                    }

                    served += 1;
                    if close_after == Some(served) {
                        break;
                    }
                }

                drop(tls);
                seen.closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });

    addr
}

/// Starts a DNS-over-QUIC server on loopback.
///
/// `close_after`, when set, has it retire the connection with `DOQ_NO_ERROR`
/// once it has answered that many queries — the close a server sends when it
/// has been restarted or is ageing a connection out.
async fn doq_server(
    tls: Arc<rustls::ServerConfig>,
    seen: Arc<Seen>,
    close_after: Option<usize>,
) -> SocketAddr {
    let endpoint =
        agl_dns::doq::endpoint("127.0.0.1:0".parse().expect("static addr"), tls).expect("binding");
    let addr = endpoint.local_addr().expect("an address");

    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else {
                continue;
            };
            seen.accepted.fetch_add(1, Ordering::SeqCst);
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut served = 0;
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let mut lenbuf = [0u8; 2];
                    if recv.read_exact(&mut lenbuf).await.is_err() {
                        break;
                    }
                    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
                    if recv.read_exact(&mut buf).await.is_err() {
                        break;
                    }

                    let body = answer(&buf, &seen);
                    let len = u16::try_from(body.len()).expect("a small answer");
                    let _ = send.write_all(&len.to_be_bytes()).await;
                    let _ = send.write_all(&body).await;
                    let _ = send.finish();

                    served += 1;
                    if close_after == Some(served) {
                        // `close` is immediate and would discard the answer
                        // that has just been written, so wait for the peer to
                        // acknowledge the stream first.
                        let _ = send.stopped().await;
                        conn.close(0u32.into(), b"");

                        break;
                    }
                }
                seen.closed.fetch_add(1, Ordering::SeqCst);
            });
        }
    });

    addr
}

/// Ten queries in a row and ten at once, down a single connection.
///
/// This is the proof the whole exercise rests on: before it, each of these
/// twenty queries opened a connection of its own and paid for a TLS
/// handshake before it could ask anything.
#[tokio::test]
async fn one_h2_connection_serves_every_query() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doh_server(server.https.clone(), seen.clone(), None).await;

    let client = Arc::new(client(&format!("https://{addr}/dns-query"), &tls).await);

    for i in 0..10u16 {
        let resp = client
            .exchange(&query(0x1000 + i, "example.com."), PATIENT)
            .await
            .expect("the query should be answered");
        assert_eq!(resp.answers.len(), 1);
    }

    let mut set = tokio::task::JoinSet::new();
    for i in 0..10u16 {
        let client = client.clone();
        set.spawn(async move {
            client
                .exchange(&query(0x2000 + i, "example.com."), PATIENT)
                .await
        });
    }

    let mut answered = 10;
    while let Some(joined) = set.join_next().await {
        let resp = joined
            .expect("the task should not panic")
            .expect("the query should be answered");
        assert_eq!(resp.answers.len(), 1);
        answered += 1;
    }

    assert_eq!(answered, 20);
    assert_eq!(
        seen.queries(),
        20,
        "every query should have reached the server"
    );
    assert_eq!(
        seen.accepted(),
        1,
        "twenty queries should have shared one connection"
    );
}

/// Fifty queries arriving together against an upstream nothing is open to.
///
/// Without a gate in front of the dial each of them finds the slot empty and
/// opens its own connection, and the server sees fifty handshakes for one
/// upstream.
#[tokio::test]
async fn concurrent_cold_queries_open_one_connection() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doh_server(server.https.clone(), seen.clone(), None).await;

    let client = Arc::new(client(&format!("https://{addr}/dns-query"), &tls).await);

    let mut set = tokio::task::JoinSet::new();
    for i in 0..50u16 {
        let client = client.clone();
        set.spawn(async move { client.exchange(&query(i, "example.com."), PATIENT).await });
    }

    let mut answered = 0;
    while let Some(joined) = set.join_next().await {
        joined
            .expect("the task should not panic")
            .expect("the query should be answered");
        answered += 1;
    }

    assert_eq!(answered, 50);
    assert_eq!(
        seen.accepted(),
        1,
        "a burst against a cold upstream should dial once"
    );
}

/// A connection the server retires, and the query that comes after it.
#[tokio::test]
async fn the_connection_is_rebuilt_after_the_server_closes_it() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doh_server(server.https.clone(), seen.clone(), Some(3)).await;

    let client = client(&format!("https://{addr}/dns-query"), &tls).await;

    for i in 0..3u16 {
        client
            .exchange(&query(i, "example.com."), PATIENT)
            .await
            .expect("the query should be answered");
    }

    // Let the shutdown land before asking again.  A query that races the
    // GOAWAY is a different case: the request is handed back unsent and
    // repeated on a fresh connection, which is right but not something a test
    // can schedule, and the case that matters here is the ordinary one where
    // the client simply finds the connection gone.
    assert!(
        settle(|| seen.closed.load(Ordering::SeqCst) == 1).await,
        "the server should have retired the connection"
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = client
        .exchange(&query(4, "example.com."), PATIENT)
        .await
        .expect("the fourth query should be answered, not fail with the old connection");
    assert_eq!(resp.answers.len(), 1);

    assert_eq!(seen.queries(), 4);
    assert_eq!(
        seen.accepted(),
        2,
        "the client should have dialled again, exactly once"
    );
}

/// Twenty queries at once against an upstream that never answers a handshake.
///
/// The gate that makes a cold burst open one connection is also what makes a
/// *dead* upstream serialise: without the memory of the failed dial, each
/// query in turn waits out the whole timeout behind it, and twenty queries
/// cost twenty timeouts rather than one.
#[tokio::test]
async fn an_unreachable_upstream_does_not_serialise() {
    let (_, tls) = certificates();

    // A listener that accepts and then says nothing: a TLS handshake against
    // it hangs rather than being refused, which is the shape of an upstream
    // that is down rather than absent.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("binding");
    let addr = listener.local_addr().expect("an address");
    let stalled = Arc::new(AtomicUsize::new(0));
    let counted = stalled.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            held.push(tcp);
        }
    });

    let client = Arc::new(client(&format!("https://{addr}/dns-query"), &tls).await);

    let budget = Duration::from_millis(300);
    let started = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..20u16 {
        let client = client.clone();
        set.spawn(async move { client.exchange(&query(i, "example.com."), budget).await });
    }

    let mut failed = 0;
    while let Some(joined) = set.join_next().await {
        assert!(
            joined.expect("the task should not panic").is_err(),
            "nothing can answer, so every query must fail"
        );
        failed += 1;
    }
    let took = started.elapsed();

    assert_eq!(failed, 20);
    assert!(
        took < budget * 4,
        "twenty queries against a dead upstream took {took:?}; each waiting its \
         turn would be {:?}",
        budget * 20
    );
    assert!(
        stalled.load(Ordering::SeqCst) <= 2,
        "a dial that has just failed should be remembered, not repeated twenty times"
    );
}

/// The connection should not outlive the client that opened it.
///
/// `POST /control/test_upstream_dns` builds a client per probe and drops it,
/// so a connection that survives its client is a socket and a task leaked on
/// every press of a button in the interface.
#[tokio::test]
async fn dropping_the_client_closes_the_connection() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doh_server(server.https.clone(), seen.clone(), None).await;

    let client = client(&format!("https://{addr}/dns-query"), &tls).await;
    client
        .exchange(&query(1, "example.com."), PATIENT)
        .await
        .expect("the query should be answered");
    assert_eq!(seen.closed.load(Ordering::SeqCst), 0);

    drop(client);

    assert!(
        settle(|| seen.closed.load(Ordering::SeqCst) == 1).await,
        "the server should have seen the connection end"
    );
}

/// Many DNS-over-QUIC queries, one connection.
#[tokio::test]
async fn one_quic_connection_serves_every_query() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doq_server(server.doq.clone(), seen.clone(), None).await;

    let client = Arc::new(client(&format!("quic://{addr}"), &tls).await);

    for i in 0..5u16 {
        client
            .exchange(&query(0x1000 + i, "example.com."), PATIENT)
            .await
            .expect("the query should be answered");
    }

    let mut set = tokio::task::JoinSet::new();
    for i in 0..5u16 {
        let client = client.clone();
        set.spawn(async move {
            client
                .exchange(&query(0x2000 + i, "example.com."), PATIENT)
                .await
        });
    }
    while let Some(joined) = set.join_next().await {
        joined
            .expect("the task should not panic")
            .expect("the query should be answered");
    }

    assert_eq!(seen.queries(), 10);
    assert_eq!(
        seen.accepted(),
        1,
        "ten queries should have shared one QUIC connection"
    );
}

/// A DoQ connection the server retires with `DOQ_NO_ERROR`.
#[tokio::test]
async fn a_retired_quic_connection_is_rebuilt() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doq_server(server.doq.clone(), seen.clone(), Some(1)).await;

    let client = client(&format!("quic://{addr}"), &tls).await;

    client
        .exchange(&query(1, "example.com."), PATIENT)
        .await
        .expect("the first query should be answered");
    assert!(
        settle(|| seen.closed.load(Ordering::SeqCst) == 1).await,
        "the server should have retired the connection"
    );

    let resp = client
        .exchange(&query(2, "example.com."), PATIENT)
        .await
        .expect("the second query should be answered on a new connection");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(seen.accepted(), 2);
}

/// RFC 9250 requires the identifier on the wire to be zero.
///
/// QUIC's own streams already pair an answer with its question, and a
/// non-zero identifier is a fingerprint rather than a feature.  The caller
/// still gets its own identifier back, because everything above this expects
/// the reply it is handed to carry the one it asked with.
#[tokio::test]
async fn a_quic_query_travels_with_a_zero_identifier() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = doq_server(server.doq.clone(), seen.clone(), None).await;

    let client = client(&format!("quic://{addr}"), &tls).await;
    let resp = client
        .exchange(&query(0x4242, "example.com."), PATIENT)
        .await
        .expect("the query should be answered");

    assert_eq!(
        *seen.wire_id.lock(),
        Some(0),
        "the identifier on the wire must be zero"
    );
    assert_eq!(
        resp.metadata.id, 0x4242,
        "the caller's identifier must be restored"
    );
}

/// Two DNS-over-TLS queries, one connection and one handshake.
#[tokio::test]
async fn a_dot_connection_is_checked_out_and_returned() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = dot_server(server.dot.clone(), seen.clone(), None).await;

    let client = client(&format!("tls://{addr}"), &tls).await;
    for i in 0..2u16 {
        let resp = client
            .exchange(&query(i, "example.com."), PATIENT)
            .await
            .expect("the query should be answered");
        assert_eq!(resp.answers.len(), 1);
    }

    assert_eq!(seen.queries(), 2);
    assert_eq!(
        seen.accepted(),
        1,
        "the second query should have reused the first's connection"
    );
    assert_eq!(
        seen.handshakes.load(Ordering::SeqCst),
        1,
        "and so should not have handshaked again"
    );
}

/// A pooled connection the server hung up on, and the query that finds out.
///
/// Nothing tells a client that a kept connection has gone: it is discovered
/// by using it.  The query that discovers it must not fail — it has not been
/// answered, so repeating it asks the upstream nothing it was not going to be
/// asked anyway.
#[tokio::test]
async fn a_dead_pooled_connection_is_retried_on_a_fresh_one() {
    let (server, tls) = certificates();
    let seen = Seen::new();
    let addr = dot_server(server.dot.clone(), seen.clone(), Some(1)).await;

    let client = client(&format!("tls://{addr}"), &tls).await;
    client
        .exchange(&query(1, "example.com."), PATIENT)
        .await
        .expect("the first query should be answered");
    assert!(
        settle(|| seen.closed.load(Ordering::SeqCst) == 1).await,
        "the server should have hung up"
    );

    let resp = client
        .exchange(&query(2, "example.com."), PATIENT)
        .await
        .expect("the second query should be answered on a fresh connection");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(seen.accepted(), 2);
}
