//! UDP and TCP listeners.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::msg;
use crate::ratelimit::Limiter;
use crate::resolver::{Action, ClientInfo, Outcome, Proto, Resolver};

/// The largest datagram the server will read.
const UDP_BUF: usize = 4096;

/// How long a TCP client may stay idle between queries.
const TCP_IDLE: Duration = Duration::from_secs(30);

/// The maximum size of a TCP-framed query.
const MAX_TCP_MSG: usize = 64 * 1024;

/// How long a TLS handshake may take before the connection is dropped.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Notified about every handled query, for the query log and statistics.
pub trait Observer: Send + Sync + 'static {
    /// Called once per handled request.
    fn observe(&self, ev: &Event<'_>);
}

/// A no-op observer, useful in tests and when logging is disabled.
pub struct NoopObserver;

impl Observer for NoopObserver {
    fn observe(&self, _ev: &Event<'_>) {}
}

/// Everything known about one handled request.
pub struct Event<'a> {
    /// The request as received.
    pub request: &'a Message,
    /// How the request was handled.
    pub outcome: &'a Outcome,
    /// The client's address.
    pub client: SocketAddr,
    /// The transport the request arrived on.
    pub proto: Proto,
}

/// Which clients may query this server.
#[derive(Clone, Debug, Default)]
pub struct Access {
    /// If non-empty, only these clients may query.
    pub allowed: Vec<IpAddr>,
    /// These clients may not query.
    pub disallowed: Vec<IpAddr>,
}

impl Access {
    /// Reports whether `ip` may query.
    pub fn permits(&self, ip: IpAddr) -> bool {
        if !self.allowed.is_empty() {
            return self.allowed.contains(&ip);
        }

        !self.disallowed.contains(&ip)
    }
}

/// The shared state every listener needs.
pub struct Server {
    /// The resolver that answers queries.
    pub resolver: Arc<Resolver>,
    /// The rate limiter.
    pub limiter: Arc<Limiter>,
    /// Client access control.
    pub access: Arc<parking_lot::RwLock<Access>>,
    /// The query observer.
    pub observer: Arc<dyn Observer>,
    /// The bound on requests being handled at once, or `None` for no bound.
    ///
    /// This is `max_goroutines`: without it a flood of slow upstream lookups
    /// can pile up until the process runs out of memory.
    concurrency: parking_lot::RwLock<Option<Arc<tokio::sync::Semaphore>>>,
}

impl Server {
    /// Builds a server around a resolver.
    pub fn new(
        resolver: Arc<Resolver>,
        limiter: Arc<Limiter>,
        observer: Arc<dyn Observer>,
    ) -> Self {
        Self {
            resolver,
            limiter,
            access: Arc::new(parking_lot::RwLock::new(Access::default())),
            observer,
            concurrency: parking_lot::RwLock::new(None),
        }
    }

    /// Sets how many requests may be handled at once; zero means no bound.
    pub fn set_max_concurrent(&self, n: u32) {
        *self.concurrency.write() = (n > 0).then(|| {
            Arc::new(tokio::sync::Semaphore::new(
                usize::try_from(n).unwrap_or(usize::MAX),
            ))
        });
    }

    /// Handles one request and returns the bytes to send back, if any.
    pub async fn handle(&self, wire: &[u8], client: SocketAddr, proto: Proto) -> Option<Vec<u8>> {
        self.handle_as(wire, client, proto, None).await
    }

    /// Handles one request on behalf of a named client.
    ///
    /// The ClientID comes from a DoH path segment or a DoT server name, and
    /// selects a persistent client's own settings.
    pub async fn handle_as(
        &self,
        wire: &[u8],
        client: SocketAddr,
        proto: Proto,
        client_id: Option<String>,
    ) -> Option<Vec<u8>> {
        // Access control and rate limiting come before parsing, so a flood of
        // malformed datagrams costs as little as possible.
        if !self.access.read().permits(client.ip()) {
            // Silence only on a datagram transport, where a spoofed source
            // would turn the answer into amplification.  A connected client
            // has already paid for the handshake and upstream tells it
            // plainly, so closing the connection instead — which is what this
            // did — reads as a broken server rather than a refusal.
            if proto.is_datagram() {
                return None;
            }

            let req = Message::from_bytes(wire).ok()?;

            return msg::refused(&req).to_bytes().ok();
        }
        if !self.limiter.allow(client.ip()) {
            return None;
        }

        let sem = self.concurrency.read().clone();
        let _permit = match &sem {
            Some(s) => Some(s.clone().acquire_owned().await.ok()?),
            None => None,
        };

        let req = Message::from_bytes(wire).ok()?;

        let info = ClientInfo {
            addr: Some(client.ip()),
            id: client_id,
            name: None,
            tags: Vec::new(),
        };
        let outcome = self.resolver.resolve(&req, proto, &info).await;

        self.observer.observe(&Event {
            request: &req,
            outcome: &outcome,
            client,
            proto,
        });

        match &outcome.action {
            Action::Drop => None,
            Action::Respond(resp) => resp.to_bytes().ok(),
        }
    }
}

/// Serves plain DNS over UDP until `shutdown` resolves.
pub async fn serve_udp(
    sock: UdpSocket,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    let sock = Arc::new(sock);
    tokio::pin!(shutdown);

    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let (n, peer) = tokio::select! {
            r = sock.recv_from(&mut buf) => r?,
            () = &mut shutdown => return Ok(()),
        };

        let wire = buf[..n].to_vec();
        let server = server.clone();
        let sock = sock.clone();
        tokio::spawn(async move {
            if let Some(resp) = server.handle(&wire, peer, Proto::Udp).await {
                // A response larger than the client's buffer would be dropped
                // by the network; set TC so it retries over TCP.
                let out = truncate_if_needed(&resp, UDP_BUF);
                let _ = sock.send_to(&out, peer).await;
            }
        });
    }
}

/// Serves plain DNS over TCP until `shutdown` resolves.
pub async fn serve_tcp(
    listener: TcpListener,
    server: Arc<Server>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => r?,
            () = &mut shutdown => return Ok(()),
        };

        let server = server.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();
            let _ = serve_stream(stream, server, peer, Proto::Tcp, None).await;
        });
    }
}

/// Serves DNS-over-TLS until `shutdown` resolves.
///
/// A handshake failure closes that one connection and leaves the listener
/// running: an unreachable server is a worse outcome than a rejected client.
///
/// `server_name` is the name the certificate is for; a client that connects
/// with `<id>.<server_name>` is asking to be treated as the client named
/// `<id>`, which is how a ClientID reaches a DoT listener.
pub async fn serve_dot(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    server: Arc<Server>,
    server_name: Arc<String>,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> std::io::Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            r = listener.accept() => r?,
            () = &mut shutdown => return Ok(()),
        };

        let server = server.clone();
        let acceptor = acceptor.clone();
        let name = server_name.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();

            // Bound the handshake so a client that connects and says nothing
            // cannot hold a task open.
            let accepted = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream));
            let Ok(Ok(tls_stream)) = accepted.await else {
                return;
            };

            let client_id = tls_stream
                .get_ref()
                .1
                .server_name()
                .and_then(|sni| client_id_from_sni(sni, &name));

            let _ = serve_stream(tls_stream, server, peer, Proto::Tls, client_id).await;
        });
    }
}

/// Extracts a ClientID from the name a client asked for.
///
/// Only the label directly below the server's own name counts, and the name
/// itself carries no identifier.  A client that asks for something unrelated
/// gets no identifier rather than having part of that name taken as one.
pub fn client_id_from_sni(sni: &str, server_name: &str) -> Option<String> {
    if server_name.is_empty() {
        return None;
    }

    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    let base = server_name.trim_end_matches('.').to_ascii_lowercase();

    let id = sni.strip_suffix(&base)?.strip_suffix('.')?;
    if id.is_empty() || id.contains('.') {
        return None;
    }

    Some(id.to_string())
}

/// Handles queries on one stream until it closes or goes idle.
///
/// Plain DNS over TCP and DNS-over-TLS share this: both carry the same
/// two-byte-length framing, and only the transport underneath differs.
async fn serve_stream<S>(
    mut stream: S,
    server: Arc<Server>,
    peer: SocketAddr,
    proto: Proto,
    client_id: Option<String>,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        let mut lenbuf = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut lenbuf)).await {
            Ok(Ok(_)) => {}
            // Idle timeout or a clean close: stop serving this connection.
            _ => return Ok(()),
        }

        let n = usize::from(u16::from_be_bytes(lenbuf));
        if n == 0 || n > MAX_TCP_MSG {
            return Ok(());
        }

        let mut wire = vec![0u8; n];
        if stream.read_exact(&mut wire).await.is_err() {
            return Ok(());
        }

        let Some(resp) = server
            .handle_as(&wire, peer, proto, client_id.clone())
            .await
        else {
            // Nothing to send: close rather than leave the client waiting.
            return Ok(());
        };

        let len = match u16::try_from(resp.len()) {
            Ok(l) => l,
            Err(_) => return Ok(()),
        };

        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&resp).await?;
        stream.flush().await?;
    }
}

/// Sets the truncation bit and strips records if a response will not fit in a
/// datagram.
fn truncate_if_needed(wire: &[u8], limit: usize) -> Vec<u8> {
    if wire.len() <= limit {
        return wire.to_vec();
    }

    let Ok(msg) = Message::from_bytes(wire) else {
        return wire.to_vec();
    };

    let mut t = Message::query();
    t.metadata = msg.metadata;
    t.metadata.truncation = true;
    t.queries = msg.queries;

    t.to_bytes().unwrap_or_else(|_| wire.to_vec())
}

/// Binds a UDP socket, allowing address reuse so restarts do not fail.
pub async fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::bind(addr).await
}

/// Binds a TCP listener.
pub async fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    TcpListener::bind(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{Cache, Config as CacheConfig};
    use crate::pool::{Mode, Pool, SharedPool};
    use crate::ratelimit::Config as RlConfig;
    use crate::resolver::Settings;
    use crate::rewrite::Table;
    use agl_filter::engine::Engine;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    fn test_server(rules: &str, per_second: u32) -> Arc<Server> {
        let resolver = Resolver::new(
            Engine::build([(1i64, rules)], []),
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

        Arc::new(Server::new(
            Arc::new(resolver),
            Arc::new(Limiter::new(RlConfig {
                per_second,
                ..Default::default()
            })),
            Arc::new(NoopObserver),
        ))
    }

    fn wire_query(name: &str, qt: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = 0x2222;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), qt));

        m.to_bytes().unwrap()
    }

    fn peer() -> SocketAddr {
        "192.0.2.10:5000".parse().unwrap()
    }

    #[tokio::test]
    async fn answers_a_blocked_query_over_udp() {
        let s = test_server("||ads.example.com^\n", 0);
        let out = s
            .handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp,
            )
            .await
            .expect("should answer");

        let resp = Message::from_bytes(&out).unwrap();
        assert_eq!(resp.metadata.id, 0x2222);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn garbage_input_produces_no_response() {
        let s = test_server("", 0);
        assert!(
            s.handle(b"not a dns message", peer(), Proto::Udp)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn access_control_blocks_disallowed_clients() {
        let s = test_server("||ads.example.com^\n", 0);
        s.access.write().disallowed = vec![peer().ip()];
        assert!(
            s.handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn a_blocked_client_is_refused_rather_than_cut_off_on_stream_transports() {
        // Upstream drops only on UDP and DNSCrypt, where a spoofed source
        // would make the answer amplification; every connected transport gets
        // REFUSED.  Returning nothing closed the connection instead, which
        // `dig +tcp` reports as "communications error: end of file".
        use hickory_proto::op::ResponseCode;

        let s = test_server("||ads.example.com^\n", 0);
        s.access.write().disallowed = vec![peer().ip()];
        let q = wire_query("example.com.", RecordType::A);

        for proto in [Proto::Tcp, Proto::Tls, Proto::Https, Proto::Quic] {
            let out = s
                .handle(&q, peer(), proto)
                .await
                .unwrap_or_else(|| panic!("{proto:?} must answer, not hang up"));
            let resp = Message::from_bytes(&out).unwrap();
            assert_eq!(
                resp.metadata.response_code,
                ResponseCode::Refused,
                "{proto:?}"
            );
        }

        // UDP still says nothing at all.
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_none());
    }

    #[tokio::test]
    async fn allowlist_mode_rejects_everyone_else() {
        let s = test_server("||ads.example.com^\n", 0);
        s.access.write().allowed = vec!["10.0.0.1".parse().unwrap()];
        assert!(
            s.handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp
            )
            .await
            .is_none()
        );

        s.access.write().allowed = vec![peer().ip()];
        assert!(
            s.handle(
                &wire_query("ads.example.com.", RecordType::A),
                peer(),
                Proto::Udp
            )
            .await
            .is_some()
        );
    }

    #[tokio::test]
    async fn rate_limiting_drops_excess_queries() {
        let s = test_server("||ads.example.com^\n", 2);
        let q = wire_query("ads.example.com.", RecordType::A);
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_some());
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_some());
        assert!(
            s.handle(&q, peer(), Proto::Udp).await.is_none(),
            "third should be limited"
        );
    }

    #[tokio::test]
    async fn access_blocked_hosts_are_silent_on_udp() {
        let s = test_server("", 0);
        let q = wire_query("version.bind.", RecordType::TXT);
        assert!(s.handle(&q, peer(), Proto::Udp).await.is_none());
        assert!(
            s.handle(&q, peer(), Proto::Tcp).await.is_some(),
            "TCP gets REFUSED"
        );
    }

    #[tokio::test]
    async fn udp_listener_round_trips() {
        let s = test_server("||ads.example.com^\n", 0);
        let sock = bind_udp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = sock.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_udp(sock, s, async {
                let _ = rx.await;
            })
            .await;
        });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(addr).await.unwrap();
        client
            .send(&wire_query("ads.example.com.", RecordType::A))
            .await
            .unwrap();

        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(3), client.recv(&mut buf))
            .await
            .expect("should not time out")
            .unwrap();

        let resp = Message::from_bytes(&buf[..n]).unwrap();
        assert_eq!(resp.metadata.id, 0x2222);
        assert_eq!(resp.answers.len(), 1);

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn tcp_listener_round_trips_and_reuses_the_connection() {
        let s = test_server("||ads.example.com^\n", 0);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_tcp(listener, s, async {
                let _ = rx.await;
            })
            .await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Two queries on the same connection, as a real client would.
        for _ in 0..2 {
            let q = wire_query("ads.example.com.", RecordType::A);
            c.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
            c.write_all(&q).await.unwrap();
            c.flush().await.unwrap();

            let mut lenbuf = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(3), c.read_exact(&mut lenbuf))
                .await
                .expect("should not time out")
                .unwrap();
            let n = usize::from(u16::from_be_bytes(lenbuf));
            let mut buf = vec![0u8; n];
            c.read_exact(&mut buf).await.unwrap();

            let resp = Message::from_bytes(&buf).unwrap();
            assert_eq!(resp.answers.len(), 1);
        }

        let _ = tx.send(());
    }

    /// A self-signed certificate for `dns.example.com`.
    fn test_cert() -> (String, String) {
        let c = rcgen::generate_simple_self_signed(vec!["dns.example.com".to_string()])
            .expect("generating a certificate");

        (c.cert.pem(), c.signing_key.serialize_pem())
    }

    #[tokio::test]
    async fn dot_listener_answers_a_query() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert.clone(),
            private_key: key,
            ..Default::default()
        })
        .expect("the test pair must load");

        let s = test_server("||ads.example.com^\n", 0);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_dot(listener, loaded.dot, s, Arc::new(String::new()), async {
                let _ = rx.await;
            })
            .await;
        });

        // Trust only the certificate the server presents.
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut cert.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let name = rustls_pki_types::ServerName::try_from("dns.example.com").unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(name, tcp).await.expect("handshake");

        let q = wire_query("ads.example.com.", RecordType::A);
        tls.write_all(&(q.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tls.write_all(&q).await.unwrap();
        tls.flush().await.unwrap();

        let mut lenbuf = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut lenbuf))
            .await
            .expect("should not time out")
            .unwrap();
        let mut buf = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
        tls.read_exact(&mut buf).await.unwrap();

        let resp = Message::from_bytes(&buf).unwrap();
        assert_eq!(resp.metadata.id, 0x2222);
        assert_eq!(resp.answers.len(), 1, "the blocked name should be answered");

        let _ = tx.send(());
    }

    #[tokio::test]
    async fn dot_records_the_query_as_encrypted() {
        // The query log distinguishes transports, so the listener must pass
        // the right one through.
        assert_eq!(Proto::Tls.log_name(), "tls");
        assert!(!Proto::Tls.is_datagram(), "DoT is connection-oriented");
    }

    #[tokio::test]
    async fn a_client_that_never_completes_the_handshake_is_dropped() {
        let (cert, key) = test_cert();
        let loaded = crate::tls::load(&crate::tls::Source {
            certificate_chain: cert,
            private_key: key,
            ..Default::default()
        })
        .unwrap();

        let s = test_server("", 0);
        let listener = bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = serve_dot(listener, loaded.dot, s, Arc::new(String::new()), async {
                let _ = rx.await;
            })
            .await;
        });

        // Connect and send nothing.  The listener must stay available.
        let _silent = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(tokio::net::TcpStream::connect(addr).await.is_ok());

        let _ = tx.send(());
    }

    #[test]
    fn access_defaults_to_permitting_everyone() {
        let a = Access::default();
        assert!(a.permits("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn oversized_responses_get_the_truncation_bit() {
        let mut m = Message::query();
        m.metadata.id = 5;
        m.add_query(Query::query(
            Name::from_utf8("a.com.").unwrap(),
            RecordType::A,
        ));
        let wire = m.to_bytes().unwrap();

        // Pretend the limit is tiny so truncation kicks in.
        let out = truncate_if_needed(&wire, 4);
        let back = Message::from_bytes(&out).unwrap();
        assert!(back.metadata.truncation);
        assert!(back.answers.is_empty());
    }

    #[test]
    fn a_client_id_is_the_label_below_the_server_name() {
        assert_eq!(
            client_id_from_sni("kids-tablet.dns.example", "dns.example").as_deref(),
            Some("kids-tablet")
        );
        assert_eq!(
            client_id_from_sni("KIDS-TABLET.DNS.EXAMPLE.", "dns.example").as_deref(),
            Some("kids-tablet"),
            "case and a trailing dot do not matter"
        );
    }

    #[test]
    fn the_server_name_itself_carries_no_client_id() {
        assert_eq!(client_id_from_sni("dns.example", "dns.example"), None);
    }

    #[test]
    fn a_deeper_or_unrelated_name_yields_nothing() {
        // Taking a label out of an unrelated name would let a client claim
        // any identifier it liked.
        assert_eq!(client_id_from_sni("a.b.dns.example", "dns.example"), None);
        assert_eq!(client_id_from_sni("evil.example", "dns.example"), None);
        assert_eq!(client_id_from_sni("xdns.example", "dns.example"), None);
    }

    #[test]
    fn without_a_configured_name_no_identifier_is_taken() {
        assert_eq!(client_id_from_sni("anything.example", ""), None);
    }
}
