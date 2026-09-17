//! Upstream resolver clients: plain DNS, DNS-over-TLS, DNS-over-HTTPS and
//! DNS-over-QUIC.
//!
//! Hostnames of encrypted upstreams are resolved through the configured
//! bootstrap resolvers rather than the system resolver, as upstream does —
//! otherwise the first query would depend on whatever resolver the host is
//! already using, which is often this very server.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::addr::{Transport, Upstream};
use crate::conn::Connections;

/// The largest DNS message this client will accept.
pub(crate) const MAX_MSG: usize = 64 * 1024;

/// The longest one address is given while others remain untried.
///
/// `upstream_timeout` defaults to ten seconds, and every client below this
/// server — dig at five, glibc at five twice over — has given up long before
/// that.  Spending the whole budget on the first of several addresses means
/// the rest are never reached at all, so each attempt but the last is capped
/// and the remainder of the budget is carried forward.
const ATTEMPT_CAP: Duration = Duration::from_secs(2);

/// The EDNS payload size advertised for UDP queries.
pub const UDP_PAYLOAD: usize = 4096;

/// An upstream exchange failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Network or I/O failure.
    #[error("upstream i/o: {0}")]
    Io(#[from] io::Error),

    /// The upstream did not answer in time.
    #[error("upstream timed out after {0:?}")]
    Timeout(Duration),

    /// The response could not be decoded.
    #[error("decoding response: {0}")]
    Decode(String),

    /// The upstream's hostname could not be resolved via bootstrap.
    #[error("bootstrapping {host}: {reason}")]
    Bootstrap {
        /// The hostname that failed to resolve.
        host: String,
        /// Why it failed.
        reason: String,
    },

    /// TLS setup or handshake failure.
    #[error("tls: {0}")]
    Tls(String),

    /// The HTTP layer of a DoH exchange failed.
    #[error("http: {0}")]
    Http(String),

    /// This build does not implement the upstream's transport.
    #[error("unsupported upstream transport: {0}")]
    Unsupported(String),

    /// A recent attempt to reach this upstream failed.
    ///
    /// Held for a moment after a dial fails so that a burst of queries
    /// against an upstream that is down fails at once, rather than each query
    /// in turn waiting out the whole `upstream_timeout` behind the same gate.
    #[error("upstream unreachable: {0}")]
    Unreachable(String),
}

/// The trust anchors and the TLS session cache every upstream draws on.
///
/// Both are expensive and both must be shared.  Parsing the webpki roots is
/// ~150 certificates' worth of work, and the `Resumption` store rustls builds
/// alongside them is what turns a reconnect into a one-round-trip resumed
/// handshake.  These used to be rebuilt inside each exchange, so no session
/// ticket ever outlived the query that obtained it and resumption was
/// impossible by construction.
static BASE: LazyLock<rustls::ClientConfig> = LazyLock::new(|| {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
});

/// Clones the shared base, offering one set of application protocols.
///
/// A clone carries the same `Arc`s for the verifier, the roots and the
/// resumption store, so all four profiles share one session cache — rustls
/// only honours a shared store between configurations whose verifiers are
/// pointer-identical, which cloning guarantees and rebuilding does not.
fn with_alpn(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
    let mut cfg = BASE.clone();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    Arc::new(cfg)
}

/// The profile for DNS-over-TLS.
pub(crate) static DOT: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| with_alpn(&[]));
/// The profile for DNS-over-HTTPS over TCP.
pub(crate) static HTTPS: LazyLock<Arc<rustls::ClientConfig>> =
    LazyLock::new(|| with_alpn(&[b"h2", b"http/1.1"]));
/// The profile for DNS-over-QUIC.
pub(crate) static DOQ: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| with_alpn(&[b"doq"]));
/// The profile for DNS-over-HTTPS carried by HTTP/3.
pub(crate) static H3: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| with_alpn(&[b"h3"]));

/// The shared rustls client configuration, trusting the webpki roots.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    DOT.clone()
}

/// Resolves the addresses an upstream should be contacted on.
///
/// A literal address is used directly; a hostname is resolved through the
/// bootstrap resolvers.
pub async fn resolve_upstream(
    up: &Upstream,
    bootstrap: &[SocketAddr],
    timeout: Duration,
    prefer_ipv6: bool,
) -> Result<Vec<SocketAddr>, Error> {
    if let Ok(ip) = up.host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, up.port)]);
    }

    if bootstrap.is_empty() {
        // Fall back to the system resolver rather than failing outright.
        let authority = up.authority();
        let addrs = tokio::net::lookup_host(&authority)
            .await
            .map_err(|e| Error::Bootstrap {
                host: up.host.clone(),
                reason: e.to_string(),
            })?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(Error::Bootstrap {
                host: up.host.clone(),
                reason: "no addresses".into(),
            });
        }

        return Ok(addrs);
    }

    let order = if prefer_ipv6 {
        [RecordType::AAAA, RecordType::A]
    } else {
        [RecordType::A, RecordType::AAAA]
    };

    let mut out = Vec::new();
    for qt in order {
        for bs in bootstrap {
            if let Ok(addrs) = bootstrap_lookup(&up.host, qt, *bs, timeout).await {
                out.extend(addrs.into_iter().map(|ip| SocketAddr::new(ip, up.port)));
                break;
            }
        }
        if !out.is_empty() {
            break;
        }
    }

    if out.is_empty() {
        return Err(Error::Bootstrap {
            host: up.host.clone(),
            reason: "no bootstrap resolver answered".into(),
        });
    }

    Ok(out)
}

/// Performs one plain-DNS lookup against a bootstrap resolver.
async fn bootstrap_lookup(
    host: &str,
    qt: RecordType,
    server: SocketAddr,
    timeout: Duration,
) -> Result<Vec<IpAddr>, Error> {
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    let name = Name::from_utf8(host).map_err(|e| Error::Bootstrap {
        host: host.to_string(),
        reason: e.to_string(),
    })?;

    let mut req = Message::query();
    req.metadata.id = rand::random::<u16>();
    req.metadata.recursion_desired = true;
    req.add_query(Query::query(name, qt));

    let resp = udp_exchange(&req, server, timeout).await?;

    Ok(resp
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect())
}

/// The absolute URI a DNS-over-HTTPS query is posted to.
///
/// The port belongs in the authority whenever it is not the default, or a
/// server hosting several names on one address is asked for the wrong one.
/// `Upstream::authority` already brackets an IPv6 literal.
fn doh_uri(up: &Upstream) -> String {
    if up.port == 443 {
        format!("https://{}{}", up.host, up.path)
    } else {
        format!("https://{}{}", up.authority(), up.path)
    }
}

/// Rejects a reply that does not answer the question that was asked.
///
/// dnsproxy checks this on every exchange — `upstream.validateResponse` —
/// and it matters more here than the name suggests: a reply is written
/// straight into the cache under the key of the question that *was* asked, so
/// an upstream answering something else poisons that name.  Names compare
/// case-insensitively, which is what `Name`'s own equality already does and
/// what dnsproxy's `strings.EqualFold` does.
pub(crate) fn check_reply(req: &Message, resp: &Message) -> Result<(), Error> {
    let Some(asked) = req.queries.first() else {
        return Ok(());
    };

    let [got] = resp.queries.as_slice() else {
        return Err(Error::Decode(format!(
            "reply carried {} questions, expected one",
            resp.queries.len()
        )));
    };

    if got.query_type() != asked.query_type() || got.query_class() != asked.query_class() {
        return Err(Error::Decode(format!(
            "reply answers {} {}, not {} {}",
            got.query_class(),
            got.query_type(),
            asked.query_class(),
            asked.query_type()
        )));
    }

    if !same_name(got.name(), asked.name()) {
        return Err(Error::Decode(format!(
            "reply answers {}, not {}",
            got.name(),
            asked.name()
        )));
    }

    Ok(())
}

/// Compares two names label by label, case-insensitively.
///
/// `Name`'s own equality also compares whether each name is fully qualified,
/// and those disagree here for a reason that is easy to miss: a name read off
/// the wire is always fully qualified, while one built from a configured
/// hostname — `bootstrap_lookup` doing `Name::from_utf8("dns.quad9.net")` —
/// is not.  Comparing with `==` therefore rejects every bootstrap reply and
/// takes every hostname upstream down with it.  What matters is the labels,
/// which is also what dnsproxy compares.
fn same_name(a: &hickory_proto::rr::Name, b: &hickory_proto::rr::Name) -> bool {
    a.num_labels() == b.num_labels()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// Sends a query over UDP and reads the reply.
pub async fn udp_exchange(
    req: &Message,
    server: SocketAddr,
    timeout: Duration,
) -> Result<Message, Error> {
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("static addr")
    } else {
        "[::]:0".parse().expect("static addr")
    };

    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;

    let wire = req.to_bytes().map_err(|e| Error::Decode(e.to_string()))?;
    sock.send(&wire).await?;

    let mut buf = vec![0u8; UDP_PAYLOAD];
    loop {
        let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout(timeout))??;

        let resp = Message::from_bytes(&buf[..n]).map_err(|e| Error::Decode(e.to_string()))?;
        // Ignore replies that do not belong to this query.  A datagram
        // carrying the right identifier but the wrong question is not a
        // stray, it is an attempt at the cache, so it fails the exchange
        // rather than being waited past.
        if resp.metadata.id == req.metadata.id {
            check_reply(req, &resp)?;

            return Ok(resp);
        }
    }
}

/// Sends a query over a stream that speaks DNS with a two-byte length prefix.
pub(crate) async fn stream_exchange<S>(
    stream: &mut S,
    req: &Message,
    timeout: Duration,
) -> Result<Message, Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let wire = req.to_bytes().map_err(|e| Error::Decode(e.to_string()))?;
    let len = u16::try_from(wire.len())
        .map_err(|_| Error::Decode("request too large for TCP framing".into()))?;

    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&wire);

    tokio::time::timeout(timeout, async {
        stream.write_all(&framed).await?;
        stream.flush().await?;

        let mut lenbuf = [0u8; 2];
        stream.read_exact(&mut lenbuf).await?;
        let n = usize::from(u16::from_be_bytes(lenbuf));
        if n > MAX_MSG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "response too large",
            ));
        }

        let mut buf = vec![0u8; n];
        stream.read_exact(&mut buf).await?;

        Ok::<_, io::Error>(buf)
    })
    .await
    .map_err(|_| Error::Timeout(timeout))?
    .map_err(Error::Io)
    .and_then(|buf| Message::from_bytes(&buf).map_err(|e| Error::Decode(e.to_string())))
    .and_then(|resp| {
        // Nothing checked the reply here before, which was survivable only
        // because the connection was thrown away afterwards.  A pooled
        // connection that has just produced a frame belonging to some other
        // query must not be reused, so this is a prerequisite for keeping
        // one, not only a hardening step.
        if resp.metadata.id != req.metadata.id {
            return Err(Error::Decode(format!(
                "reply carried id {:#06x}, expected {:#06x}",
                resp.metadata.id, req.metadata.id
            )));
        }
        check_reply(req, &resp)?;

        Ok(resp)
    })
}

/// Sends a query over TCP.
pub async fn tcp_exchange(
    req: &Message,
    server: SocketAddr,
    timeout: Duration,
) -> Result<Message, Error> {
    let mut s = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    s.set_nodelay(true).ok();

    stream_exchange(&mut s, req, timeout).await
}

/// A resolved, ready-to-use upstream.
#[derive(Debug)]
pub struct Client {
    /// The specification this client serves.
    pub upstream: Upstream,
    /// The addresses to contact, in preference order.
    addrs: Vec<SocketAddr>,
    /// What is kept open to each of those addresses.
    ///
    /// Indexed by position in `addrs`, which is resolved once and never
    /// reordered, so the two stay aligned for the life of the client.
    conns: Connections,
    /// The absolute URI a DNS-over-HTTPS query is posted to.
    ///
    /// Built once, because it never varies for a client, and because the
    /// authority has to carry the port whenever it is not the default: an
    /// upstream reached on a custom port was otherwise asked for the wrong
    /// virtual host.
    doh_uri: String,
    /// Whether DNS-over-HTTPS should be tried over HTTP/3 first.
    prefer_http3: bool,
    /// The index into `addrs` that answered last.
    ///
    /// Addresses are resolved once and never reordered, so without this a
    /// dead first address is paid for on every query for the life of the
    /// process rather than once.
    preferred: AtomicUsize,
}

impl Client {
    /// Resolves an upstream and builds a client for it.
    pub async fn connect(
        upstream: Upstream,
        bootstrap: &[SocketAddr],
        timeout: Duration,
        prefer_ipv6: bool,
        tls: Arc<rustls::ClientConfig>,
    ) -> Result<Self, Error> {
        if !upstream.is_supported() {
            return Err(Error::Unsupported(upstream.original.clone()));
        }

        let addrs = resolve_upstream(&upstream, bootstrap, timeout, prefer_ipv6).await?;
        let conns = Connections::new(&addrs, &tls);

        Ok(Self {
            doh_uri: doh_uri(&upstream),
            upstream,
            addrs,
            conns,
            prefer_http3: false,
            preferred: AtomicUsize::new(0),
        })
    }

    /// Asks for DNS-over-HTTPS to be tried over HTTP/3 first.
    ///
    /// This is `use_http3_upstreams`.  A server that does not speak it fails
    /// the handshake and the exchange falls back to HTTP/2, so the setting
    /// cannot make an upstream unusable.
    pub fn with_http3(mut self, yes: bool) -> Self {
        self.prefer_http3 = yes;

        self
    }

    /// Builds a client with no resolved addresses.
    ///
    /// Every exchange fails; used where a checker needs an upstream to hold
    /// but the test never lets it reach the network.
    pub fn offline(upstream: Upstream) -> Self {
        Self {
            doh_uri: doh_uri(&upstream),
            upstream,
            addrs: Vec::new(),
            conns: Connections::new(&[], &tls_config()),
            prefer_http3: false,
            preferred: AtomicUsize::new(0),
        }
    }

    /// Closes every connection this client is holding open.
    ///
    /// `POST /control/test_upstream_dns` builds a throwaway client for each
    /// probe, and a connection kept for a client nobody will ask again is a
    /// socket and a driver task leaked per probe.  [`Drop`] calls this, so
    /// the only reason to call it directly is to hang up early.
    pub fn close(&self) {
        self.conns.close();
    }

    /// Sends a query and returns the reply.
    ///
    /// A truncated UDP answer is retried over TCP, as a resolver must.
    pub async fn exchange(&self, req: &Message, timeout: Duration) -> Result<Message, Error> {
        if matches!(self.upstream.transport, Transport::Stamp) {
            return Err(Error::Unsupported(self.upstream.original.clone()));
        }

        let n = self.addrs.len();
        if n == 0 {
            return Err(Error::Bootstrap {
                host: self.upstream.host.clone(),
                reason: "no addresses to try".into(),
            });
        }

        let deadline = Instant::now() + timeout;
        let first = self.preferred.load(Ordering::Relaxed) % n;
        let mut last: Option<Error> = None;

        for step in 0..n {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }

            // Whatever is left goes to the final attempt; the others are
            // capped so one blackholed address cannot consume the lot.
            let budget = if step + 1 == n {
                left
            } else {
                left.min(ATTEMPT_CAP)
            };

            let i = (first + step) % n;
            let addr = self.addrs[i];

            let host = &self.upstream.host;
            let uri = self.doh_uri.as_str();

            let r = match self.upstream.transport {
                Transport::Udp => match udp_exchange(req, addr, budget).await {
                    Ok(resp) if resp.metadata.truncation => self.conns.tcp(i, req, budget).await,
                    other => other,
                },
                Transport::Tcp => self.conns.tcp(i, req, budget).await,
                Transport::Tls => self.conns.tls(i, req, host, budget).await,
                Transport::Https if self.prefer_http3 => {
                    match self.conns.https3(i, req, host, uri, budget).await {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            tracing::debug!(
                                upstream = %self.upstream,
                                error = %e,
                                "http/3 failed; falling back to http/2"
                            );

                            self.conns.https(i, req, host, uri, budget).await
                        }
                    }
                }
                Transport::Https => self.conns.https(i, req, host, uri, budget).await,
                Transport::Quic => self.conns.quic(i, req, host, budget).await,
                Transport::Stamp => unreachable!("rejected above"),
            };

            match r {
                Ok(resp) => {
                    if i != first {
                        self.preferred.store(i, Ordering::Relaxed);
                    }

                    return Ok(resp);
                }
                Err(e) => last = Some(e),
            }
        }

        Err(last.unwrap_or(Error::Timeout(timeout)))
    }

    /// The addresses this client will contact.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
    }
}

impl Drop for Client {
    /// Hangs up rather than leaving the connections to time out.
    fn drop(&mut self) {
        self.close();
    }
}

/// Reports whether a response indicates an upstream failure worth retrying
/// against another upstream.
pub fn is_failure(resp: &Message) -> bool {
    matches!(
        resp.metadata.response_code,
        ResponseCode::ServFail | ResponseCode::Refused | ResponseCode::NotImp
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    fn query(name: &str) -> Message {
        let mut m = Message::query();
        m.metadata.id = 0x4242;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

        m
    }

    #[test]
    fn tls_config_loads_the_webpki_roots() {
        let c = tls_config();
        assert!(Arc::strong_count(&c) >= 1);
        assert!(HTTPS.alpn_protocols.contains(&b"h2".to_vec()));
    }

    #[tokio::test]
    async fn literal_addresses_skip_bootstrap() {
        let up = addr::parse("1.2.3.4:53").unwrap().upstream.unwrap();
        let got = resolve_upstream(&up, &[], Duration::from_secs(1), false)
            .await
            .unwrap();
        assert_eq!(got, vec!["1.2.3.4:53".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn ipv6_literals_resolve_to_themselves() {
        let up = addr::parse("[2620:fe::10]:853").unwrap().upstream.unwrap();
        let got = resolve_upstream(&up, &[], Duration::from_secs(1), false)
            .await
            .unwrap();
        assert_eq!(
            got,
            vec!["[2620:fe::10]:853".parse::<SocketAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn a_dnscrypt_stamp_is_rejected_up_front() {
        // DNSCrypt is excluded by design; a stamp must be refused at startup
        // rather than accepted and then silently never used.
        let up = addr::parse("sdns://AQcAAAAAAAAAAAA")
            .unwrap()
            .upstream
            .unwrap();
        let err = Client::connect(up, &[], Duration::from_secs(1), false, tls_config())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }

    #[tokio::test]
    async fn quic_upstreams_are_accepted() {
        let up = addr::parse("quic://dns.adguard.com")
            .unwrap()
            .upstream
            .unwrap();
        assert!(up.is_supported());
        assert_eq!(up.port, 853);
    }

    #[tokio::test]
    async fn udp_exchange_times_out_against_a_black_hole() {
        // Port 1 on loopback: nothing listens, so this must time out or be
        // refused rather than hang.
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = udp_exchange(&query("example.com."), server, Duration::from_millis(300)).await;
        assert!(r.is_err(), "expected failure, got {r:?}");
    }

    #[tokio::test]
    async fn tcp_exchange_fails_fast_when_refused() {
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let r = tcp_exchange(&query("example.com."), server, Duration::from_millis(500)).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn udp_exchange_round_trips_against_a_local_echo_server() {
        // A minimal server that answers with a fixed A record.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf[..n]).unwrap();
            let resp = crate::msg::with_addrs(&req, &["93.184.216.34".parse().unwrap()], 300);
            sock.send_to(&resp.to_bytes().unwrap(), peer).await.unwrap();
        });

        let resp = udp_exchange(&query("example.com."), addr, Duration::from_secs(2))
            .await
            .expect("exchange should succeed");
        assert_eq!(resp.metadata.id, 0x4242);
        assert_eq!(resp.answers.len(), 1);
    }

    #[tokio::test]
    async fn tcp_exchange_round_trips_against_a_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut lenbuf = [0u8; 2];
            s.read_exact(&mut lenbuf).await.unwrap();
            let n = usize::from(u16::from_be_bytes(lenbuf));
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf).unwrap();
            let resp = crate::msg::with_addrs(&req, &["1.2.3.4".parse().unwrap()], 60);
            let wire = resp.to_bytes().unwrap();
            s.write_all(&(wire.len() as u16).to_be_bytes())
                .await
                .unwrap();
            s.write_all(&wire).await.unwrap();
            s.flush().await.unwrap();
        });

        let resp = tcp_exchange(&query("example.com."), addr, Duration::from_secs(2))
            .await
            .expect("exchange should succeed");
        assert_eq!(resp.answers.len(), 1);
    }

    /// A live upstream sitting behind a blackholed one.
    ///
    /// `Client::exchange` walks `addrs` in order, and every attempt used to
    /// get the whole budget, so one unroutable address cost the full
    /// `upstream_timeout` — ten seconds by default — on every single query.
    #[tokio::test]
    async fn a_dead_first_address_does_not_cost_the_full_timeout() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(req) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let resp = crate::msg::with_addrs(&req, &["1.2.3.4".parse().unwrap()], 60);
                let _ = sock.send_to(&resp.to_bytes().unwrap(), peer).await;
            }
        });

        // TEST-NET-1 is routed nowhere, so it times out rather than being
        // refused: the shape a genuinely dead upstream address has.
        let dead: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let addrs = vec![dead, live];
        let up = addr::parse("192.0.2.1").unwrap().upstream.unwrap();
        let c = Client {
            doh_uri: doh_uri(&up),
            upstream: up,
            conns: Connections::new(&addrs, &tls_config()),
            addrs,
            prefer_http3: false,
            preferred: AtomicUsize::new(0),
        };

        let started = std::time::Instant::now();
        let got = c
            .exchange(&query("example.com."), Duration::from_secs(10))
            .await;
        let took = started.elapsed();

        assert!(
            got.is_ok(),
            "the live address should have answered: {got:?}"
        );
        assert!(
            took < Duration::from_secs(3),
            "a dead first address cost {took:?} of a ten-second budget"
        );
    }

    /// The shape bootstrap uses: a question built from a configured hostname,
    /// which carries no trailing dot, answered by a name read off the wire,
    /// which always does.
    ///
    /// `Name`'s own equality compares that flag too, so validating with `==`
    /// rejected every bootstrap reply and took every hostname upstream down
    /// with it.  The tests above did not catch it because they spell their
    /// names with the dot.
    #[tokio::test]
    async fn a_reply_matches_a_question_built_without_a_trailing_dot() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let (n, peer) = sock.recv_from(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf[..n]).unwrap();
            let resp = crate::msg::with_addrs(&req, &["9.9.9.9".parse().unwrap()], 300);
            sock.send_to(&resp.to_bytes().unwrap(), peer).await.unwrap();
        });

        let mut req = Message::query();
        req.metadata.id = 0x4242;
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(
            Name::from_utf8("dns.quad9.net").unwrap(),
            RecordType::A,
        ));
        assert!(!req.queries[0].name().is_fqdn(), "the premise of this test");

        let got = udp_exchange(&req, addr, Duration::from_secs(2)).await;
        assert!(got.is_ok(), "a bootstrap reply must be accepted: {got:?}");
    }

    /// An upstream answering a question that was never asked.
    ///
    /// dnsproxy checks the question section on every reply
    /// (`upstream.validateResponse`); the stream path here checked nothing, so
    /// the answer was returned to the caller and cached under the *requested*
    /// name.
    #[tokio::test]
    async fn a_stream_response_for_another_question_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut lenbuf = [0u8; 2];
            s.read_exact(&mut lenbuf).await.unwrap();
            let n = usize::from(u16::from_be_bytes(lenbuf));
            let mut buf = vec![0u8; n];
            s.read_exact(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf).unwrap();

            let mut resp = crate::msg::with_addrs(
                &query("attacker.example."),
                &["6.6.6.6".parse().unwrap()],
                60,
            );
            resp.metadata.id = req.metadata.id;

            let wire = resp.to_bytes().unwrap();
            s.write_all(&(wire.len() as u16).to_be_bytes())
                .await
                .unwrap();
            s.write_all(&wire).await.unwrap();
            s.flush().await.unwrap();
        });

        let got = tcp_exchange(&query("example.com."), addr, Duration::from_secs(2)).await;
        assert!(
            got.is_err(),
            "a reply for a different question must be rejected, got {got:?}"
        );
    }

    /// A DoH upstream on a port other than 443.
    ///
    /// The port has to reach the authority, or a server hosting several names
    /// on one address answers for the wrong one.
    #[test]
    fn a_custom_port_reaches_the_doh_authority() {
        let up = |s: &str| addr::parse(s).unwrap().upstream.unwrap();

        assert_eq!(
            doh_uri(&up("https://dns.example/dns-query")),
            "https://dns.example/dns-query",
            "the default port stays out of the authority"
        );
        assert_eq!(
            doh_uri(&up("https://dns.example:8443/dns-query")),
            "https://dns.example:8443/dns-query"
        );
        assert_eq!(
            doh_uri(&up("https://[2001:db8::1]:8443/dns-query")),
            "https://[2001:db8::1]:8443/dns-query",
            "an IPv6 literal stays bracketed"
        );
    }

    #[test]
    fn failure_classification() {
        let mut m = Message::query();
        m.metadata.response_code = ResponseCode::ServFail;
        assert!(is_failure(&m));

        m.metadata.response_code = ResponseCode::NXDomain;
        assert!(!is_failure(&m), "NXDOMAIN is a valid answer, not a failure");

        m.metadata.response_code = ResponseCode::NoError;
        assert!(!is_failure(&m));
    }
}
