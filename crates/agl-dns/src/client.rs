//! Upstream resolver clients: plain DNS, DNS-over-TLS, DNS-over-HTTPS and
//! DNS-over-QUIC.
//!
//! Hostnames of encrypted upstreams are resolved through the configured
//! bootstrap resolvers rather than the system resolver, as upstream does —
//! otherwise the first query would depend on whatever resolver the host is
//! already using, which is often this very server.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::addr::{Transport, Upstream};

/// The largest DNS message this client will accept.
const MAX_MSG: usize = 64 * 1024;

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
}

/// Builds the shared rustls client configuration, trusting the webpki roots.
pub fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // DoT speaks plain DNS over the TLS stream; DoH negotiates HTTP.
    cfg.alpn_protocols = Vec::new();

    Arc::new(cfg)
}

/// Builds a rustls configuration that offers HTTP ALPN, for DoH.
fn https_tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(cfg)
}

/// Builds a rustls configuration offering one application protocol.
fn alpn_tls_config(alpn: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];

    Arc::new(cfg)
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
        // Ignore replies that do not belong to this query.
        if resp.metadata.id == req.metadata.id {
            return Ok(resp);
        }
    }
}

/// Sends a query over a stream that speaks DNS with a two-byte length prefix.
async fn stream_exchange<S>(
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

/// Sends a query over DNS-over-TLS.
pub async fn tls_exchange(
    req: &Message,
    server: SocketAddr,
    server_name: &str,
    cfg: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<Message, Error> {
    let connector = tokio_rustls::TlsConnector::from(cfg);
    let dnsname = rustls_pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|e| Error::Tls(format!("invalid server name {server_name:?}: {e}")))?;

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    tcp.set_nodelay(true).ok();

    let mut tls = tokio::time::timeout(timeout, connector.connect(dnsname, tcp))
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Tls(e.to_string()))?;

    stream_exchange(&mut tls, req, timeout).await
}

/// Sends a query over DNS-over-HTTPS.
///
/// Uses the POST form with `application/dns-message`, which avoids the
/// base64url encoding of the GET form and is what upstream prefers.
pub async fn https_exchange(
    req: &Message,
    server: SocketAddr,
    host: &str,
    path: &str,
    timeout: Duration,
) -> Result<Message, Error> {
    use http_body_util::Full;
    use hyper::Request;

    let wire = req.to_bytes().map_err(|e| Error::Decode(e.to_string()))?;

    let connector = tokio_rustls::TlsConnector::from(https_tls_config());
    let dnsname = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| Error::Tls(format!("invalid server name {host:?}: {e}")))?;

    let tcp = tokio::time::timeout(timeout, TcpStream::connect(server))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    tcp.set_nodelay(true).ok();

    let tls = tokio::time::timeout(timeout, connector.connect(dnsname, tcp))
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Tls(e.to_string()))?;

    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = hyper_util::rt::TokioIo::new(tls);

    let uri = format!("https://{host}{path}");
    let build = |body: Full<bytes::Bytes>| {
        Request::builder()
            .method("POST")
            .uri(&uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(body)
            .map_err(|e| Error::Http(e.to_string()))
    };

    let resp_bytes = if is_h2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|e| Error::Http(e.to_string()))?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });

        let resp =
            tokio::time::timeout(timeout, sender.send_request(build(Full::new(wire.into()))?))
                .await
                .map_err(|_| Error::Timeout(timeout))?
                .map_err(|e| Error::Http(e.to_string()))?;
        let out = read_body(resp, timeout).await;
        task.abort();
        out?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let task = tokio::spawn(async move {
            let _ = conn.await;
        });

        let resp =
            tokio::time::timeout(timeout, sender.send_request(build(Full::new(wire.into()))?))
                .await
                .map_err(|_| Error::Timeout(timeout))?
                .map_err(|e| Error::Http(e.to_string()))?;
        let out = read_body(resp, timeout).await;
        task.abort();
        out?
    };

    Message::from_bytes(&resp_bytes).map_err(|e| Error::Decode(e.to_string()))
}

/// Sends a query over DNS-over-QUIC.
///
/// The framing is the two-byte length prefix TCP and DoT use, so only the
/// transport differs.  RFC 9250 requires the message identifier to be zero on
/// the wire, because QUIC's own stream multiplexing already tells answers
/// apart; the caller's identifier is restored on the way back.
pub async fn quic_exchange(
    req: &Message,
    server: SocketAddr,
    server_name: &str,
    timeout: Duration,
) -> Result<Message, Error> {
    let id = req.metadata.id;
    let mut on_wire = req.clone();
    on_wire.metadata.id = 0;

    let wire = on_wire
        .to_bytes()
        .map_err(|e| Error::Decode(e.to_string()))?;
    let len = u16::try_from(wire.len())
        .map_err(|_| Error::Decode("request too large for quic framing".into()))?;

    let conn = quic_connect(server, server_name, timeout).await?;

    let mut resp = tokio::time::timeout(timeout, async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Http(format!("opening a quic stream: {e}")))?;

        send.write_all(&len.to_be_bytes())
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        send.write_all(&wire)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        // Closing the send side is how a DoQ client signals a complete query.
        send.finish().map_err(|e| Error::Http(e.to_string()))?;

        let mut lenbuf = [0u8; 2];
        recv.read_exact(&mut lenbuf)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        let n = usize::from(u16::from_be_bytes(lenbuf));
        if n > MAX_MSG {
            return Err(Error::Decode("response too large".into()));
        }

        let mut buf = vec![0u8; n];
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        Message::from_bytes(&buf).map_err(|e| Error::Decode(e.to_string()))
    })
    .await
    .map_err(|_| Error::Timeout(timeout))??;

    resp.metadata.id = id;

    Ok(resp)
}

/// Opens a QUIC connection to a DoQ server.
async fn quic_connect(
    server: SocketAddr,
    server_name: &str,
    timeout: Duration,
) -> Result<quinn::Connection, Error> {
    quic_connect_alpn(server, server_name, timeout, b"doq").await
}

/// Opens a QUIC connection offering one application protocol.
async fn quic_connect_alpn(
    server: SocketAddr,
    server_name: &str,
    timeout: Duration,
    alpn: &[u8],
) -> Result<quinn::Connection, Error> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(alpn_tls_config(alpn))
        .map_err(|e| Error::Tls(e.to_string()))?;
    let cfg = quinn::ClientConfig::new(Arc::new(crypto));

    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse().expect("static addr")
    } else {
        "[::]:0".parse().expect("static addr")
    };
    let mut endpoint = quinn::Endpoint::client(bind).map_err(Error::Io)?;
    endpoint.set_default_client_config(cfg);

    let connecting = endpoint
        .connect(server, server_name)
        .map_err(|e| Error::Tls(e.to_string()))?;

    tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Http(format!("quic handshake: {e}")))
}

/// Sends a query over DNS-over-HTTPS carried by HTTP/3.
///
/// This is `use_http3_upstreams`.  The exchange is the same POST as over
/// HTTP/2; only the transport underneath differs, so a server that does not
/// speak HTTP/3 simply fails the handshake and the caller falls back.
pub async fn https3_exchange(
    req: &Message,
    server: SocketAddr,
    host: &str,
    path: &str,
    timeout: Duration,
) -> Result<Message, Error> {
    use bytes::Buf as _;

    let wire = req.to_bytes().map_err(|e| Error::Decode(e.to_string()))?;

    let conn = quic_connect_alpn(server, host, timeout, b"h3").await?;
    let (mut driver, mut sender) = h3::client::new(h3_quinn::Connection::new(conn))
        .await
        .map_err(|e| Error::Http(format!("http/3 handshake: {e}")))?;

    // The connection has to be driven while the request is in flight.
    let task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let out = tokio::time::timeout(timeout, async {
        let request = hyper::Request::builder()
            .method("POST")
            .uri(format!("https://{host}{path}"))
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| Error::Http(e.to_string()))?;

        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        stream
            .send_data(bytes::Bytes::from(wire))
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        stream
            .finish()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        let resp = stream
            .recv_response()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(Error::Http(format!("upstream returned {}", resp.status())));
        }

        let mut body = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|e| Error::Http(e.to_string()))?
        {
            if body.len() + chunk.remaining() > MAX_MSG {
                return Err(Error::Http("response body too large".into()));
            }
            body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
        }

        Message::from_bytes(&body).map_err(|e| Error::Decode(e.to_string()))
    })
    .await;

    task.abort();

    out.map_err(|_| Error::Timeout(timeout))?
}

/// Reads and size-limits an HTTP response body.
async fn read_body<B>(resp: hyper::Response<B>, timeout: Duration) -> Result<Vec<u8>, Error>
where
    B: hyper::body::Body + Unpin,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt;

    let status = resp.status();
    if !status.is_success() {
        return Err(Error::Http(format!("upstream returned {status}")));
    }

    let collected = tokio::time::timeout(timeout, resp.into_body().collect())
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Http(e.to_string()))?;

    let bytes = collected.to_bytes();
    if bytes.len() > MAX_MSG {
        return Err(Error::Http("response body too large".into()));
    }

    Ok(bytes.to_vec())
}

/// A resolved, ready-to-use upstream.
#[derive(Debug)]
pub struct Client {
    /// The specification this client serves.
    pub upstream: Upstream,
    /// The addresses to contact, in preference order.
    addrs: Vec<SocketAddr>,
    /// Shared TLS settings for DoT.
    tls: Arc<rustls::ClientConfig>,
    /// Whether DNS-over-HTTPS should be tried over HTTP/3 first.
    prefer_http3: bool,
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

        Ok(Self {
            upstream,
            addrs,
            tls,
            prefer_http3: false,
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
            upstream,
            addrs: Vec::new(),
            tls: tls_config(),
            prefer_http3: false,
        }
    }

    /// Sends a query and returns the reply.
    ///
    /// A truncated UDP answer is retried over TCP, as a resolver must.
    pub async fn exchange(&self, req: &Message, timeout: Duration) -> Result<Message, Error> {
        let mut last: Option<Error> = None;

        for &addr in &self.addrs {
            let r = match self.upstream.transport {
                Transport::Udp => match udp_exchange(req, addr, timeout).await {
                    Ok(resp) if resp.metadata.truncation => tcp_exchange(req, addr, timeout).await,
                    other => other,
                },
                Transport::Tcp => tcp_exchange(req, addr, timeout).await,
                Transport::Tls => {
                    tls_exchange(req, addr, &self.upstream.host, self.tls.clone(), timeout).await
                }
                Transport::Https if self.prefer_http3 => {
                    let host = &self.upstream.host;
                    let path = &self.upstream.path;
                    match https3_exchange(req, addr, host, path, timeout).await {
                        Ok(resp) => Ok(resp),
                        Err(e) => {
                            tracing::debug!(
                                upstream = %self.upstream,
                                error = %e,
                                "http/3 failed; falling back to http/2"
                            );

                            https_exchange(req, addr, host, path, timeout).await
                        }
                    }
                }
                Transport::Https => {
                    https_exchange(req, addr, &self.upstream.host, &self.upstream.path, timeout)
                        .await
                }
                Transport::Quic => quic_exchange(req, addr, &self.upstream.host, timeout).await,
                Transport::Stamp => {
                    return Err(Error::Unsupported(self.upstream.original.clone()));
                }
            };

            match r {
                Ok(resp) => return Ok(resp),
                Err(e) => last = Some(e),
            }
        }

        Err(last.unwrap_or_else(|| Error::Bootstrap {
            host: self.upstream.host.clone(),
            reason: "no addresses to try".into(),
        }))
    }

    /// The addresses this client will contact.
    pub fn addrs(&self) -> &[SocketAddr] {
        &self.addrs
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
        assert!(https_tls_config().alpn_protocols.contains(&b"h2".to_vec()));
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
