//! Connections to an upstream that outlive the query that opened them.
//!
//! Every encrypted transport pays for a handshake before it can carry
//! anything, and that handshake used to be paid on *every* query, because
//! each exchange dialled, asked and hung up.  Measured against a public
//! resolver it cost a hundred milliseconds or so — DoT 103 ms, DoH 108 ms,
//! DoQ 110 ms, HTTP/3 112 ms above the one-round-trip floor — while the local
//! processing of the same query takes forty microseconds.  The handshake was
//! three orders of magnitude more expensive than the work it carried.
//!
//! What is kept depends on what the protocol can do with it:
//!
//!   * HTTP/2, HTTP/3 and QUIC multiplex, so one connection serves every
//!     query at once and the slot holds a handle that is cloned per request;
//!   * DNS-over-TLS and plain TCP do not, so a connection is checked out
//!     exclusively and returned only once a complete, validated response has
//!     been read off it.
//!
//! Two things here are load-bearing, and both are easier to get wrong than
//! right:
//!
//!   * **Dialling is single-flight.**  A burst of queries against a cold
//!     multiplexing upstream must open one connection between them, not one
//!     each, so a dial is made behind a gate and everything that waited at
//!     the gate finds the connection the winner installed.
//!   * **...which is exactly why a failed dial is remembered.**  A gate in
//!     front of an upstream that is *down* would queue every query behind a
//!     dial that takes the whole `upstream_timeout` to fail, and then do it
//!     again for the next one: ten seconds each, in turn.  That is a far
//!     worse regression than the handshake this module removes, so a failure
//!     blocks further dials for a moment and is handed to everyone waiting.
//!
//! Nothing here holds a [`parking_lot`] guard across an `.await`.  The
//! futures this module returns are spawned into a `JoinSet` by
//! [`crate::pool`], which requires them to be `Send`, and that set is
//! `abort_all`ed as soon as one upstream answers — so every exchange must
//! also be safe to drop half-way.  A checked-out stream is dropped with the
//! future and never returned to the pool; a multiplexed request simply loses
//! its own stream.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use http_body_util::Full;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::client::{Error, MAX_MSG, check_reply, stream_exchange};

/// How long a failed dial suppresses the next one to the same address.
///
/// Long enough that a burst of queries against a dead upstream fails at once
/// instead of one timeout at a time, short enough that an upstream coming
/// back is noticed within a query or two.
const DIAL_BACKOFF: Duration = Duration::from_secs(1);

/// How long a connection may sit idle before it is dropped rather than used.
///
/// Enforced when one is checked out rather than by a reaper task, the same
/// lazy sweep [`crate::ratelimit`] uses: a resolver that is not being asked
/// anything has nothing to tidy.
const IDLE_CAP: Duration = Duration::from_secs(10);

/// The most idle connections one address keeps.
///
/// This caps what is *kept*, not what may be in flight: a burst opens as many
/// connections as it needs and returns as many as fit.
const IDLE_MAX: usize = 4;

/// Beyond this much idle time a reused connection is treated as suspect.
const SUSPECT_AFTER: Duration = Duration::from_secs(1);

/// The least a suspect connection is given before the retry takes over.
const PROBE_FLOOR: Duration = Duration::from_millis(500);

/// How often HTTP/2 pings an otherwise idle connection.
///
/// Without this a connection that a NAT table has quietly forgotten looks
/// perfectly healthy until a query is sent down it and waits out the whole
/// timeout.
const H2_KEEPALIVE: Duration = Duration::from_secs(30);

/// How long a QUIC connection may be idle before either end may drop it.
const QUIC_IDLE: Duration = Duration::from_secs(30);

/// How often a QUIC connection is kept alive.
///
/// Twenty seconds is dnsproxy's `QUICKeepAlivePeriod`, and it is deliberately
/// below [`QUIC_IDLE`] so the connection is refreshed before either end may
/// time it out.
const QUIC_KEEPALIVE: Duration = Duration::from_secs(20);

/// The application error code both DoQ and HTTP/3 use for "nothing is wrong".
///
/// `DOQ_NO_ERROR` and `H3_NO_ERROR` are both zero, which is what a server
/// sends when it retires a connection it has no further complaint about.
const NO_ERROR: u32 = 0;

/// The HTTP/2 request sender, which every query to one address shares.
type H2Sender = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

/// The HTTP/1.1 request sender, which carries one query at a time.
type H1Sender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

/// The HTTP/3 request sender.
type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// A DNS-over-TLS stream.
type DotStream = tokio_rustls::client::TlsStream<TcpStream>;

/// The TLS profiles a client offers, one per application protocol.
///
/// Every caller in the binary passes [`crate::client::tls_config`], the
/// shared default, and that case is answered with the shared per-protocol
/// statics: they hold one another's session cache, so a handshake that does
/// have to happen can still be resumed.  A caller that brought its own roots
/// — a test pointing a client at a local server, in practice — gets the same
/// set derived from what it passed, since the four profiles differ only in
/// the protocols they advertise.
#[derive(Clone, Debug)]
struct Profiles {
    /// DNS-over-TLS, which negotiates no application protocol.
    dot: Arc<rustls::ClientConfig>,
    /// DNS-over-HTTPS over TCP, offering HTTP/2 and HTTP/1.1.
    https: Arc<rustls::ClientConfig>,
    /// DNS-over-QUIC.
    doq: Arc<rustls::ClientConfig>,
    /// DNS-over-HTTPS carried by HTTP/3.
    h3: Arc<rustls::ClientConfig>,
}

impl Profiles {
    /// The profiles to use when `root` holds the trust configuration.
    fn derive(root: &Arc<rustls::ClientConfig>) -> Self {
        if Arc::ptr_eq(root, &crate::client::DOT) {
            return Self {
                dot: crate::client::DOT.clone(),
                https: crate::client::HTTPS.clone(),
                doq: crate::client::DOQ.clone(),
                h3: crate::client::H3.clone(),
            };
        }

        let alpn = |protocols: &[&[u8]]| {
            let mut cfg = (**root).clone();
            cfg.alpn_protocols = protocols.iter().map(|p| p.to_vec()).collect();

            Arc::new(cfg)
        };

        Self {
            dot: root.clone(),
            https: alpn(&[b"h2", b"http/1.1"]),
            doq: alpn(&[b"doq"]),
            h3: alpn(&[b"h3"]),
        }
    }
}

/// A connection idling between the queries that use it.
struct Idle<T> {
    /// The connection itself.
    conn: T,
    /// When it was handed back.
    since: Instant,
    /// How long the exchange that last used it took.
    rtt: Duration,
}

impl<T> Idle<T> {
    /// Wraps a connection that has only just been opened.
    fn fresh(conn: T) -> Self {
        Self {
            conn,
            since: Instant::now(),
            rtt: Duration::ZERO,
        }
    }

    /// How long this connection gets before the exchange gives up on it.
    ///
    /// A connection that has been idle for a moment may have been dropped by
    /// a NAT table or a load balancer without a packet being sent to say so,
    /// and the loss is only discovered by waiting.  Waiting out the whole
    /// `upstream_timeout` before dialling a fresh one would turn a reuse that
    /// saves a handshake into one that costs ten seconds, so a connection
    /// that has sat still gets roughly as long as it has ever needed and the
    /// rest of the budget is left to the retry.
    fn budget(&self, whole: Duration) -> Duration {
        if self.since.elapsed() <= SUSPECT_AFTER {
            return whole;
        }

        whole.min(PROBE_FLOOR.max(self.rtt.saturating_mul(4)))
    }
}

/// Connections handed out to one query at a time.
struct Pool<T> {
    /// The idle connections, least recently used first.
    idle: parking_lot::Mutex<VecDeque<Idle<T>>>,
}

impl<T> Default for Pool<T> {
    fn default() -> Self {
        Self {
            idle: parking_lot::Mutex::new(VecDeque::new()),
        }
    }
}

impl<T> fmt::Debug for Pool<T> {
    /// Says only what this is: taking the lock to report what is in it would
    /// deadlock against whoever is formatting while holding it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pool")
    }
}

impl<T> Pool<T> {
    /// Takes the most recently used connection that still looks usable.
    ///
    /// Most recently used rather than least: dnsproxy carries a standing note
    /// that its own pool hands connections out in FILO order and so lets the
    /// ones at the bottom rot.  Returning to the back and taking from the
    /// back keeps the busy connections busy and lets the rest age out.
    ///
    /// Nothing here probes a connection for liveness first.  Reading from a
    /// TLS stream to see whether it is still there consumes whatever is
    /// waiting, and what is usually waiting is a post-handshake session
    /// ticket; eating it breaks the very resumption it was sent for.  The age
    /// check and the retry are the mechanism instead.
    fn take(&self, alive: impl Fn(&T) -> bool) -> Option<Idle<T>> {
        let mut held = self.idle.lock();

        // Entries are pushed as they are returned, so the front is always the
        // oldest and a sweep from there can stop at the first live one.
        while held
            .front()
            .is_some_and(|i| i.since.elapsed() > IDLE_CAP || !alive(&i.conn))
        {
            held.pop_front();
        }

        match held.back() {
            Some(i) if i.since.elapsed() <= IDLE_CAP && alive(&i.conn) => held.pop_back(),
            _ => None,
        }
    }

    /// Returns a connection that has just produced a complete response.
    fn put(&self, conn: T, rtt: Duration) {
        let mut held = self.idle.lock();
        held.push_back(Idle {
            conn,
            since: Instant::now(),
            rtt,
        });

        while held.len() > IDLE_MAX {
            held.pop_front();
        }
    }

    /// Drops every idle connection.
    fn clear(&self) {
        self.idle.lock().clear();
    }
}

/// The one connection every query to an address shares.
struct Shared<T> {
    /// The connection, and the stamp identifying this incarnation of it.
    live: parking_lot::Mutex<Option<(u64, T)>>,
    /// The next stamp to hand out.
    stamps: AtomicU64,
}

impl<T> Default for Shared<T> {
    fn default() -> Self {
        Self {
            live: parking_lot::Mutex::new(None),
            stamps: AtomicU64::new(0),
        }
    }
}

impl<T> fmt::Debug for Shared<T> {
    /// Hand-written for the same reason as [`Pool`]'s, and because neither
    /// `h3`'s sender nor its stream opener implements `Debug` at all.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Shared")
    }
}

impl<T: Clone> Shared<T> {
    /// The live connection, if `alive` still vouches for it.
    fn get(&self, alive: impl Fn(&T) -> bool) -> Option<(u64, T)> {
        let mut held = self.live.lock();
        match held.as_ref() {
            Some((stamp, conn)) if alive(conn) => Some((*stamp, conn.clone())),
            Some(_) => {
                *held = None;

                None
            }
            None => None,
        }
    }

    /// Installs a freshly dialled connection and returns its stamp.
    fn put(&self, conn: T) -> u64 {
        let stamp = self.stamps.fetch_add(1, Ordering::Relaxed);
        *self.live.lock() = Some((stamp, conn));

        stamp
    }

    /// Drops the connection carrying `stamp`, if it is still the current one.
    ///
    /// The stamp is what stops a query that has just found its connection
    /// broken from throwing away the replacement another query installed
    /// while it was failing.
    fn forget(&self, stamp: u64) {
        let mut held = self.live.lock();
        if held.as_ref().is_some_and(|(s, _)| *s == stamp) {
            *held = None;
        }
    }

    /// Takes the connection out of the slot, if there is one.
    fn take(&self) -> Option<T> {
        self.live.lock().take().map(|(_, conn)| conn)
    }
}

/// The gate in front of a slot, and what a failed dial left behind.
#[derive(Default, Debug)]
struct Dialer {
    /// Held for the length of a dial.
    ///
    /// A `tokio` mutex rather than a `parking_lot` one because it is held
    /// across the handshake, which is the whole point of it.
    gate: tokio::sync::Mutex<()>,
    /// Why the last dial failed, and when that stops being assumed.
    recent: parking_lot::Mutex<Option<(Instant, String)>>,
}

impl Dialer {
    /// The recorded failure, while it is recent enough to still act on.
    fn blocked(&self) -> Option<Error> {
        let held = self.recent.lock();
        let (until, why) = held.as_ref()?;

        (*until > Instant::now()).then(|| Error::Unreachable(why.clone()))
    }

    /// Records a dial failure, to be handed to whoever asks next.
    fn failed(&self, e: &Error) {
        *self.recent.lock() = Some((Instant::now() + DIAL_BACKOFF, e.to_string()));
    }

    /// Forgets any recorded failure.
    fn succeeded(&self) {
        *self.recent.lock() = None;
    }
}

/// A set of connections and the dialler that fills it.
#[derive(Default, Debug)]
struct Channel<S> {
    /// What is open.
    slot: S,
    /// How it is opened.
    dialer: Dialer,
}

/// The HTTP connections kept to one DNS-over-HTTPS endpoint.
#[derive(Default, Debug)]
struct Https {
    /// The HTTP/2 sender, which multiplexes, so every query shares one.
    h2: Shared<H2Sender>,
    /// Idle HTTP/1.1 senders.
    ///
    /// HTTP/1.1 cannot interleave requests, so these are checked out one
    /// query at a time exactly like a DNS-over-TLS stream.  They share the
    /// HTTP/2 slot's gate because they share its dial: which of the two a
    /// handshake produced is only known once it has finished.
    h1: Pool<H1Sender>,
}

/// An HTTP/3 connection: the sender, and the QUIC connection under it.
#[derive(Clone)]
struct H3Conn {
    /// Where requests are handed in.
    sender: H3Sender,
    /// The connection they ride on, which is what says whether it is alive.
    conn: quinn::Connection,
}

impl fmt::Debug for H3Conn {
    /// Hand-written because neither `h3::client::SendRequest` nor
    /// `h3_quinn::OpenStreams` implements `Debug`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("H3Conn")
    }
}

/// Everything kept open to one address.
#[derive(Debug)]
struct Address {
    /// Where these connect to.
    addr: SocketAddr,
    /// DNS-over-HTTPS over TCP.
    https: Channel<Https>,
    /// DNS-over-HTTPS over HTTP/3.
    ///
    /// Dialled through its own gate rather than the HTTPS one, because an
    /// upstream with no HTTP/3 at all must not have its failure held against
    /// the HTTP/2 exchange that falls back to it.
    h3: Channel<Shared<H3Conn>>,
    /// DNS-over-QUIC.
    doq: Channel<Shared<quinn::Connection>>,
    /// DNS-over-TLS.
    dot: Channel<Pool<DotStream>>,
    /// Plain DNS over TCP, including the retry of a truncated UDP answer.
    tcp: Channel<Pool<TcpStream>>,
}

impl Address {
    /// A set of empty slots for one address.
    fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            https: Channel::default(),
            h3: Channel::default(),
            doq: Channel::default(),
            dot: Channel::default(),
            tcp: Channel::default(),
        }
    }

    /// Drops every connection to this address.
    fn close(&self) {
        // Dropping a sender is what shuts its driver task down: hyper's and
        // h3's connections both run until the last handle to them is gone.
        self.https.slot.h2.take();
        self.https.slot.h1.clear();
        self.dot.slot.clear();
        self.tcp.slot.clear();

        // QUIC is told rather than dropped, so the peer sees a clean close
        // instead of waiting out its idle timeout.
        if let Some(conn) = self.doq.slot.take() {
            conn.close(NO_ERROR.into(), b"");
        }
        if let Some(h3) = self.h3.slot.take() {
            h3.conn.close(NO_ERROR.into(), b"");
        }
    }
}

/// The connections one client keeps, one set per address it may contact.
#[derive(Debug)]
pub struct Connections {
    /// The slots, in the same order as the client's addresses.
    per: Vec<Address>,
    /// The TLS settings every dial from here uses.
    profiles: Profiles,
}

impl Connections {
    /// Builds an empty slot for each of `addrs`.
    ///
    /// Every exchange below names an address by its position in that list,
    /// which is how the caller already holds it, and panics if given a
    /// position that does not exist.
    pub fn new(addrs: &[SocketAddr], tls: &Arc<rustls::ClientConfig>) -> Self {
        Self {
            per: addrs.iter().copied().map(Address::new).collect(),
            profiles: Profiles::derive(tls),
        }
    }

    /// Drops every connection, letting the tasks driving them finish.
    ///
    /// `POST /control/test_upstream_dns` builds a throwaway client per probe,
    /// so without this each probe would leave a connection and a task behind.
    pub fn close(&self) {
        for a in &self.per {
            a.close();
        }
    }

    /// Sends a query over plain TCP.
    pub async fn tcp(&self, i: usize, req: &Message, timeout: Duration) -> Result<Message, Error> {
        let a = &self.per[i];

        pooled(&a.tcp, req, timeout, |left| tcp_connect(a.addr, left)).await
    }

    /// Sends a query over DNS-over-TLS.
    pub async fn tls(
        &self,
        i: usize,
        req: &Message,
        host: &str,
        timeout: Duration,
    ) -> Result<Message, Error> {
        let a = &self.per[i];

        pooled(&a.dot, req, timeout, |left| {
            tls_connect(a.addr, host, self.profiles.dot.clone(), left)
        })
        .await
    }

    /// Sends a query over DNS-over-HTTPS.
    ///
    /// Uses the POST form with `application/dns-message`, which avoids the
    /// base64url encoding of the GET form and is what upstream prefers.
    pub async fn https(
        &self,
        i: usize,
        req: &Message,
        host: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<Message, Error> {
        let a = &self.per[i];
        let wire = Bytes::from(req.to_bytes().map_err(|e| Error::Decode(e.to_string()))?);
        let uri = format!("https://{host}{path}");
        let deadline = Instant::now() + timeout;

        // Two passes at most.  The first may run on a connection that was
        // already open, and the one failure worth repeating is that such a
        // connection was closed underneath it before the request reached the
        // wire — the GOAWAY race, which a busy public resolver runs into
        // whenever it retires a connection by age.
        let mut retried = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout(timeout));
            }

            match self.http_conn(a, host, retried, left).await? {
                Http::Two(stamp, mut sender) => {
                    match h2_send(&mut sender, &uri, wire.clone(), left).await {
                        Sent::Body(body) => return decode(req, &body),
                        Sent::Unsent(e) if !retried => {
                            a.https.slot.h2.forget(stamp);
                            tracing::debug!(
                                error = %e,
                                "the http/2 connection was gone before the query was sent; dialling again"
                            );
                            retried = true;
                        }
                        // A request that was already on the wire is not sent
                        // twice: the upstream may well have answered it, and
                        // a second copy is a second query against whatever
                        // quota it keeps.  The connection still goes, because
                        // the commonest way to reach here is one that has
                        // stopped carrying anything without saying so.
                        Sent::Unsent(e) | Sent::Spent(e) => {
                            a.https.slot.h2.forget(stamp);

                            return Err(e);
                        }
                    }
                }
                Http::One(mut idle) => {
                    let budget = idle.budget(left);
                    let started = Instant::now();
                    match h1_send(&mut idle.conn, &uri, wire.clone(), budget).await {
                        Ok(body) => {
                            let out = decode(req, &body);
                            if out.is_ok() {
                                a.https.slot.h1.put(idle.conn, started.elapsed());
                            }

                            return out;
                        }
                        Err(e) if !retried => {
                            tracing::debug!(
                                error = %e,
                                "the pooled http/1.1 connection failed; dialling a fresh one"
                            );
                            retried = true;
                        }
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// Hands out a connection to a DoH endpoint, dialling one if needed.
    ///
    /// `fresh` refuses the idle HTTP/1.1 connections: a pooled one that has
    /// just failed says nothing good about the rest of the pool, so the retry
    /// goes to a connection that is known to be new.
    async fn http_conn(
        &self,
        a: &Address,
        host: &str,
        fresh: bool,
        timeout: Duration,
    ) -> Result<Http, Error> {
        if let Some(c) = ready_http(&a.https.slot, fresh) {
            return Ok(c);
        }

        // Only one task dials; the rest wait here and then find what it left.
        let _gate = a.https.dialer.gate.lock().await;
        if let Some(c) = ready_http(&a.https.slot, fresh) {
            return Ok(c);
        }
        if let Some(e) = a.https.dialer.blocked() {
            return Err(e);
        }

        match dial_https(a.addr, host, self.profiles.https.clone(), timeout).await {
            Ok(Dialed::Two(sender)) => {
                a.https.dialer.succeeded();
                let stamp = a.https.slot.h2.put(sender.clone());

                Ok(Http::Two(stamp, sender))
            }
            Ok(Dialed::One(sender)) => {
                a.https.dialer.succeeded();

                Ok(Http::One(Idle::fresh(sender)))
            }
            Err(e) => {
                a.https.dialer.failed(&e);

                Err(e)
            }
        }
    }

    /// Sends a query over DNS-over-HTTPS carried by HTTP/3.
    ///
    /// This is `use_http3_upstreams`.  The exchange is the same POST as over
    /// HTTP/2; only the transport underneath differs, so a server that does
    /// not speak HTTP/3 fails the handshake and the caller falls back.
    pub async fn https3(
        &self,
        i: usize,
        req: &Message,
        host: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<Message, Error> {
        let a = &self.per[i];
        let wire = Bytes::from(req.to_bytes().map_err(|e| Error::Decode(e.to_string()))?);
        let uri = format!("https://{host}{path}");
        let deadline = Instant::now() + timeout;

        let mut retried = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout(timeout));
            }

            let (stamp, h3, reused) = shared(
                &a.h3,
                |c: &H3Conn| c.conn.close_reason().is_none(),
                || async {
                    let until = Instant::now() + left;
                    let conn = quic_connect(&self.profiles.h3, a.addr, host, left).await?;

                    // Bounded like the others: starting HTTP/3 is an exchange
                    // of settings, and it runs with the gate held.
                    let rest = until.saturating_duration_since(Instant::now());
                    tokio::time::timeout(rest, h3_start(conn))
                        .await
                        .map_err(|_| Error::Timeout(left))?
                },
            )
            .await?;

            match h3_send(&h3, &uri, wire.clone(), left).await {
                Ok(body) => return decode(req, &body),
                Err(e) => {
                    // A connection that has been retired is worth one more
                    // attempt on a fresh one; a connection that is still open
                    // failed for some reason of its own, and one that was only
                    // just dialled would fail the same way twice.
                    let retired = worth_rebuilding(&h3.conn);
                    if retired {
                        a.h3.slot.forget(stamp);
                    }
                    if retried || !reused || !retired {
                        return Err(e);
                    }

                    tracing::debug!(error = %e, "the http/3 connection was retired; dialling again");
                    retried = true;
                }
            }
        }
    }

    /// Sends a query over DNS-over-QUIC.
    ///
    /// The framing is the two-byte length prefix TCP and DoT use, so only the
    /// transport differs.  RFC 9250 requires the message identifier to be
    /// zero on the wire, because QUIC's own stream multiplexing already tells
    /// answers apart; the caller's identifier is restored on the way back.
    pub async fn quic(
        &self,
        i: usize,
        req: &Message,
        host: &str,
        timeout: Duration,
    ) -> Result<Message, Error> {
        let a = &self.per[i];

        let id = req.metadata.id;
        let mut on_wire = req.clone();
        on_wire.metadata.id = 0;
        let framed = frame(&on_wire)?;

        let deadline = Instant::now() + timeout;
        let mut retried = false;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Timeout(timeout));
            }

            let (stamp, conn, reused) = shared(
                &a.doq,
                |c: &quinn::Connection| c.close_reason().is_none(),
                || quic_connect(&self.profiles.doq, a.addr, host, left),
            )
            .await?;

            match quic_send(&conn, &framed, left).await {
                Ok(mut resp) => {
                    resp.metadata.id = id;
                    check_reply(req, &resp)?;

                    return Ok(resp);
                }
                Err(e) => {
                    // A connection that has been retired is worth one more
                    // attempt on a fresh one; a connection that is still open
                    // failed for some reason of its own, and one that was only
                    // just dialled would fail the same way twice.
                    let retired = worth_rebuilding(&conn);
                    if retired {
                        a.doq.slot.forget(stamp);
                    }
                    if retried || !reused || !retired {
                        return Err(e);
                    }

                    tracing::debug!(error = %e, "the quic connection was retired; dialling again");
                    retried = true;
                }
            }
        }
    }
}

/// What a query got handed to send itself on.
enum Http {
    /// An HTTP/2 sender, and the stamp identifying it in its slot.
    Two(u64, H2Sender),
    /// An HTTP/1.1 sender, checked out of the pool or newly opened.
    One(Idle<H1Sender>),
}

/// What a handshake produced.
enum Dialed {
    /// The server negotiated HTTP/2.
    Two(H2Sender),
    /// The server negotiated HTTP/1.1, or named no protocol at all.
    One(H1Sender),
}

/// What became of a request that was handed to a connection.
enum Sent {
    /// The response body.
    Body(Vec<u8>),
    /// The request never reached the wire, so repeating it is safe.
    Unsent(Error),
    /// The request was on the wire already; repeating it is not safe.
    Spent(Error),
}

/// The HTTP connection already open to an endpoint, if there is a usable one.
fn ready_http(slot: &Https, fresh: bool) -> Option<Http> {
    // `is_closed` is a flag hyper sets when the connection's driver has
    // finished; asking costs nothing and reads nothing off the socket.
    if let Some((stamp, sender)) = slot.h2.get(|s| !s.is_closed()) {
        return Some(Http::Two(stamp, sender));
    }
    if fresh {
        return None;
    }

    slot.h1.take(|s| !s.is_closed()).map(Http::One)
}

/// Runs one exchange on a checked-out connection, dialling if none is idle.
///
/// The invariant this keeps is that a connection goes back into the pool only
/// after a complete response has been read off it *and* validated.  Anything
/// else — a timeout, a short read, a reply to a question nobody asked — drops
/// it, because a stream with an unread frame still on it would hand that
/// frame to the next query.
///
/// Unlike the multiplexed transports, dialling here is not gated: several
/// queries at once genuinely need several connections, and making them queue
/// for one another would be the serialisation the gate exists to prevent
/// elsewhere.  The memory of a failed dial still applies, so a dead upstream
/// is not dialled over and over.
async fn pooled<T, D, F>(
    chan: &Channel<Pool<T>>,
    req: &Message,
    timeout: Duration,
    dial: D,
) -> Result<Message, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send,
    D: Fn(Duration) -> F,
    F: Future<Output = Result<T, Error>>,
{
    let deadline = Instant::now() + timeout;

    if let Some(mut idle) = chan.slot.take(|_| true) {
        let budget = idle.budget(timeout);
        let started = Instant::now();
        match stream_exchange(&mut idle.conn, req, budget).await {
            Ok(resp) => {
                chan.slot.put(idle.conn, started.elapsed());

                return Ok(resp);
            }
            // `idle` is dropped with this arm, which closes the connection.
            Err(e) => tracing::debug!(
                error = %e,
                "the pooled connection failed; dialling a fresh one"
            ),
        }
    }

    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Error::Timeout(timeout));
    }
    if let Some(e) = chan.dialer.blocked() {
        return Err(e);
    }

    let mut conn = match dial(left).await {
        Ok(conn) => {
            chan.dialer.succeeded();

            conn
        }
        Err(e) => {
            chan.dialer.failed(&e);

            return Err(e);
        }
    };

    let started = Instant::now();
    let left = deadline.saturating_duration_since(Instant::now());
    let resp = stream_exchange(&mut conn, req, left).await?;
    chan.slot.put(conn, started.elapsed());

    Ok(resp)
}

/// Hands out the one connection a slot holds, dialling it if there is none.
///
/// Returns the stamp identifying the connection, the connection itself, and
/// whether it was already open — which is what decides whether a failure is
/// worth one retry.
async fn shared<T, A, D, F>(
    chan: &Channel<Shared<T>>,
    alive: A,
    dial: D,
) -> Result<(u64, T, bool), Error>
where
    T: Clone,
    A: Fn(&T) -> bool,
    D: FnOnce() -> F,
    F: Future<Output = Result<T, Error>>,
{
    if let Some((stamp, conn)) = chan.slot.get(&alive) {
        return Ok((stamp, conn, true));
    }

    let _gate = chan.dialer.gate.lock().await;

    // Another query may have dialled while this one waited at the gate; that
    // is the entire point of the gate.
    if let Some((stamp, conn)) = chan.slot.get(&alive) {
        return Ok((stamp, conn, true));
    }
    if let Some(e) = chan.dialer.blocked() {
        return Err(e);
    }

    match dial().await {
        Ok(conn) => {
            chan.dialer.succeeded();
            let stamp = chan.slot.put(conn.clone());

            Ok((stamp, conn, false))
        }
        Err(e) => {
            chan.dialer.failed(&e);

            Err(e)
        }
    }
}

/// Opens a TCP connection.
async fn tcp_connect(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, Error> {
    let s = tokio::time::timeout(timeout, TcpStream::connect(addr))
        .await
        .map_err(|_| Error::Timeout(timeout))??;
    s.set_nodelay(true).ok();

    Ok(s)
}

/// Opens a TLS connection, presenting `host` as the server name.
///
/// The budget covers the whole thing.  Giving the connect and the handshake
/// one each would let a server that answers TCP and then says nothing hold a
/// dial — and, behind a dial, the gate — for twice as long as the query it is
/// serving was ever given.
async fn tls_connect(
    addr: SocketAddr,
    host: &str,
    cfg: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<DotStream, Error> {
    let deadline = Instant::now() + timeout;
    let name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| Error::Tls(format!("invalid server name {host:?}: {e}")))?;
    let tcp = tcp_connect(addr, timeout).await?;

    tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        tokio_rustls::TlsConnector::from(cfg).connect(name, tcp),
    )
    .await
    .map_err(|_| Error::Timeout(timeout))?
    .map_err(|e| Error::Tls(e.to_string()))
}

/// Opens an HTTP connection to a DoH endpoint and starts its driver.
async fn dial_https(
    addr: SocketAddr,
    host: &str,
    cfg: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<Dialed, Error> {
    let deadline = Instant::now() + timeout;
    let tls = tls_connect(addr, host, cfg, timeout).await?;
    let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
    let io = hyper_util::rt::TokioIo::new(tls);

    // The HTTP handshake is an exchange in its own right — SETTINGS, over
    // HTTP/2 — and it is bounded for the same reason the TLS one is: it runs
    // with the gate held, so a server that goes quiet here would stop every
    // query queued behind it rather than only its own.
    let left = deadline.saturating_duration_since(Instant::now());

    if is_h2 {
        let handshake =
            hyper::client::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                // Setting an interval without a timer panics inside hyper the first
                // time it wants to schedule a ping, which is thirty seconds after the
                // connection this module keeps has gone quiet.
                .timer(hyper_util::rt::TokioTimer::new())
                .keep_alive_interval(H2_KEEPALIVE)
                .keep_alive_while_idle(true)
                .handshake(io);
        let (sender, conn) = tokio::time::timeout(left, handshake)
            .await
            .map_err(|_| Error::Timeout(timeout))?
            .map_err(|e| Error::Http(e.to_string()))?;

        // Never aborted: the driver is what carries every request and every
        // response on this connection, and it ends by itself once the last
        // sender has been dropped.  Aborting it was what made the old
        // one-query-per-connection code correct only because the connection
        // was thrown away with it.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        return Ok(Dialed::Two(sender));
    }

    let (sender, conn) = tokio::time::timeout(left, hyper::client::conn::http1::handshake(io))
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Http(e.to_string()))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    Ok(Dialed::One(sender))
}

/// Builds the POST that carries a query to a DoH endpoint.
fn doh_request<B>(uri: &str, body: B) -> Result<hyper::Request<B>, Error> {
    hyper::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(body)
        .map_err(|e| Error::Http(e.to_string()))
}

/// Sends one query on an HTTP/2 connection.
async fn h2_send(sender: &mut H2Sender, uri: &str, wire: Bytes, timeout: Duration) -> Sent {
    let req = match doh_request(uri, Full::new(wire)) {
        Ok(req) => req,
        Err(e) => return Sent::Spent(e),
    };

    // `try_send_request` rather than `send_request` because its error hands
    // the request back when — and only when — nothing of it reached the wire,
    // which is precisely the condition under which sending it again is not a
    // second query to the upstream.
    let sent = tokio::time::timeout(timeout, sender.try_send_request(req)).await;
    let resp = match sent {
        Err(_) => return Sent::Spent(Error::Timeout(timeout)),
        Ok(Ok(resp)) => resp,
        Ok(Err(mut e)) => {
            let unsent = e.take_message().is_some();
            let e = Error::Http(e.into_error().to_string());

            return if unsent {
                Sent::Unsent(e)
            } else {
                Sent::Spent(e)
            };
        }
    };

    match read_body(resp, timeout).await {
        Ok(body) => Sent::Body(body),
        Err(e) => Sent::Spent(e),
    }
}

/// Sends one query on an HTTP/1.1 connection.
async fn h1_send(
    sender: &mut H1Sender,
    uri: &str,
    wire: Bytes,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let req = doh_request(uri, Full::new(wire))?;
    let resp = tokio::time::timeout(timeout, sender.send_request(req))
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Http(e.to_string()))?;

    read_body(resp, timeout).await
}

/// Reads and size-limits an HTTP response body.
async fn read_body<B>(resp: hyper::Response<B>, timeout: Duration) -> Result<Vec<u8>, Error>
where
    B: hyper::body::Body + Unpin,
    B::Error: fmt::Display,
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

/// Decodes a DoH response body and checks that it answers the question asked.
///
/// The identifier is deliberately not compared: RFC 8484 lets a DoH server
/// answer with a zero identifier whatever it was asked with, since HTTP has
/// already paired the response with its request.  The question section is
/// what dnsproxy's `validateResponse` checks, and it is what matters — the
/// answer is about to be cached under the name that *was* asked.
fn decode(req: &Message, body: &[u8]) -> Result<Message, Error> {
    let resp = Message::from_bytes(body).map_err(|e| Error::Decode(e.to_string()))?;
    check_reply(req, &resp)?;

    Ok(resp)
}

/// Frames a message the way a stream transport carries it.
fn frame(msg: &Message) -> Result<Vec<u8>, Error> {
    let wire = msg.to_bytes().map_err(|e| Error::Decode(e.to_string()))?;
    let len = u16::try_from(wire.len())
        .map_err(|_| Error::Decode("request too large for framing".into()))?;

    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&wire);

    Ok(out)
}

/// The QUIC endpoints, one per address family.
///
/// `quinn::Endpoint::client` binds a UDP socket and spawns a driver task, and
/// both were being built and thrown away for every DoQ and HTTP/3 query.  One
/// endpoint carries any number of connections, so it is built once and cloned.
///
/// A `Mutex<Option<_>>` rather than a `OnceLock` for two reasons: a bind that
/// failed once should not poison QUIC for the life of the process, and the
/// driver task belongs to the runtime that spawned it, so an endpoint cached
/// under one runtime is inert under the next.  Tests are where that second
/// case shows up — each `#[tokio::test]` builds its own runtime — so the
/// runtime is recorded alongside the endpoint and a mismatch rebuilds.
static QUIC_V4: parking_lot::Mutex<Option<(tokio::runtime::Id, quinn::Endpoint)>> =
    parking_lot::Mutex::new(None);
/// The IPv6 endpoint; see [`QUIC_V4`].
static QUIC_V6: parking_lot::Mutex<Option<(tokio::runtime::Id, quinn::Endpoint)>> =
    parking_lot::Mutex::new(None);

/// The endpoint to reach `server` from, building it on first use.
fn quic_endpoint(server: SocketAddr) -> Result<quinn::Endpoint, Error> {
    let (slot, bind) = if server.is_ipv4() {
        (&QUIC_V4, "0.0.0.0:0")
    } else {
        (&QUIC_V6, "[::]:0")
    };

    let here = tokio::runtime::Handle::current().id();
    let mut held = slot.lock();
    if let Some((born, ep)) = held.as_ref()
        && *born == here
    {
        return Ok(ep.clone());
    }

    let ep = quinn::Endpoint::client(bind.parse().expect("static addr")).map_err(Error::Io)?;
    *held = Some((here, ep.clone()));

    Ok(ep)
}

/// Opens a QUIC connection with the protocol the profile advertises.
async fn quic_connect(
    tls: &Arc<rustls::ClientConfig>,
    server: SocketAddr,
    server_name: &str,
    timeout: Duration,
) -> Result<quinn::Connection, Error> {
    let h3 = tls.alpn_protocols.iter().any(|p| p == b"h3");

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls.clone())
        .map_err(|e| Error::Tls(e.to_string()))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(QUIC_IDLE.try_into().expect("the idle timeout fits")));
    // Keeping a connection alive is the point of holding one: without this it
    // is dropped by the peer after half a minute of quiet and the next query
    // pays for a handshake again.
    transport.keep_alive_interval(Some(QUIC_KEEPALIVE));
    if !h3 {
        // Unidirectional streams carry nothing in DoQ, so the server is told
        // it may open none.  HTTP/3 is the opposite: its control stream and
        // both QPACK streams are unidirectional, so it keeps the default and
        // would fail its own handshake without them.
        transport.max_concurrent_uni_streams(0u32.into());
    }
    cfg.transport_config(Arc::new(transport));

    // Not `set_default_client_config`: DoQ and HTTP/3 share the endpoint but
    // need different application protocols, so the configuration travels with
    // the connection rather than the endpoint.
    let connecting = quic_endpoint(server)?
        .connect_with(cfg, server, server_name)
        .map_err(|e| Error::Tls(e.to_string()))?;

    tokio::time::timeout(timeout, connecting)
        .await
        .map_err(|_| Error::Timeout(timeout))?
        .map_err(|e| Error::Http(format!("quic handshake: {e}")))
}

/// Reports whether a QUIC connection that has just failed should be rebuilt.
///
/// dnsproxy keeps the same list, for the same reasons (`isQUICRetryError`): a
/// server that has restarted, a load balancer retiring a connection by age,
/// or an idle timeout all close a connection with what amounts to "nothing is
/// wrong, start again".  Google's resolver in particular ends a perfectly
/// healthy connection with a NO_ERROR transport close once it has lived long
/// enough.
fn worth_rebuilding(conn: &quinn::Connection) -> bool {
    match conn.close_reason() {
        // Still open, so whatever failed was the stream's business and not the
        // connection's: a second connection would fail the same way.
        None => false,
        Some(quinn::ConnectionError::ApplicationClosed(c)) => c.error_code == NO_ERROR.into(),
        Some(quinn::ConnectionError::TransportError(e)) => {
            e.code == quinn::TransportErrorCode::NO_ERROR
        }
        Some(
            quinn::ConnectionError::TimedOut
            | quinn::ConnectionError::Reset
            | quinn::ConnectionError::ConnectionClosed(_)
            | quinn::ConnectionError::LocallyClosed
            | quinn::ConnectionError::VersionMismatch,
        ) => true,
        // The local side has run out of connection identifiers; opening
        // another connection would not find any more of them.
        Some(quinn::ConnectionError::CidsExhausted) => false,
    }
}

/// Sends one framed query on its own bidirectional stream.
async fn quic_send(
    conn: &quinn::Connection,
    framed: &[u8],
    timeout: Duration,
) -> Result<Message, Error> {
    tokio::time::timeout(timeout, async {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::Http(format!("opening a quic stream: {e}")))?;

        send.write_all(framed)
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
    .map_err(|_| Error::Timeout(timeout))?
}

/// Starts HTTP/3 on a QUIC connection and spawns the task that drives it.
async fn h3_start(conn: quinn::Connection) -> Result<H3Conn, Error> {
    let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(|e| Error::Http(format!("http/3 handshake: {e}")))?;

    // As with HTTP/2, never aborted: the driver carries every exchange on
    // this connection and finishes on its own when the connection closes.
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    Ok(H3Conn { sender, conn })
}

/// Sends one query on an HTTP/3 connection.
async fn h3_send(h3: &H3Conn, uri: &str, wire: Bytes, timeout: Duration) -> Result<Vec<u8>, Error> {
    use bytes::Buf as _;

    // The clone is held until the body has been read: h3 shuts the connection
    // down when the last sender is dropped.
    let mut sender = h3.sender.clone();

    tokio::time::timeout(timeout, async move {
        let mut stream = sender
            .send_request(doh_request(uri, ())?)
            .await
            .map_err(|e| Error::Http(e.to_string()))?;
        stream
            .send_data(wire)
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

        Ok(body)
    })
    .await
    .map_err(|_| Error::Timeout(timeout))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_connection_is_given_a_shortened_first_attempt() {
        let mut idle = Idle::fresh(());
        // Just returned: it gets the whole budget, since nothing suggests it
        // has gone away.
        assert_eq!(
            idle.budget(Duration::from_secs(10)),
            Duration::from_secs(10)
        );

        idle.since = Instant::now() - Duration::from_secs(5);
        idle.rtt = Duration::from_millis(40);
        assert_eq!(
            idle.budget(Duration::from_secs(10)),
            PROBE_FLOOR,
            "a fast upstream should get the floor, not four times nothing"
        );

        idle.rtt = Duration::from_millis(400);
        assert_eq!(
            idle.budget(Duration::from_secs(10)),
            Duration::from_millis(1600),
            "a slow upstream should get room to be slow"
        );

        assert_eq!(
            idle.budget(Duration::from_millis(200)),
            Duration::from_millis(200),
            "the shortened attempt must never exceed the budget it came from"
        );
    }

    #[test]
    fn the_pool_hands_back_the_most_recently_used_connection() {
        let pool: Pool<u8> = Pool::default();
        pool.put(1, Duration::ZERO);
        pool.put(2, Duration::ZERO);

        assert_eq!(pool.take(|_| true).map(|i| i.conn), Some(2));
        assert_eq!(pool.take(|_| true).map(|i| i.conn), Some(1));
        assert!(pool.take(|_| true).is_none());
    }

    #[test]
    fn the_pool_drops_what_it_cannot_keep() {
        let pool: Pool<u8> = Pool::default();
        for i in 0..u8::try_from(IDLE_MAX).expect("the cap is small") + 3 {
            pool.put(i, Duration::ZERO);
        }

        assert_eq!(pool.idle.lock().len(), IDLE_MAX);
        assert_eq!(
            pool.take(|_| true).map(|i| i.conn),
            Some(u8::try_from(IDLE_MAX).expect("the cap is small") + 2),
            "the newest connection should survive and the oldest should go"
        );
    }

    #[test]
    fn a_connection_that_says_it_is_closed_is_not_handed_out() {
        let pool: Pool<bool> = Pool::default();
        pool.put(false, Duration::ZERO);
        pool.put(true, Duration::ZERO);

        assert_eq!(pool.take(|alive| *alive).map(|i| i.conn), Some(true));
        assert!(
            pool.take(|alive| *alive).is_none(),
            "the dead one should have been swept, not returned"
        );
    }

    #[test]
    fn a_stale_connection_is_dropped_rather_than_used() {
        let pool: Pool<u8> = Pool::default();
        pool.idle.lock().push_back(Idle {
            conn: 7,
            since: Instant::now() - IDLE_CAP - Duration::from_secs(1),
            rtt: Duration::ZERO,
        });

        assert!(pool.take(|_| true).is_none());
        assert!(pool.idle.lock().is_empty());
    }

    #[test]
    fn a_stamp_keeps_one_failure_from_discarding_the_replacement() {
        let slot: Shared<u8> = Shared::default();
        let first = slot.put(1);
        let second = slot.put(2);

        // The query holding the first connection discovers it is broken only
        // after another query has installed the second.
        slot.forget(first);
        assert_eq!(slot.get(|_| true).map(|(_, c)| c), Some(2));

        slot.forget(second);
        assert!(slot.get(|_| true).is_none());
    }

    #[test]
    fn a_dead_connection_is_cleared_when_it_is_asked_for() {
        let slot: Shared<bool> = Shared::default();
        slot.put(false);

        assert!(slot.get(|alive| *alive).is_none());
        assert!(
            slot.live.lock().is_none(),
            "asking should have cleared the slot, not only refused it"
        );
    }

    #[test]
    fn a_failed_dial_is_remembered_and_then_forgotten() {
        let d = Dialer::default();
        assert!(d.blocked().is_none());

        d.failed(&Error::Tls("handshake refused".into()));
        let held = d.blocked().expect("a recent failure should block a dial");
        assert!(
            held.to_string().contains("handshake refused"),
            "the recorded reason should survive: {held}"
        );

        d.succeeded();
        assert!(d.blocked().is_none());
    }

    #[test]
    fn the_backoff_expires() {
        let d = Dialer::default();
        *d.recent.lock() = Some((
            Instant::now() - Duration::from_millis(1),
            "long gone".into(),
        ));

        assert!(d.blocked().is_none());
    }

    #[test]
    fn the_shared_default_reuses_the_shared_profiles() {
        let p = Profiles::derive(&crate::client::tls_config());
        assert!(
            Arc::ptr_eq(&p.https, &crate::client::HTTPS),
            "the default must draw on the shared session cache"
        );
        assert_eq!(p.doq.alpn_protocols, vec![b"doq".to_vec()]);
    }

    #[test]
    fn other_roots_are_given_the_same_set_of_protocols() {
        let mut own = (*crate::client::tls_config()).clone();
        own.alpn_protocols = vec![b"nonsense".to_vec()];
        let p = Profiles::derive(&Arc::new(own));

        assert_eq!(
            p.https.alpn_protocols,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(p.h3.alpn_protocols, vec![b"h3".to_vec()]);
        assert_eq!(
            p.dot.alpn_protocols,
            vec![b"nonsense".to_vec()],
            "DNS-over-TLS negotiates no protocol, so it keeps what it was given"
        );
    }
}
