//! Optimistic caching, and the background refresh behind it.
//!
//! The behaviour these pin was captured from AdGuard Home v0.107.79 running
//! with `cache_optimistic: true` against an upstream that answered a
//! different address every time, so each answer said which exchange produced
//! it:
//!
//! ```text
//! t=0.0  first, a miss              answer=10.0.0.2  ttl=2  query_time=1 msec
//! t=1.0  still inside the TTL       answer=10.0.0.2  ttl=1  query_time=0 msec
//! t=4.0  EXPIRED (age 4s > ttl 2s)  answer=10.0.0.2  ttl=7  query_time=0 msec
//! t=5.0  just after                 answer=10.0.0.3  ttl=1  query_time=0 msec
//! ```
//!
//! Three things to copy.  The expired entry is served rather than waited on;
//! it carries `cache_optimistic_answer_ttl` -- 7s there, a deliberately
//! non-default value -- rather than what was left of its own TTL; and the
//! refreshed answer is in the cache a moment later, having been fetched
//! without any client waiting for it.  Its query log held six lines for six
//! client queries, though the upstream had been asked nine times.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use sift_dns::cache::{Cache, Config as CacheConfig};
use sift_dns::client::{Client, tls_config};
use sift_dns::pool::{Mode, Pool, SharedPool};
use sift_dns::ratelimit::{Config as RlConfig, Limiter};
use sift_dns::resolver::{Action, ClientInfo, Proto, Resolver, Settings};
use sift_dns::rewrite::Table;
use sift_dns::server::{Event, Observer, Server};
use sift_filter::engine::Engine;
use tokio::net::UdpSocket;

/// The TTL the fake upstream puts on every answer.
const UPSTREAM_TTL: u32 = 1;

/// The TTL an optimistically served answer must carry.
///
/// Deliberately not the 30s default, so an implementation that hardcodes the
/// default rather than reading `cache_optimistic_answer_ttl` fails here.
const ANSWER_TTL: u32 = 7;

/// How many requests the fake upstream has answered.
#[derive(Default)]
struct Seen {
    count: AtomicUsize,
}

impl Seen {
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

/// Starts an upstream that answers `10.0.0.N`, counting up with each request.
///
/// The address identifies which exchange produced an answer, which is what
/// makes "served from the cache" and "fetched again" distinguishable.  The
/// delay is what separates the two in time.
async fn upstream(delay: Duration) -> (SocketAddr, Arc<Seen>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("binding");
    let addr = sock.local_addr().expect("local addr");
    let seen = Arc::new(Seen::default());

    let s = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(req) = Message::from_bytes(&buf[..n]) else {
                continue;
            };
            let nth = s.count.fetch_add(1, Ordering::SeqCst) + 1;

            let mut resp = Message::query();
            resp.metadata.id = req.metadata.id;
            resp.metadata.message_type = hickory_proto::op::MessageType::Response;
            resp.queries = req.queries.clone();
            if let Some(q) = req.queries.first() {
                resp.answers = vec![Record::from_rdata(
                    q.name().clone(),
                    UPSTREAM_TTL,
                    RData::A(A(std::net::Ipv4Addr::new(10, 0, 0, nth as u8))),
                )];
            }

            let wire = resp.to_bytes().expect("encoding");
            tokio::time::sleep(delay).await;
            let _ = sock.send_to(&wire, peer).await;
        }
    });

    (addr, seen)
}

/// A resolver with optimistic caching on and a refresh worker behind it.
async fn resolver(server: SocketAddr, refreshes: bool) -> Arc<Resolver> {
    let up = sift_dns::addr::parse(&server.to_string())
        .expect("parsing")
        .upstream
        .expect("an upstream");
    let client = Client::connect(up, &[], Duration::from_secs(2), false, tls_config())
        .await
        .expect("connecting");

    let r = Arc::new(Resolver::new(
        Engine::build([(1i64, "")], sift_filter::engine::NO_LISTS),
        Table::default(),
        Cache::new(CacheConfig {
            size_bytes: 1024 * 1024,
            optimistic: true,
            optimistic_answer_ttl: Duration::from_secs(u64::from(ANSWER_TTL)),
            ..CacheConfig::default()
        }),
        SharedPool::new(Pool::new(
            vec![Arc::new(client)],
            vec![],
            vec![],
            Mode::LoadBalance,
            Duration::from_secs(2),
            Duration::from_secs(2),
        )),
        Settings::default(),
    ));

    if refreshes {
        let (tx, rx) = sift_dns::refresh::channel();
        r.set_refresh_sender(tx);
        tokio::spawn(sift_dns::refresh::run(r.clone(), rx));
    }

    r
}

/// An `A` query for `name`.
fn request(name: &str) -> Message {
    let mut m = Message::query();
    m.metadata.id = 0x4242;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_utf8(name).expect("a name"),
        RecordType::A,
    ));

    m
}

fn client() -> ClientInfo {
    ClientInfo {
        addr: Some("203.0.113.77".parse::<IpAddr>().expect("an address")),
        ..Default::default()
    }
}

/// The address and TTL of the first answer, which say which exchange produced
/// it and how long the client was told to keep it.
fn answer(out: &sift_dns::resolver::Outcome) -> (String, u32) {
    let Action::Respond(m) = &out.action else {
        panic!("expected an answer");
    };
    let r = m.answers.first().expect("an answer record");

    (r.data.to_string(), r.ttl)
}

/// Waits for `cond`, up to two seconds.
async fn until(cond: impl Fn() -> bool) {
    for _ in 0..200 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("condition never held");
}

#[tokio::test]
async fn an_expired_entry_is_served_at_once_and_refreshed_behind_it() {
    // The upstream is slow, so waiting for it and not waiting for it are
    // hundreds of milliseconds apart rather than a matter of luck.
    let (up, seen) = upstream(Duration::from_millis(300)).await;
    let r = resolver(up, true).await;

    let first = r
        .resolve(&request("example.com."), Proto::Udp, &client())
        .await;
    assert_eq!(answer(&first).0, "10.0.0.1", "the first answer is fetched");
    assert_eq!(seen.count(), 1);

    // Let the entry's one-second TTL run out.
    tokio::time::sleep(Duration::from_millis(1200)).await;

    let started = Instant::now();
    let stale = r
        .resolve(&request("example.com."), Proto::Udp, &client())
        .await;
    let took = started.elapsed();

    assert!(
        took < Duration::from_millis(1),
        "an optimistically served answer must not wait on the upstream, took {took:?}"
    );
    assert!(stale.cached, "and is reported as a cache hit");
    assert_eq!(
        answer(&stale),
        ("10.0.0.1".to_string(), ANSWER_TTL),
        "the stored answer, stamped with cache_optimistic_answer_ttl"
    );

    // The refresh runs without anybody waiting for it, and its answer is what
    // the next client gets.  The upstream counts a request when it arrives,
    // so the answer is one delay behind that.
    until(|| seen.count() == 2).await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    let after = r
        .resolve(&request("example.com."), Proto::Udp, &client())
        .await;
    assert_eq!(
        answer(&after).0,
        "10.0.0.2",
        "the refreshed answer replaced the stale one"
    );
}

#[tokio::test]
async fn without_a_refresh_worker_an_expired_entry_is_not_served() {
    // Serving stale is only honest if something is going to replace it.  A
    // resolver built without a worker must still answer from the upstream.
    let (up, seen) = upstream(Duration::ZERO).await;
    let r = resolver(up, false).await;

    let first = r
        .resolve(&request("example.com."), Proto::Udp, &client())
        .await;
    assert_eq!(answer(&first).0, "10.0.0.1");

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let second = r
        .resolve(&request("example.com."), Proto::Udp, &client())
        .await;
    assert_eq!(
        answer(&second).0,
        "10.0.0.2",
        "the expired entry was refetched rather than served"
    );
    assert_eq!(seen.count(), 2);
}

/// The events the query log and statistics would be built from.
#[derive(Default)]
struct Watching {
    /// Whether each observed request was answered from the cache.
    cached: parking_lot::Mutex<Vec<bool>>,
}

impl Watching {
    fn seen(&self) -> Vec<bool> {
        self.cached.lock().clone()
    }
}

impl Observer for Watching {
    fn observe(&self, ev: &Event<'_>) {
        self.cached.lock().push(ev.outcome.cached);
    }
}

#[tokio::test]
async fn a_background_refresh_is_not_logged_or_counted() {
    // A refresh has no client.  Routing it through `Server::handle` would
    // give it a query-log line and a statistics tick of its own, and every
    // popular name would be counted twice.
    let (up, seen) = upstream(Duration::ZERO).await;
    let r = resolver(up, true).await;

    let observer = Arc::new(Watching::default());
    let server = Server::new(
        r.clone(),
        Arc::new(Limiter::new(RlConfig {
            per_second: 0,
            ..RlConfig::default()
        })),
        observer.clone(),
    );

    let wire = request("example.com.").to_bytes().expect("encoding");
    let from: SocketAddr = "203.0.113.77:5353".parse().expect("an address");

    // Three client queries, each after the previous entry has expired, so
    // each of the last two is served stale and refreshed behind.
    for _ in 0..3 {
        server
            .handle(&wire, from, Proto::Udp)
            .await
            .expect("an answer");
        tokio::time::sleep(Duration::from_millis(1200)).await;
    }

    until(|| seen.count() == 3).await;

    // One miss and two answers served from the cache.  The observer sees the
    // three client queries and nothing else.
    assert_eq!(
        observer.seen(),
        vec![false, true, true],
        "one event per client query: a miss, then two cache hits"
    );

    // Three upstream exchanges for one client-caused fetch: the other two are
    // the refreshes behind the stale answers.  Had they gone through
    // `Server::handle` the observer would have five events, not three.
    assert_eq!(
        seen.count(),
        3,
        "the refreshes reached the upstream without being observed"
    );
}
