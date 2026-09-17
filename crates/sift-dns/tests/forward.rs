//! What reaches the upstream, and what comes back.
//!
//! These drive the resolver against a tiny local server, so the settings that
//! only show up in the forwarded request — the client subnet, the DNSSEC OK
//! bit, request coalescing — can be observed rather than inferred.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use sift_dns::cache::{Cache, Config as CacheConfig};
use sift_dns::client::{Client, tls_config};
use sift_dns::pool::{Mode, Pool, SharedPool};
use sift_dns::resolver::{Action, ClientInfo, Proto, Resolver, Settings};
use sift_dns::rewrite::Table;
use sift_filter::engine::Engine;
use tokio::net::UdpSocket;

/// What the fake upstream saw and how often.
#[derive(Default)]
struct Seen {
    /// How many requests arrived.
    count: AtomicUsize,
    /// The client subnet of the last request, if it carried one.
    subnet: parking_lot::Mutex<Option<String>>,
    /// Whether the last request asked for DNSSEC records.
    dnssec: parking_lot::Mutex<bool>,
}

/// Starts a local server that answers every query with `answer`.
///
/// `delay` holds each answer back, which is what makes a second identical
/// request arrive while the first is still in flight.
async fn upstream(answer: IpAddr, delay: Duration) -> (SocketAddr, Arc<Seen>) {
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

            s.count.fetch_add(1, Ordering::SeqCst);
            *s.subnet.lock() = sift_dns::edns::subnet_of(&req).map(|x| x.to_cidr());
            *s.dnssec.lock() = sift_dns::edns::dnssec_ok(&req);

            let mut resp = Message::query();
            resp.metadata.id = req.metadata.id;
            resp.metadata.message_type = hickory_proto::op::MessageType::Response;
            resp.queries = req.queries.clone();
            if let Some(q) = req.queries.first() {
                let data = match answer {
                    IpAddr::V4(a) => RData::A(A(a)),
                    IpAddr::V6(a) => RData::AAAA(hickory_proto::rr::rdata::AAAA(a)),
                };
                resp.answers = vec![Record::from_rdata(q.name().clone(), 300, data)];
            }

            let wire = resp.to_bytes().expect("encoding");
            tokio::time::sleep(delay).await;
            let _ = sock.send_to(&wire, peer).await;
        }
    });

    (addr, seen)
}

/// Builds a resolver pointed at one upstream.
async fn resolver(server: SocketAddr, settings: Settings) -> Resolver {
    let up = sift_dns::addr::parse(&server.to_string())
        .expect("parsing")
        .upstream
        .expect("an upstream");
    let client = Client::connect(up, &[], Duration::from_secs(2), false, tls_config())
        .await
        .expect("connecting");

    Resolver::new(
        Engine::build([(1i64, "")], sift_filter::engine::NO_LISTS),
        Table::default(),
        Cache::new(CacheConfig {
            size_bytes: 0,
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
        settings,
    )
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

/// A client on an ordinary network, rather than loopback.
fn lan_client() -> ClientInfo {
    ClientInfo {
        addr: Some("203.0.113.77".parse().expect("an address")),
        ..Default::default()
    }
}

#[tokio::test]
async fn the_client_subnet_is_forwarded_when_it_is_enabled() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            ecs_enabled: true,
            ..Default::default()
        },
    )
    .await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert!(matches!(out.action, Action::Respond(_)));

    assert_eq!(
        seen.subnet.lock().clone().as_deref(),
        Some("203.0.113.0/24"),
        "the address is masked to /24 before it is sent"
    );
    assert_eq!(out.req_ecs, "203.0.113.0/24", "and recorded in the log");
}

#[tokio::test]
async fn no_subnet_is_forwarded_when_the_feature_is_off() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(server, Settings::default()).await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;

    assert_eq!(seen.subnet.lock().clone(), None);
    assert!(out.req_ecs.is_empty());
}

#[tokio::test]
async fn a_loopback_client_is_never_described_to_the_upstream() {
    // Its subnet says nothing useful and would only leak that the query came
    // from the server itself.
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            ecs_enabled: true,
            ..Default::default()
        },
    )
    .await;

    let _ = r
        .resolve(
            &request("example.com."),
            Proto::Udp,
            &ClientInfo {
                addr: Some("127.0.0.1".parse().unwrap()),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(seen.subnet.lock().clone(), None);
}

#[tokio::test]
async fn a_custom_subnet_replaces_the_clients() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            ecs_enabled: true,
            ecs_custom: Some("198.51.100.9".parse().unwrap()),
            ..Default::default()
        },
    )
    .await;

    let _ = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;

    assert_eq!(
        seen.subnet.lock().clone().as_deref(),
        Some("198.51.100.0/24")
    );
}

#[tokio::test]
async fn the_dnssec_bit_is_set_only_when_it_is_asked_for() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::ZERO).await;

    let plain = resolver(server, Settings::default()).await;
    let _ = plain
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert!(!*seen.dnssec.lock());

    let signed = resolver(
        server,
        Settings {
            dnssec_enabled: true,
            ..Default::default()
        },
    )
    .await;
    let _ = signed
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    assert!(*seen.dnssec.lock());
}

#[tokio::test]
async fn identical_requests_in_flight_are_coalesced() {
    // A burst of the same question from several devices should cost one
    // upstream exchange, not one each.
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::from_millis(150)).await;
    let r = Arc::new(
        resolver(
            server,
            Settings {
                pending_enabled: true,
                ..Default::default()
            },
        )
        .await,
    );

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..5 {
        let r = r.clone();
        set.spawn(async move {
            r.resolve(&request("example.com."), Proto::Udp, &lan_client())
                .await
        });
    }

    let mut answered = 0;
    while let Some(out) = set.join_next().await {
        let out = out.expect("the task should not panic");
        if let Action::Respond(m) = &out.action
            && m.metadata.response_code == ResponseCode::NoError
            && !m.answers.is_empty()
        {
            answered += 1;
        }
    }

    assert_eq!(answered, 5, "every caller should get the answer");
    assert_eq!(
        seen.count.load(Ordering::SeqCst),
        1,
        "only one request should have reached the upstream"
    );
}

#[tokio::test]
async fn without_coalescing_every_request_goes_upstream() {
    let (server, seen) = upstream("192.0.2.1".parse().unwrap(), Duration::from_millis(150)).await;
    let r = Arc::new(resolver(server, Settings::default()).await);

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..3 {
        let r = r.clone();
        set.spawn(async move {
            r.resolve(&request("example.com."), Proto::Udp, &lan_client())
                .await
        });
    }
    while set.join_next().await.is_some() {}

    assert_eq!(seen.count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn a_bogus_address_becomes_nxdomain() {
    // Some resolvers answer a name that does not exist with a search-page
    // address; that answer is worse than none.
    let (server, _) = upstream("192.0.2.77".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            bogus_nxdomain: vec![("192.0.2.0".parse().unwrap(), 24)],
            ..Default::default()
        },
    )
    .await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    let resp = out.response().expect("an answer");

    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert!(resp.answers.is_empty());
}

#[tokio::test]
async fn an_address_outside_the_bogus_range_is_passed_through() {
    let (server, _) = upstream("198.51.100.5".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            bogus_nxdomain: vec![("192.0.2.0".parse().unwrap(), 24)],
            ..Default::default()
        },
    )
    .await;

    let out = r
        .resolve(&request("example.com."), Proto::Udp, &lan_client())
        .await;
    let resp = out.response().expect("an answer");

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
}

#[tokio::test]
async fn an_aaaa_query_is_synthesised_from_the_a_answer() {
    // The fake upstream answers every question with an address, so an AAAA
    // query comes back empty only because DNS64 rewrites what it receives;
    // here it answers A, which is what DNS64 asks for second.
    let (server, _) = upstream("192.0.2.33".parse().unwrap(), Duration::ZERO).await;
    let r = resolver(
        server,
        Settings {
            dns64: sift_dns::dns64::Prefixes::new(true, []),
            ..Default::default()
        },
    )
    .await;

    let mut req = Message::query();
    req.metadata.id = 1;
    req.add_query(Query::query(
        Name::from_utf8("example.com.").unwrap(),
        RecordType::AAAA,
    ));

    let out = r.resolve(&req, Proto::Udp, &lan_client()).await;
    let resp = out.response().expect("an answer");

    let addrs = sift_dns::resolver::answer_addrs(resp);
    assert_eq!(
        addrs,
        vec!["64:ff9b::c000:221".parse::<IpAddr>().unwrap()],
        "the IPv4 answer should be mapped into the well-known prefix"
    );
}
