//! Live checks against public resolvers.
//!
//! These need outbound network access, so they are `#[ignore]`d by default.
//! Run them with `cargo test -p agl-dns -- --ignored`.

use std::net::SocketAddr;
use std::time::Duration;

use agl_dns::addr;
use agl_dns::client::{Client, tls_config};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};

/// Builds an `A` query for `name`.
fn query(name: &str) -> Message {
    let mut m = Message::query();
    m.metadata.id = rand::random();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

    m
}

/// Resolves `spec` and asks it for `name`, returning the addresses it answers.
async fn resolve_via(spec: &str, name: &str) -> Vec<std::net::IpAddr> {
    let up = addr::parse(spec).unwrap().upstream.unwrap();
    let bootstrap: Vec<SocketAddr> = vec![
        "9.9.9.10:53".parse().unwrap(),
        "149.112.112.10:53".parse().unwrap(),
    ];

    let c = Client::connect(up, &bootstrap, Duration::from_secs(10), false, tls_config())
        .await
        .unwrap_or_else(|e| panic!("connecting to {spec}: {e}"));

    let resp = c
        .exchange(&query(name), Duration::from_secs(10))
        .await
        .unwrap_or_else(|e| panic!("querying {spec}: {e}"));

    resp.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(std::net::IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(std::net::IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

#[tokio::test]
#[ignore = "needs network"]
async fn plain_udp_upstream_resolves() {
    let ips = resolve_via("9.9.9.10", "example.com.").await;
    assert!(!ips.is_empty(), "expected an answer");
}

#[tokio::test]
#[ignore = "needs network"]
async fn tcp_upstream_resolves() {
    let ips = resolve_via("tcp://9.9.9.10", "example.com.").await;
    assert!(!ips.is_empty(), "expected an answer");
}

#[tokio::test]
#[ignore = "needs network"]
async fn dns_over_tls_upstream_resolves() {
    let ips = resolve_via("tls://dns.quad9.net", "example.com.").await;
    assert!(!ips.is_empty(), "expected an answer");
}

#[tokio::test]
#[ignore = "needs network"]
async fn dns_over_https_upstream_resolves() {
    // The default upstream a fresh AdGuard Home install uses.
    let ips = resolve_via("https://dns10.quad9.net/dns-query", "example.com.").await;
    assert!(!ips.is_empty(), "expected an answer");
}

#[tokio::test]
#[ignore = "needs network"]
async fn bootstrap_resolves_an_encrypted_upstreams_hostname() {
    let up = addr::parse("tls://dns.quad9.net")
        .unwrap()
        .upstream
        .unwrap();
    let bootstrap: Vec<SocketAddr> = vec!["9.9.9.10:53".parse().unwrap()];
    let c = Client::connect(up, &bootstrap, Duration::from_secs(10), false, tls_config())
        .await
        .expect("bootstrap should resolve the hostname");

    assert!(!c.addrs().is_empty());
    assert!(c.addrs().iter().all(|a| a.port() == 853));
}
