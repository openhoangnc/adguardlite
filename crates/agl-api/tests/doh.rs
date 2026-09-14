//! End-to-end checks of the DNS-over-HTTPS routes, through the real router.
//!
//! These run over plain HTTP with `insecure_enabled` set, so no certificate is
//! needed: what is being checked is the routing, the two request forms and the
//! refusal, not TLS. The TLS listeners are exercised in `agl-dns`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agl_api::state::{AppState, NoFetcher, NoReloader, Shared};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

/// Builds a server state whose engine blocks `ads.example.com`.
fn state(insecure: bool) -> Shared {
    let mut config = agl_config::Config::default();
    config.http.doh.insecure_enabled = insecure;
    config.dns.upstream_dns = vec![];
    config.dns.bootstrap_dns = vec![];
    config.filters = vec![];
    // A configured user, so `/` serves the interface rather than redirecting
    // to the setup wizard. DoH itself sits outside `/control` and is not
    // gated either way; this only decides what the UI fallback returns.
    config.users = vec![agl_config::model::WebUser {
        name: "admin".to_string(),
        password: agl_api::auth::hash_password("unused by these tests").expect("hashing"),
    }];

    let resolver = Arc::new(agl_dns::resolver::Resolver::new(
        agl_filter::engine::Engine::build([(1i64, "||ads.example.com^")], []),
        agl_dns::rewrite::Table::default(),
        agl_dns::cache::Cache::new(agl_dns::cache::Config::default()),
        agl_dns::pool::SharedPool::new(agl_dns::pool::Pool::new(
            vec![],
            vec![],
            vec![],
            agl_dns::pool::Mode::LoadBalance,
            Duration::from_millis(50),
            Duration::from_millis(50),
        )),
        agl_dns::resolver::Settings::default(),
    ));

    let dns_server = Arc::new(agl_dns::server::Server::new(
        resolver.clone(),
        Arc::new(agl_dns::ratelimit::Limiter::new(
            agl_dns::ratelimit::Config {
                per_second: 0,
                ..Default::default()
            },
        )),
        Arc::new(agl_dns::server::NoopObserver),
    ));

    let base = std::env::temp_dir().join(format!("agl-doh-{}", std::process::id()));
    let paths = agl_config::Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
    paths.ensure().expect("preparing the working directory");

    Arc::new(AppState {
        paths: paths.clone(),
        config: parking_lot::RwLock::new(config),
        resolver,
        dns_server,
        filters: parking_lot::RwLock::new(agl_filter::lists::Manager::default()),
        querylog: Arc::new(agl_querylog::log::QueryLog::new(
            paths.query_log(""),
            paths.query_log_rotated(""),
            agl_querylog::log::Config {
                file_enabled: false,
                ..Default::default()
            },
        )),
        stats: Arc::new(agl_stats::stats::Stats::new(
            agl_stats::stats::Config::default(),
        )),
        sessions: agl_api::auth::Sessions::new(),
        started: jiff::Timestamp::now(),
        fetcher: Arc::new(NoFetcher),
        reloader: Arc::new(NoReloader),
        dns_addresses: parking_lot::RwLock::new(vec![]),
        version: Arc::new(agl_api::state::NoVersionCheck),
        version_cache: parking_lot::RwLock::new(None),
    })
}

/// Starts the router on an ephemeral port and returns its address.
async fn serve(insecure: bool) -> SocketAddr {
    // The router is built as if it were the encrypted listener only when the
    // test asks for it; otherwise plain-HTTP DoH must be refused.
    let app = agl_api::routes::router(state(insecure), false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    addr
}

/// Encodes an `A` query.
fn query(name: &str) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.id = 0x4321;
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

    m.to_bytes().unwrap()
}

/// Performs one HTTP request and returns the status and body.
async fn request(
    method: &str,
    url: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> (u16, Vec<u8>) {
    use http_body_util::{BodyExt, Full};

    let uri: hyper::Uri = url.parse().unwrap();
    let host = uri.host().unwrap().to_string();
    let port = uri.port_u16().unwrap();
    let stream = tokio::net::TcpStream::connect((host.as_str(), port))
        .await
        .unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut b = hyper::Request::builder()
        .method(method)
        .uri(uri.path_and_query().unwrap().as_str())
        .header("host", format!("{host}:{port}"));
    if let Some(ct) = content_type {
        b = b.header("content-type", ct);
    }

    let req = b
        .body(Full::new(bytes::Bytes::from(body.unwrap_or_default())))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    task.abort();

    (status, bytes)
}

/// Base64url-encodes a query the way the GET form carries it.
fn encode(wire: &[u8]) -> String {
    use base64::Engine as _;

    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire)
}

#[tokio::test]
async fn post_answers_a_blocked_name() {
    let addr = serve(true).await;
    let (status, body) = request(
        "POST",
        &format!("http://{addr}/dns-query"),
        Some(query("ads.example.com.")),
        Some("application/dns-message"),
    )
    .await;

    assert_eq!(status, 200);
    let m = Message::from_bytes(&body).expect("the body must be a DNS message");
    assert_eq!(m.metadata.id, 0x4321);
    assert_eq!(m.answers.len(), 1, "the blocked name should be answered");
}

#[tokio::test]
async fn get_answers_a_blocked_name() {
    let addr = serve(true).await;
    let url = format!(
        "http://{addr}/dns-query?dns={}",
        encode(&query("ads.example.com."))
    );
    let (status, body) = request("GET", &url, None, None).await;

    assert_eq!(status, 200);
    assert_eq!(Message::from_bytes(&body).unwrap().answers.len(), 1);
}

#[tokio::test]
async fn the_client_id_route_answers_too() {
    // Upstream's default routes include a ClientID path segment.
    let addr = serve(true).await;

    let (status, body) = request(
        "POST",
        &format!("http://{addr}/dns-query/my-laptop"),
        Some(query("ads.example.com.")),
        Some("application/dns-message"),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(Message::from_bytes(&body).unwrap().answers.len(), 1);

    let url = format!(
        "http://{addr}/dns-query/my-laptop?dns={}",
        encode(&query("ads.example.com."))
    );
    let (status, _) = request("GET", &url, None, None).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn plain_http_is_refused_unless_allowed() {
    // Serving DNS over unencrypted HTTP exposes queries, so it is off by
    // default even though the route exists.
    let addr = serve(false).await;
    let (status, _) = request(
        "POST",
        &format!("http://{addr}/dns-query"),
        Some(query("ads.example.com.")),
        Some("application/dns-message"),
    )
    .await;

    assert_eq!(status, 404, "plain-HTTP DoH must not answer by default");
}

#[tokio::test]
async fn a_post_without_the_dns_media_type_is_refused() {
    let addr = serve(true).await;
    let (status, _) = request(
        "POST",
        &format!("http://{addr}/dns-query"),
        Some(query("ads.example.com.")),
        Some("application/json"),
    )
    .await;

    assert_eq!(status, 415);
}

#[tokio::test]
async fn a_get_without_the_dns_parameter_is_refused() {
    let addr = serve(true).await;
    let (status, _) = request("GET", &format!("http://{addr}/dns-query"), None, None).await;

    assert_eq!(status, 400);
}

#[tokio::test]
async fn a_malformed_query_is_refused_rather_than_answered() {
    let addr = serve(true).await;
    let (status, _) = request(
        "POST",
        &format!("http://{addr}/dns-query"),
        Some(b"this is not a dns message".to_vec()),
        Some("application/dns-message"),
    )
    .await;

    assert_eq!(status, 400);
}

#[tokio::test]
async fn the_web_interface_still_serves_alongside_dns() {
    // Both share the router, so one must not shadow the other.
    let addr = serve(true).await;
    let (status, body) = request("GET", &format!("http://{addr}/"), None, None).await;

    assert_eq!(status, 200);
    assert!(!body.is_empty());
}
