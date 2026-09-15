//! End-to-end checks of the authentication gate and the first-run routing,
//! through the real router.
//!
//! These drive the whole `Router`, not `control_router()` on its own, because
//! the bug they exist for lived in the seam: `Router::nest` strips `/control`
//! before any middleware layered on the inner router sees the path, so an
//! allowlist spelled in full paths matched nothing and `POST /control/login`
//! answered 401 to correct credentials. Nothing short of the assembled router
//! reproduces that.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agl_api::state::{AppState, NoFetcher, NoReloader, Shared};

/// Builds a server state, with a user configured or not.
fn state(user: Option<(&str, &str)>) -> Shared {
    let mut config = agl_config::Config::default();
    config.dns.upstream_dns = vec![];
    config.dns.bootstrap_dns = vec![];
    config.filters = vec![];
    config.users = user
        .map(|(name, password)| agl_config::model::WebUser {
            name: name.to_string(),
            password: agl_api::auth::hash_password(password).expect("hashing"),
        })
        .into_iter()
        .collect();

    let resolver = Arc::new(agl_dns::resolver::Resolver::new(
        agl_filter::engine::Engine::build(
            agl_filter::engine::NO_LISTS,
            agl_filter::engine::NO_LISTS,
        ),
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

    let base = std::env::temp_dir().join(format!(
        "agl-gate-{}-{:p}",
        std::process::id(),
        &config as *const _
    ));
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

/// Starts the assembled router on an ephemeral port.
async fn serve(user: Option<(&str, &str)>) -> SocketAddr {
    let app = agl_api::routes::router(state(user), false);
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

/// One request; returns the status, the `location` header and the body.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    cookie: Option<&str>,
) -> (u16, Option<String>, String) {
    use http_body_util::{BodyExt, Full};

    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    let task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", addr.to_string());
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(c) = cookie {
        builder = builder.header("cookie", c);
    }

    let req = builder
        .body(Full::new(hyper::body::Bytes::from(
            body.unwrap_or("").to_string(),
        )))
        .unwrap();

    let res = sender.send_request(req).await.unwrap();
    let status = res.status().as_u16();
    let location = res
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let set_cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    task.abort();

    // The session cookie is what the caller needs back from a login.
    let out = set_cookie.unwrap_or_else(|| String::from_utf8_lossy(&bytes).to_string());

    (status, location, out)
}

#[tokio::test]
async fn login_is_reachable_without_a_session() {
    // The regression: correct credentials answered 401 because the allowlist
    // was compared against `/control/login` while the middleware, sitting
    // inside the nest, was handed `/login`. Nobody could sign in at all.
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (status, _, cookie) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"correct horse"}"#),
        None,
    )
    .await;
    assert_eq!(status, 200, "login must not require a session");
    assert!(
        cookie.contains("agh_session"),
        "no session cookie: {cookie}"
    );

    // And the session it hands out actually opens the rest of the API.
    let jar = cookie.split(';').next().unwrap().to_string();
    let (status, _, _) = request(addr, "GET", "/control/status", None, Some(&jar)).await;
    assert_eq!(status, 200, "the session from login must be accepted");
}

#[tokio::test]
async fn a_wrong_password_is_still_refused() {
    let addr = serve(Some(("admin", "correct horse"))).await;

    let (status, _, _) = request(
        addr,
        "POST",
        "/control/login",
        Some(r#"{"name":"admin","password":"wrong"}"#),
        None,
    )
    .await;
    assert_eq!(status, 401);

    let (status, _, _) = request(addr, "GET", "/control/status", None, None).await;
    assert_eq!(status, 401, "the API stays shut without a session");
}

#[tokio::test]
async fn the_wizard_is_gone_once_a_user_exists() {
    // Upstream registers the install handlers only on the first launch. Left
    // open, they would let anyone re-run the wizard over a live config.
    let addr = serve(Some(("admin", "correct horse"))).await;

    for path in [
        "/control/install/get_addresses",
        "/control/install/check_config",
        "/control/install/configure",
    ] {
        let (status, _, _) = request(addr, "POST", path, Some("{}"), None).await;
        assert_eq!(status, 404, "{path} must not exist once configured");
    }

    let (status, _, _) = request(addr, "GET", "/install.html", None, None).await;
    assert_eq!(
        status, 403,
        "the wizard page must be refused once configured"
    );
}

#[tokio::test]
async fn the_first_launch_redirects_everything_to_the_wizard() {
    // Without this a fresh install opens on a dashboard for a server that has
    // no user and no settings.
    let addr = serve(None).await;

    for path in ["/", "/index.html", "/login.html"] {
        let (status, location, _) = request(addr, "GET", path, None, None).await;
        assert_eq!(status, 302, "{path} must redirect on the first launch");
        assert_eq!(location.as_deref(), Some("install.html"), "{path}");
    }

    // The wizard itself, and the assets it needs, are served.
    let (status, _, _) = request(addr, "GET", "/install.html", None, None).await;
    assert_eq!(status, 200);

    // And its endpoints are open, because there is nobody to authenticate as.
    let (status, _, _) = request(addr, "GET", "/control/install/get_addresses", None, None).await;
    assert_eq!(status, 200);
}
