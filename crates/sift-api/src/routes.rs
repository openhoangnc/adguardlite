//! The control API's routing table and its authentication gate.

use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::json;

use crate::doh;
use crate::error::ApiResult;
use crate::handlers::{filtering, logs, misc, status};
use crate::state::Shared;

/// Paths reachable without a session, always.
///
/// These are matched against the path *inside* the `/control` router.
/// `Router::nest` strips the prefix before any middleware layered on the
/// inner router sees it, so a full path spelled `/control/login` here matches
/// nothing and silently locks the web interface out — which is exactly what
/// it did.  `login_is_reachable_without_a_session` drives the whole router so
/// the stripping is part of the test.
const PUBLIC: &[&str] = &["/login"];

/// Paths that serve the setup wizard, reachable only until it has run.
///
/// Upstream registers these handlers only on the first launch, so once a user
/// exists they are gone.  Leaving them reachable would let anyone re-run the
/// wizard over a configured server.
const INSTALL: &[&str] = &[
    "/install/get_addresses",
    "/install/check_config",
    "/install/configure",
];

/// Builds the full application router.
///
/// `secure` says whether this router is serving an encrypted listener; it
/// decides whether DNS-over-HTTPS answers, since serving DNS over plain HTTP
/// exposes queries to the network.
pub fn router(state: Shared, secure: bool) -> Router {
    let control = control_router()
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state.clone());

    // DNS-over-HTTPS shares the router with the web interface, because
    // upstream serves both on the HTTPS port.  The routes are the defaults in
    // `http.doh.routes`; a ClientID may be appended as a path segment.
    let dns = Router::new()
        .route("/dns-query", get(doh::get).post(doh::post))
        .route(
            "/dns-query/{client_id}",
            get(doh::get_with_client).post(doh::post_with_client),
        );

    let mut app = Router::new()
        .nest("/control", control)
        .merge(dns.with_state(state.clone()))
        .fallback(get(serve_ui));

    // On the plain listener, `force_https` sends browsers to the encrypted
    // one.  The redirect is added only there: applying it to the HTTPS router
    // would send every request back to itself.
    if !secure {
        app = app.layer(middleware::from_fn_with_state(
            state.clone(),
            redirect_to_https,
        ));
    }

    app.layer(axum::Extension(doh::Secure(secure)))
        .with_state(state)
}

/// Redirects a plain-HTTP request to the HTTPS port when `force_https` is set.
///
/// DNS-over-HTTPS is left alone: a DoH client does not follow redirects, and
/// whether it may use the plain port is already decided by
/// `http.doh.insecure_enabled`.
async fn redirect_to_https(State(s): State<Shared>, req: Request, next: Next) -> Response {
    let (enabled, port) = {
        let cfg = s.config.read();

        (
            cfg.tls.enabled && cfg.tls.force_https && cfg.tls.port_https != 0,
            cfg.tls.port_https,
        )
    };

    let path = req.uri().path();
    if !enabled || path.starts_with("/dns-query") {
        return next.run(req).await;
    }

    let Some(host) = host_without_port(req.headers()) else {
        return next.run(req).await;
    };

    let target = if port == 443 {
        format!("https://{host}{}", path_and_query(&req))
    } else {
        format!("https://{host}:{port}{}", path_and_query(&req))
    };

    match target.parse::<header::HeaderValue>() {
        Ok(v) => (StatusCode::FOUND, [(header::LOCATION, v)]).into_response(),
        Err(_) => next.run(req).await,
    }
}

/// The `Host` header without its port, which the redirect target rebuilds.
fn host_without_port(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?.trim();
    if host.is_empty() {
        return None;
    }

    // An IPv6 literal is bracketed, so the last colon is only a port
    // separator when it comes after the closing bracket.
    if let Some(end) = host.rfind(']') {
        return Some(host[..=end].to_string());
    }

    Some(match host.rsplit_once(':') {
        Some((h, _)) => h.to_string(),
        None => host.to_string(),
    })
}

/// The path and query of a request, as the redirect target needs them.
fn path_and_query(req: &Request) -> String {
    req.uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_else(|| "/".to_string())
}

/// Serves the embedded web interface.
///
/// Before the wizard has run, everything but the wizard's own assets is
/// redirected to it, and afterwards the wizard is gone.  Both halves are
/// upstream's `postInstallHandler`/`preInstallHandler`: without the redirect
/// a new install opens on a dashboard for a server that has no user, and
/// without the 403 the wizard stays reachable over a configured one.
///
/// Once a user exists the pages sit behind the same gate as the API, because
/// upstream's authentication middleware wraps its whole mux rather than only
/// `/control`.  The redirect from `/` is the *only* way a signed-out browser
/// reaches the login form: the shipped interface sends itself to
/// `/login.html` when an API call answers **403**, and the gate answers 401,
/// so a dashboard handed to a signed-out visitor is a dashboard that can
/// never load.
async fn serve_ui(State(s): State<Shared>, headers: HeaderMap, req: Request) -> Response {
    let path = req.uri().path();

    if s.needs_install() {
        if !is_install_page(path) && !path.starts_with("/assets/") {
            return (StatusCode::FOUND, [(header::LOCATION, "install.html")], "").into_response();
        }

        return crate::ui::serve(path, &headers);
    }

    if is_install_page(path) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    let user = match authenticate(&s, &req) {
        Ok(u) => u,
        Err(left) => return crate::auth::too_many_attempts(left),
    };

    if user.is_some() {
        // Someone who is already signed in has no use for the login form.
        if path == "/login.html" || path == "/forgot_password.html" {
            return (StatusCode::FOUND, [(header::LOCATION, "/")], "").into_response();
        }
    } else if !is_public_page(path) {
        if path == "/" || path == "/index.html" {
            return (StatusCode::FOUND, [(header::LOCATION, "login.html")], "").into_response();
        }

        return (StatusCode::UNAUTHORIZED, "").into_response();
    }

    crate::ui::serve(path, &headers)
}

/// The part of a request path that names an asset.
///
/// The build puts its hashed bundles under `/static/`, so `/login.html` and
/// `/static/login.4b8e.js` are both the login page's — one the document, one
/// what it is built from.  Both gates below reason about the name, so both
/// strip the directory first; matching `/login.` against the raw path missed
/// the script the moment webpack started writing it somewhere else, and
/// locked the login form out of its own JavaScript.
fn asset_name(path: &str) -> &str {
    path.strip_prefix("/static/")
        .unwrap_or_else(|| path.trim_start_matches('/'))
}

/// Reports whether a page is served without a session.
///
/// Upstream's `isPublicResource`, minus the API paths it also lists: the
/// login and password-reset pages, the hashed script and stylesheet built
/// beside them, and the icons under `/assets/`.  The dashboard's own
/// `main.<hash>.js` is deliberately not here.
fn is_public_page(path: &str) -> bool {
    let name = asset_name(path);

    path.starts_with("/assets/")
        || name.starts_with("login.")
        || name.starts_with("forgot_password.")
}

/// Reports whether a path belongs to the setup wizard.
///
/// The wizard's document and the bundle it loads, so the first launch can
/// serve them and a configured server can refuse them.
fn is_install_page(path: &str) -> bool {
    asset_name(path).starts_with("install.")
}

/// Identifies the caller, throttling Basic-credential guessing as it goes.
///
/// `Err` carries how long a client that has spent its attempts must wait;
/// building the refusal is left to the caller, which keeps the response types
/// out of a function whose answer is a user name.
///
/// Upstream throttles its Basic path and not its cookie path, and so does
/// this: a session token is sixteen random bytes, so guessing one is not a
/// threat worth slowing down, while guessing a password is.  A request with
/// no `Authorization` header at all therefore costs a client nothing, which
/// is how a signed-out browser can keep asking for `/` without locking the
/// address out.
fn authenticate(s: &Shared, req: &Request) -> Result<Option<String>, Duration> {
    let headers = req.headers();
    if !headers.contains_key(header::AUTHORIZATION) {
        return Ok(misc::current_user(s, headers));
    }

    let client = peer_ip(req);
    let left = s.login_limiter.blocked_for(&client);
    if !left.is_zero() {
        return Err(left);
    }

    let user = misc::current_user(s, headers);
    if user.is_some() {
        s.login_limiter.record_success(&client);
    } else {
        s.login_limiter.record_failure(&client);
    }

    Ok(user)
}

/// The address a request arrived from, which the throttle keys on.
///
/// The connection's own peer, never a forwarded-for header: upstream refuses
/// to read one here because anyone able to set it could otherwise spend
/// someone else's attempts, or dodge their own block by changing it.
/// See <https://github.com/AdguardTeam/AdGuardHome/issues/2799>.
///
/// The port is dropped, or every fresh connection would be a fresh client and
/// the throttle would hold nobody back.
pub fn peer_ip(req: &Request) -> String {
    req.extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_default()
}

/// Rejects requests that carry no valid session, once a user exists.
///
/// `path` is the path within the `/control` router: see [`PUBLIC`].
async fn require_auth(State(s): State<Shared>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();
    let first_run = s.needs_install();

    // The wizard's own endpoints stop existing once it has run, as upstream's
    // do, rather than staying open for a second pass over a live config.
    if !first_run && INSTALL.contains(&path.as_str()) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    // Before the wizard has run there is nobody to authenticate as.
    let open = first_run || PUBLIC.contains(&path.as_str());
    if open {
        return next.run(req).await;
    }

    match authenticate(&s, &req) {
        Ok(Some(_)) => return next.run(req).await,
        Ok(None) => {}
        Err(left) => return crate::auth::too_many_attempts(left),
    }

    // A bare 401, as upstream writes.  Adding `WWW-Authenticate: Basic` here
    // -- which this did -- hands the exchange to the browser, which answers
    // the web interface's own background request with its native sign-in
    // dialog and never lets `/login.html` render.  Basic credentials are
    // still *accepted*; they are simply not solicited.
    (StatusCode::UNAUTHORIZED, "forbidden").into_response()
}

/// The `/control` sub-router.
fn control_router() -> Router<Shared> {
    Router::new()
        // Status and DNS settings.
        .route("/status", get(status::status))
        .route("/dns_info", get(status::dns_info))
        .route("/dns_config", post(status::set_dns_config))
        .route("/protection", post(status::set_protection))
        .route("/cache_clear", post(status::cache_clear))
        .route("/test_upstream_dns", post(status::test_upstream))
        .route("/version.json", get(status::version).post(status::version))
        .route("/update", post(update_unsupported))
        // Filtering.
        .route("/filtering/status", get(filtering::status))
        .route("/filtering/config", post(filtering::set_config))
        .route("/filtering/add_url", post(filtering::add_url))
        .route("/filtering/remove_url", post(filtering::remove_url))
        .route("/filtering/set_url", post(filtering::set_url))
        .route("/filtering/refresh", post(filtering::refresh))
        .route("/filtering/set_rules", post(filtering::set_rules))
        .route("/filtering/check_host", get(filtering::check_host))
        // Safety toggles.
        .route(
            "/safebrowsing/enable",
            post(|State(s): State<Shared>| filtering::safebrowsing_set(s, true)),
        )
        .route(
            "/safebrowsing/disable",
            post(|State(s): State<Shared>| filtering::safebrowsing_set(s, false)),
        )
        .route("/safebrowsing/status", get(filtering::safebrowsing_status))
        .route(
            "/parental/enable",
            post(|State(s): State<Shared>| filtering::parental_set(s, true)),
        )
        .route(
            "/parental/disable",
            post(|State(s): State<Shared>| filtering::parental_set(s, false)),
        )
        .route("/parental/status", get(filtering::parental_status))
        .route(
            "/safesearch/enable",
            post(|State(s): State<Shared>| filtering::safesearch_set(s, true)),
        )
        .route(
            "/safesearch/disable",
            post(|State(s): State<Shared>| filtering::safesearch_set(s, false)),
        )
        // Upstream answers GET here with 405; only PUT is defined.
        .route("/safesearch/settings", put(filtering::safesearch_settings))
        .route("/safesearch/status", get(filtering::safesearch_status))
        // Rewrites.
        .route("/rewrite/list", get(filtering::rewrite_list))
        .route("/rewrite/add", post(filtering::rewrite_add))
        .route("/rewrite/delete", post(filtering::rewrite_delete))
        .route("/rewrite/update", put(filtering::rewrite_update))
        .route("/rewrite/settings", get(filtering::rewrite_settings))
        .route(
            "/rewrite/settings/update",
            put(filtering::rewrite_settings_update),
        )
        // Query log.
        .route("/querylog", get(logs::querylog))
        .route("/querylog_info", get(logs::querylog_info))
        .route("/querylog_config", post(logs::querylog_config_legacy))
        .route("/querylog_clear", post(logs::querylog_clear))
        .route("/querylog/config", get(logs::querylog_config))
        .route("/querylog/config/update", put(logs::querylog_config_update))
        // Statistics.
        .route("/stats", get(logs::stats))
        .route("/stats_reset", post(logs::stats_reset))
        .route("/stats_info", get(logs::stats_info))
        .route("/stats_config", post(logs::stats_config_legacy))
        .route("/stats/config", get(logs::stats_config))
        .route("/stats/config/update", put(logs::stats_config_update))
        // Clients and access control.
        .route("/clients", get(misc::clients))
        .route("/clients/add", post(misc::clients_add))
        .route("/clients/delete", post(misc::clients_delete))
        .route("/clients/update", post(misc::clients_update))
        .route("/clients/find", get(misc::clients_find))
        .route(
            "/clients/search",
            get(misc::clients_find).post(misc::clients_search),
        )
        .route("/access/list", get(misc::access_list))
        .route("/access/set", post(misc::access_set))
        // Blocked services.
        .route("/blocked_services/services", get(misc::services_ids))
        .route("/blocked_services/all", get(misc::services_all))
        .route("/blocked_services/list", get(misc::services_list))
        .route("/blocked_services/set", post(misc::services_set))
        .route("/blocked_services/get", get(misc::services_get))
        .route("/blocked_services/update", put(misc::services_update))
        // Encryption.
        .route("/tls/status", get(misc::tls_status))
        .route("/tls/configure", post(misc::tls_configure))
        .route("/tls/validate", post(misc::tls_validate))
        // DHCP.  Not implemented: status reports the feature as off and every
        // change is refused.  See the DHCP section of TASK.md.
        .route("/dhcp/status", get(misc::dhcp_status))
        .route("/dhcp/interfaces", get(misc::dhcp_interfaces))
        .route("/dhcp/set_config", post(dhcp_unsupported))
        .route("/dhcp/find_active_dhcp", post(dhcp_unsupported))
        .route("/dhcp/add_static_lease", post(dhcp_unsupported))
        .route("/dhcp/remove_static_lease", post(dhcp_unsupported))
        .route("/dhcp/update_static_lease", put(dhcp_unsupported))
        .route("/dhcp/reset", post(dhcp_unsupported))
        .route("/dhcp/reset_leases", post(dhcp_unsupported))
        // Localisation and profile.
        .route("/i18n/current_language", get(misc::current_language))
        .route("/i18n/change_language", post(misc::change_language))
        .route("/profile", get(misc::profile))
        .route("/profile/update", put(misc::profile_update))
        // Sessions.
        .route("/login", post(misc::login))
        .route("/logout", get(misc::logout))
        // Setup wizard.
        .route("/install/get_addresses", get(misc::install_addresses))
        .route("/install/check_config", post(misc::install_check))
        .route("/install/configure", post(misc::install_configure))
        // Apple profiles.
        .route("/apple/doh.mobileconfig", get(mobileconfig_doh))
        .route("/apple/dot.mobileconfig", get(mobileconfig_dot))
}

/// Answers `POST /control/update`.
///
/// This build deliberately does not replace its own binary: it ships as a
/// container image and as archives, and rewriting a running executable in
/// place is the job of whatever installed it.
///
/// `/control/version.json` still reports the latest release so the interface
/// can say one exists, with `can_autoupdate` false so the button is not
/// offered.  See the updates section of TASK.md.
async fn update_unsupported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "this build of sift does not replace its own binary; \
         pull the new image or archive through whatever installed it",
    )
        .into_response()
}

/// Answers every DHCP endpoint that would change something.
///
/// This build deliberately ships no DHCP server -- see the DHCP section of
/// TASK.md -- so a request to configure one is refused rather than stored.
/// Accepting it would write settings into the config file that nothing acts
/// on, which reads as a working DHCP server from the web interface.
///
/// 501 is what upstream's own API documents for a build without DHCP support,
/// so the interface already knows how to present it.
async fn dhcp_unsupported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "this build of sift has no DHCP server; \
         use your router or a separate DHCP service",
    )
        .into_response()
}

/// `GET /control/apple/doh.mobileconfig`
async fn mobileconfig_doh(State(s): State<Shared>) -> ApiResult<Response> {
    mobileconfig(&s, "HTTPS")
}

/// `GET /control/apple/dot.mobileconfig`
async fn mobileconfig_dot(State(s): State<Shared>) -> ApiResult<Response> {
    mobileconfig(&s, "TLS")
}

/// Builds an Apple DNS settings profile.
fn mobileconfig(s: &Shared, proto: &str) -> ApiResult<Response> {
    let cfg = s.config.read();
    let host = if cfg.tls.server_name.is_empty() {
        "adguardhome".to_string()
    } else {
        cfg.tls.server_name.clone()
    };

    let server_entry = if proto == "HTTPS" {
        format!("<key>ServerURL</key><string>https://{host}/dns-query</string>")
    } else {
        format!("<key>ServerName</key><string>{host}</string>")
    };

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key><string>{proto}</string>
        {server_entry}
      </dict>
      <key>PayloadDescription</key><string>Configures device to use AdGuard Home</string>
      <key>PayloadDisplayName</key><string>AdGuard Home DNS over {proto}</string>
      <key>PayloadIdentifier</key><string>com.apple.dnsSettings.managed.adguardhome</string>
      <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>AdGuard Home DNS over {proto}</string>
  <key>PayloadIdentifier</key><string>com.adguardhome.dns</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#
    );

    Ok(([(header::CONTENT_TYPE, "application/xml")], plist).into_response())
}

/// A JSON body of `{"enabled": ...}`, used by several toggles.
pub async fn enabled_json(enabled: bool) -> Json<serde_json::Value> {
    Json(json!({ "enabled": enabled }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_header_loses_its_port() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "example.com:3000".parse().unwrap());
        assert_eq!(host_without_port(&h).as_deref(), Some("example.com"));

        h.insert(header::HOST, "example.com".parse().unwrap());
        assert_eq!(host_without_port(&h).as_deref(), Some("example.com"));

        h.insert(header::HOST, "[2001:db8::1]:3000".parse().unwrap());
        assert_eq!(host_without_port(&h).as_deref(), Some("[2001:db8::1]"));

        h.insert(header::HOST, "".parse().unwrap());
        assert_eq!(host_without_port(&h), None);
    }

    #[tokio::test]
    async fn self_update_is_refused_rather_than_pretending_to_work() {
        // Accepting it would have to download an AdGuard Home release and
        // write it over this binary, which replaces the implementation.
        let r = update_unsupported().await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn every_dhcp_change_is_refused() {
        // Storing DHCP settings nothing acts on would look like a working
        // server from the web interface.
        let r = dhcp_unsupported().await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn status_does_not_advertise_a_dhcp_server() {
        // The interface gates its whole DHCP section on `dhcp_available`:
        // answering true sends it to `/control/dhcp/status` and renders a
        // settings page whose every save answers 501.  Checking the source
        // rather than the value keeps this honest if the handler is rewritten.
        let src = include_str!("handlers/status.rs");
        assert!(
            src.contains("dhcp_available: false"),
            "status must not advertise a DHCP server that does not exist"
        );
    }

    #[test]
    fn the_login_form_can_reach_everything_it_is_built_from() {
        // Checked against the real build, not against names typed here: when
        // webpack moved its output under static/, `/login.` stopped matching
        // the login bundle and a signed-out browser got a blank page with two
        // 401s in the console.  Nothing in the suite noticed.
        let mut seen_script = false;

        for name in crate::ui::names() {
            let path = format!("/{name}");
            let base = asset_name(&path);

            if base.starts_with("login.") || base.starts_with("forgot_password.") {
                assert!(is_public_page(&path), "{path} must load without a session");
                seen_script |= base.ends_with(".js");
            } else if base.starts_with("main.") {
                // Upstream keeps the dashboard's own bundle behind the gate.
                assert!(!is_public_page(&path), "{path} must need a session");
            }
        }

        assert!(
            seen_script,
            "the build should carry a login bundle for this to mean anything"
        );
    }

    #[test]
    fn the_wizard_owns_its_bundle_wherever_the_build_puts_it() {
        let mut seen = false;
        for name in crate::ui::names() {
            let path = format!("/{name}");
            if asset_name(&path).starts_with("install.") {
                assert!(is_install_page(&path), "{path} belongs to the wizard");
                seen |= path.ends_with(".js");
            }
        }

        assert!(seen, "the build should carry an install bundle");
        assert!(!is_install_page("/index.html"));
        assert!(!is_install_page("/static/main.abc.js"));
    }

    #[test]
    fn every_dhcp_mutation_route_refuses() {
        // A route added later that forgets this would silently accept
        // settings, so check the table itself.
        let src = include_str!("routes.rs");
        for route in [
            "/dhcp/set_config",
            "/dhcp/find_active_dhcp",
            "/dhcp/add_static_lease",
            "/dhcp/remove_static_lease",
            "/dhcp/update_static_lease",
            "/dhcp/reset",
            "/dhcp/reset_leases",
        ] {
            let line = src
                .lines()
                .find(|l| l.contains(&format!("\"{route}\"")))
                .unwrap_or_else(|| panic!("{route} is not routed"));
            assert!(
                line.contains("dhcp_unsupported"),
                "{route} must refuse, but routes to: {line}"
            );
        }
    }
}
