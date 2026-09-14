//! The control API's routing table and its authentication gate.

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde_json::json;

use crate::error::ApiResult;
use crate::handlers::{filtering, logs, misc, status};
use crate::state::Shared;

/// Paths under `/control` that are reachable without a session.
///
/// Logging in obviously cannot require a login, and the setup wizard runs
/// before any user exists.
const PUBLIC: &[&str] = &[
    "/control/login",
    "/control/install/get_addresses",
    "/control/install/check_config",
    "/control/install/configure",
];

/// Builds the full application router.
pub fn router(state: Shared) -> Router {
    let control = control_router()
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state.clone());

    Router::new()
        .nest("/control", control)
        .fallback(get(serve_ui))
        .with_state(state)
}

/// Serves the embedded web interface.
async fn serve_ui(headers: HeaderMap, req: Request) -> Response {
    crate::ui::serve(req.uri().path(), &headers)
}

/// Rejects requests that carry no valid session, once a user exists.
async fn require_auth(State(s): State<Shared>, req: Request, next: Next) -> Response {
    let path = req.uri().path().to_string();

    // Before the wizard has run there is nobody to authenticate as.
    let open = s.needs_install() || PUBLIC.contains(&path.as_str());
    if open || misc::current_user(&s, req.headers()).is_some() {
        return next.run(req).await;
    }

    // The UI watches for 401 and redirects to the login page itself.
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"AdGuard Home\"")],
        "forbidden",
    )
        .into_response()
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
        .route("/update", post(not_supported))
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
            get(misc::clients_find).post(misc::clients_find),
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
        .route("/tls/configure", post(not_supported))
        .route("/tls/validate", post(not_supported))
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

/// Answers endpoints this build does not implement.
///
/// A clear 501 is better than a silent success that leaves the user thinking
/// a setting took effect.
async fn not_supported() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "this endpoint is not implemented by adguardlite",
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
        "this build of adguardlite has no DHCP server; \
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

    #[tokio::test]
    async fn every_dhcp_change_is_refused() {
        // Storing DHCP settings nothing acts on would look like a working
        // server from the web interface.
        let r = dhcp_unsupported().await;
        assert_eq!(r.status(), StatusCode::NOT_IMPLEMENTED);
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
