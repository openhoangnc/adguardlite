//! Clients, access control, blocked services, encryption, DHCP, the setup
//! wizard and profile endpoints.

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::state::Shared;

/// The tags a client may carry, as the UI offers them.
const SUPPORTED_TAGS: &[&str] = &[
    "device_audio",
    "device_camera",
    "device_gameconsole",
    "device_laptop",
    "device_nas",
    "device_other",
    "device_pc",
    "device_phone",
    "device_printer",
    "device_securityalarm",
    "device_tablet",
    "device_tv",
    "os_android",
    "os_ios",
    "os_linux",
    "os_macos",
    "os_other",
    "os_windows",
    "user_admin",
    "user_child",
    "user_regular",
];

/// A configured client, as the API exchanges it.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ClientJson {
    /// The client's display name.
    pub name: String,
    /// Addresses, CIDRs, MACs and ClientIDs identifying the client.
    pub ids: Vec<String>,
    /// Whether global settings apply.
    pub use_global_settings: bool,
    /// Whether filtering applies.
    pub filtering_enabled: bool,
    /// Whether parental control applies.
    pub parental_enabled: bool,
    /// Whether safe browsing applies.
    pub safebrowsing_enabled: bool,
    /// Whether global blocked-service settings apply.
    pub use_global_blocked_services: bool,
    /// Services blocked for this client.
    #[serde(default)]
    pub blocked_services: Vec<String>,
    /// Per-client upstream resolvers.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Tags applied to the client.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Whether the client's queries are excluded from the log.
    #[serde(default)]
    pub ignore_querylog: bool,
    /// Whether the client's queries are excluded from statistics.
    #[serde(default)]
    pub ignore_statistics: bool,
    /// Safe-search settings for this client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_search: Option<serde_json::Value>,
}

/// `GET /control/clients`
pub async fn clients(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let clients: Vec<ClientJson> = cfg
        .clients
        .persistent
        .iter()
        .map(|c| ClientJson {
            name: c.name.clone(),
            ids: c.ids.clone(),
            use_global_settings: c.use_global_settings,
            filtering_enabled: c.filtering_enabled,
            parental_enabled: c.parental_enabled,
            safebrowsing_enabled: c.safebrowsing_enabled,
            use_global_blocked_services: c.use_global_blocked_services,
            blocked_services: c.blocked_services.ids.clone(),
            upstreams: c.upstreams.clone(),
            tags: c.tags.clone(),
            ignore_querylog: c.ignore_querylog,
            ignore_statistics: c.ignore_statistics,
            safe_search: None,
        })
        .collect();

    Json(json!({
        "clients": if clients.is_empty() { serde_json::Value::Null } else { serde_json::to_value(&clients).unwrap_or(serde_json::Value::Null) },
        "auto_clients": [],
        "supported_tags": SUPPORTED_TAGS,
    }))
}

/// Converts an API client into its configuration form.
fn to_persistent(c: &ClientJson) -> agl_config::model::PersistentClient {
    agl_config::model::PersistentClient {
        name: c.name.clone(),
        ids: c.ids.clone(),
        tags: c.tags.clone(),
        upstreams: c.upstreams.clone(),
        use_global_settings: c.use_global_settings,
        filtering_enabled: c.filtering_enabled,
        parental_enabled: c.parental_enabled,
        safebrowsing_enabled: c.safebrowsing_enabled,
        use_global_blocked_services: c.use_global_blocked_services,
        ignore_querylog: c.ignore_querylog,
        ignore_statistics: c.ignore_statistics,
        blocked_services: agl_config::model::BlockedServices {
            schedule: agl_config::model::Schedule::default(),
            ids: c.blocked_services.clone(),
        },
        ..Default::default()
    }
}

/// `POST /control/clients/add`
pub async fn clients_add(State(s): State<Shared>, Json(req): Json<ClientJson>) -> ApiResult<()> {
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("the client name must not be empty"));
    }
    if req.ids.is_empty() {
        return Err(ApiError::bad_request(
            "a client needs at least one identifier",
        ));
    }

    {
        let mut cfg = s.config.write();
        if cfg.clients.persistent.iter().any(|c| c.name == req.name) {
            return Err(ApiError::bad_request(
                "a client with this name already exists",
            ));
        }
        cfg.clients.persistent.push(to_persistent(&req));
    }

    s.save_config().map_err(ApiError::internal)
}

/// The `/control/clients/delete` request.
#[derive(Deserialize)]
pub struct DeleteClientReq {
    /// The client to remove.
    pub name: String,
}

/// `POST /control/clients/delete`
pub async fn clients_delete(
    State(s): State<Shared>,
    Json(req): Json<DeleteClientReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        let before = cfg.clients.persistent.len();
        cfg.clients.persistent.retain(|c| c.name != req.name);
        if cfg.clients.persistent.len() == before {
            return Err(ApiError::not_found("no client with that name"));
        }
    }

    s.save_config().map_err(ApiError::internal)
}

/// The `/control/clients/update` request.
#[derive(Deserialize)]
pub struct UpdateClientReq {
    /// The client to change.
    pub name: String,
    /// The new settings.
    pub data: ClientJson,
}

/// `POST /control/clients/update`
pub async fn clients_update(
    State(s): State<Shared>,
    Json(req): Json<UpdateClientReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        let Some(slot) = cfg
            .clients
            .persistent
            .iter_mut()
            .find(|c| c.name == req.name)
        else {
            return Err(ApiError::not_found("no client with that name"));
        };
        *slot = to_persistent(&req.data);
    }

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/clients/find`
pub async fn clients_find(State(s): State<Shared>) -> Json<Vec<serde_json::Value>> {
    let _ = &s;

    Json(Vec::new())
}

/// `GET /control/access/list`
pub async fn access_list(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let or_null = |v: &Vec<String>| {
        if v.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
        }
    };

    Json(json!({
        "allowed_clients": or_null(&cfg.dns.allowed_clients),
        "disallowed_clients": or_null(&cfg.dns.disallowed_clients),
        "blocked_hosts": cfg.dns.blocked_hosts,
    }))
}

/// The `/control/access/set` request.
#[derive(Deserialize, Default)]
pub struct AccessSetReq {
    /// Clients allowed to query, as an allowlist.
    #[serde(default)]
    pub allowed_clients: Option<Vec<String>>,
    /// Clients forbidden from querying.
    #[serde(default)]
    pub disallowed_clients: Option<Vec<String>>,
    /// Hosts refused outright.
    #[serde(default)]
    pub blocked_hosts: Option<Vec<String>>,
}

/// `POST /control/access/set`
pub async fn access_set(State(s): State<Shared>, Json(req): Json<AccessSetReq>) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        if let Some(v) = req.allowed_clients {
            cfg.dns.allowed_clients = v;
        }
        if let Some(v) = req.disallowed_clients {
            cfg.dns.disallowed_clients = v;
        }
        if let Some(v) = req.blocked_hosts {
            cfg.dns.blocked_hosts = v;
        }

        if !cfg.dns.allowed_clients.is_empty() && !cfg.dns.disallowed_clients.is_empty() {
            return Err(ApiError::bad_request(
                "allowed_clients and disallowed_clients cannot both be set",
            ));
        }
    }

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/blocked_services/all`
pub async fn services_all() -> Json<&'static agl_filter::services::Catalogue> {
    Json(agl_filter::services::catalogue())
}

/// `GET /control/blocked_services/services`
///
/// The legacy endpoint: just the identifiers.
pub async fn services_ids() -> Json<Vec<String>> {
    Json(agl_filter::services::ids())
}

/// `GET /control/blocked_services/list`
pub async fn services_list(State(s): State<Shared>) -> Json<Vec<String>> {
    Json(s.config.read().filtering.blocked_services.ids.clone())
}

/// `POST /control/blocked_services/set`
pub async fn services_set(State(s): State<Shared>, Json(ids): Json<Vec<String>>) -> ApiResult<()> {
    s.config.write().filtering.blocked_services.ids = ids.clone();
    s.filters.write().set_blocked_services(&ids);

    s.save_config().map_err(ApiError::internal)?;
    s.reloader.reload_filters(&s.filters.read());

    Ok(())
}

/// `GET /control/blocked_services/get`
pub async fn services_get(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let bs = &cfg.filtering.blocked_services;

    Json(json!({
        "schedule": { "time_zone": bs.schedule.time_zone },
        "ids": bs.ids,
    }))
}

/// The `/control/blocked_services/update` request.
#[derive(Deserialize)]
pub struct ServicesUpdateReq {
    /// The blocked service identifiers.
    #[serde(default)]
    pub ids: Vec<String>,
    /// When the block applies.
    #[serde(default)]
    pub schedule: Option<serde_json::Value>,
}

/// `PUT /control/blocked_services/update`
pub async fn services_update(
    State(s): State<Shared>,
    Json(req): Json<ServicesUpdateReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        s.filters.write().set_blocked_services(&req.ids);
        cfg.filtering.blocked_services.ids = req.ids;
        if let Some(tz) = req
            .schedule
            .as_ref()
            .and_then(|v| v.get("time_zone"))
            .and_then(|v| v.as_str())
        {
            cfg.filtering.blocked_services.schedule.time_zone = tz.to_string();
        }
    }

    s.save_config().map_err(ApiError::internal)?;
    s.reloader.reload_filters(&s.filters.read());

    Ok(())
}

/// `GET /control/tls/status`
pub async fn tls_status(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let t = &cfg.tls;

    let mut out = json!({
        "not_before": agl_core::gotime::GO_ZERO_TIME,
        "not_after": agl_core::gotime::GO_ZERO_TIME,
        "dns_names": serde_json::Value::Null,
        "valid_cert": false,
        "valid_chain": false,
        "valid_key": false,
        "valid_pair": false,
        "enabled": t.enabled,
        "force_https": t.force_https,
        "port_https": t.port_https,
        "port_dns_over_tls": t.port_dns_over_tls,
        "port_dns_over_quic": t.port_dns_over_quic,
        "port_dnscrypt": t.port_dnscrypt,
        "dnscrypt_config_file": t.dnscrypt_config_file,
        "certificate_chain": t.certificate_chain,
        "private_key": t.private_key,
        "certificate_path": t.certificate_path,
        "private_key_path": t.private_key_path,
        "private_key_saved": !t.private_key.is_empty() || !t.private_key_path.is_empty(),
        "serve_plain_dns": cfg.dns.serve_plain_dns,
    });

    // Upstream marks the server name `omitempty`, so an unset one is absent
    // rather than an empty string.
    if !t.server_name.is_empty()
        && let Some(m) = out.as_object_mut()
    {
        m.insert("server_name".into(), json!(t.server_name));
    }

    Json(out)
}

/// `GET /control/dhcp/status`
pub async fn dhcp_status(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let d = &cfg.dhcp;

    Json(json!({
        "interface_name": d.interface_name,
        "v4": {
            "gateway_ip": d.dhcpv4.gateway_ip.to_string(),
            "subnet_mask": d.dhcpv4.subnet_mask.to_string(),
            "range_start": d.dhcpv4.range_start.to_string(),
            "range_end": d.dhcpv4.range_end.to_string(),
            "lease_duration": d.dhcpv4.lease_duration,
        },
        "v6": {
            "range_start": d.dhcpv6.range_start.to_string(),
            "lease_duration": d.dhcpv6.lease_duration,
        },
        "leases": [],
        "static_leases": [],
        "enabled": d.enabled,
    }))
}

/// `GET /control/dhcp/interfaces`
pub async fn dhcp_interfaces() -> Json<serde_json::Value> {
    Json(json!({}))
}

/// `GET /control/i18n/current_language`
pub async fn current_language(State(s): State<Shared>) -> String {
    s.config.read().language.clone()
}

/// `POST /control/i18n/change_language`
pub async fn change_language(State(s): State<Shared>, body: String) -> ApiResult<()> {
    let lang = body.trim().trim_matches('"').to_string();
    s.config.write().language = lang;

    s.save_config().map_err(ApiError::internal)
}

/// `GET /control/profile`
pub async fn profile(State(s): State<Shared>, headers: HeaderMap) -> Json<serde_json::Value> {
    let cfg = s.config.read();
    let name = current_user(&s, &headers).unwrap_or_else(|| {
        cfg.users
            .first()
            .map(|u| u.name.clone())
            .unwrap_or_default()
    });

    Json(json!({
        "name": name,
        "language": cfg.language,
        "theme": cfg.theme,
    }))
}

/// The `/control/profile/update` request.
#[derive(Deserialize)]
pub struct ProfileUpdateReq {
    /// The UI language.
    #[serde(default)]
    pub language: Option<String>,
    /// The UI theme.
    #[serde(default)]
    pub theme: Option<String>,
}

/// `PUT /control/profile/update`
pub async fn profile_update(
    State(s): State<Shared>,
    Json(req): Json<ProfileUpdateReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        if let Some(l) = req.language {
            cfg.language = l;
        }
        if let Some(t) = req.theme {
            cfg.theme = match t.as_str() {
                "dark" => agl_config::model::Theme::Dark,
                "light" => agl_config::model::Theme::Light,
                _ => agl_config::model::Theme::Auto,
            };
        }
    }

    s.save_config().map_err(ApiError::internal)
}

/// Returns the name of the user the request is authenticated as.
pub fn current_user(s: &Shared, headers: &HeaderMap) -> Option<String> {
    if let Some(c) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        && let Some(tok) = auth::token_from_cookies(c)
        && let Some(sess) = s.sessions.get(tok)
    {
        return Some(sess.user);
    }

    let a = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (user, pass) = auth::basic_credentials(a)?;
    let cfg = s.config.read();
    let u = cfg.users.iter().find(|u| u.name == user)?;

    auth::verify_password(&pass, &u.password).then_some(user)
}

/// The `/control/login` request.
#[derive(Deserialize)]
pub struct LoginReq {
    /// The user name.
    pub name: String,
    /// The password.
    pub password: String,
}

/// `POST /control/login`
pub async fn login(State(s): State<Shared>, Json(req): Json<LoginReq>) -> Response {
    let ok = {
        let cfg = s.config.read();
        cfg.users
            .iter()
            .find(|u| u.name == req.name)
            .is_some_and(|u| auth::verify_password(&req.password, &u.password))
    };

    if !ok {
        return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
    }

    let ttl = Duration::from_secs(s.config.read().http.session_ttl.as_secs().max(1) as u64);
    let token = s.sessions.create(&req.name, ttl);

    let mut headers = HeaderMap::new();
    if let Ok(v) = auth::session_cookie(&token, ttl).parse() {
        headers.insert(header::SET_COOKIE, v);
    }

    (StatusCode::OK, headers).into_response()
}

/// `GET /control/logout`
pub async fn logout(State(s): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(c) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())
        && let Some(tok) = auth::token_from_cookies(c)
    {
        s.sessions.remove(tok);
    }

    let mut out = HeaderMap::new();
    if let Ok(v) = auth::clear_cookie().parse() {
        out.insert(header::SET_COOKIE, v);
    }
    if let Ok(v) = "/login.html".parse() {
        out.insert(header::LOCATION, v);
    }

    (StatusCode::FOUND, out).into_response()
}

/// `GET /control/install/get_addresses`
pub async fn install_addresses(State(s): State<Shared>) -> Json<serde_json::Value> {
    let cfg = s.config.read();

    Json(json!({
        "web_port": cfg.http.address.0.port(),
        "dns_port": cfg.dns.port,
        "interfaces": {},
        "version": agl_core::AGH_VERSION,
    }))
}

/// The `/control/install/check_config` request.
#[derive(Deserialize)]
pub struct CheckConfigReq {
    /// The proposed web interface binding.
    #[serde(default)]
    pub web: Option<PortCheck>,
    /// The proposed DNS binding.
    #[serde(default)]
    pub dns: Option<PortCheck>,
    /// Whether to set the system resolver.
    #[serde(default)]
    pub set_static_ip: bool,
}

/// A proposed address and port.
#[derive(Deserialize)]
pub struct PortCheck {
    /// The address to bind.
    #[serde(default)]
    pub ip: Option<String>,
    /// The port to bind.
    #[serde(default)]
    pub port: Option<u16>,
    /// Whether the port is being changed.
    #[serde(default)]
    pub autofix: bool,
}

/// `POST /control/install/check_config`
pub async fn install_check(Json(_req): Json<CheckConfigReq>) -> Json<serde_json::Value> {
    Json(json!({
        "web": { "status": "" },
        "dns": { "status": "" },
        "static_ip": { "static": "no", "ip": "", "error": "" },
    }))
}

/// The `/control/install/configure` request.
#[derive(Deserialize)]
pub struct InstallReq {
    /// The web interface binding.
    pub web: PortCheck,
    /// The DNS binding.
    pub dns: PortCheck,
    /// The administrator's name.
    pub username: String,
    /// The administrator's password.
    pub password: String,
}

/// `POST /control/install/configure`
pub async fn install_configure(
    State(s): State<Shared>,
    Json(req): Json<InstallReq>,
) -> ApiResult<()> {
    if req.username.trim().is_empty() || req.password.is_empty() {
        return Err(ApiError::bad_request(
            "a username and password are required",
        ));
    }
    if !s.needs_install() {
        return Err(ApiError::forbidden(
            "this installation is already configured",
        ));
    }

    let hash = auth::hash_password(&req.password)
        .map_err(|e| ApiError::internal(format!("hashing the password: {e}")))?;

    {
        let mut cfg = s.config.write();
        cfg.users = vec![agl_config::model::WebUser {
            name: req.username,
            password: hash,
        }];

        if let Some(p) = req.dns.port {
            cfg.dns.port = p;
        }
        if let Some(ip) = req.dns.ip.as_deref().and_then(|i| i.parse().ok()) {
            cfg.dns.bind_hosts = vec![ip];
        }
        if let (Some(ip), Some(port)) = (
            req.web
                .ip
                .as_deref()
                .and_then(|i| i.parse::<std::net::IpAddr>().ok()),
            req.web.port,
        ) {
            cfg.http.address = agl_config::types::AddrPort(std::net::SocketAddr::new(ip, port));
        }
    }

    s.save_config().map_err(ApiError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_supported_tag_list_matches_the_ui() {
        // These are exactly what /control/clients reports upstream.
        assert_eq!(SUPPORTED_TAGS.len(), 21);
        assert!(SUPPORTED_TAGS.contains(&"device_phone"));
        assert!(SUPPORTED_TAGS.contains(&"os_windows"));
        assert!(SUPPORTED_TAGS.contains(&"user_child"));
        assert!(
            SUPPORTED_TAGS.windows(2).all(|w| w[0] < w[1]),
            "kept sorted"
        );
    }
}
