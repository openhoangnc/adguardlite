//! Server status, DNS settings and cache control.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sift_config::model::UpstreamMode;

use crate::error::{ApiError, ApiResult};
use crate::state::Shared;

/// The `/control/status` response.
#[derive(Serialize)]
pub struct StatusResp {
    /// The running version.
    pub version: String,
    /// The configured UI language.
    pub language: String,
    /// The addresses the DNS server listens on.
    ///
    /// Plain DNS first, as the listeners bound it, then the encrypted
    /// addresses [`encrypted_addresses`] derives from the TLS settings.
    pub dns_addresses: Vec<String>,
    /// The DNS port.
    pub dns_port: u16,
    /// The web interface port.
    pub http_port: u16,
    /// How long protection stays off, in milliseconds.
    pub protection_disabled_duration: i64,
    /// When the server started, in milliseconds since the epoch.
    pub start_time: f64,
    /// Whether protection is on.
    pub protection_enabled: bool,
    /// Whether a DHCP server exists to configure.
    ///
    /// Upstream sets this from whether it actually built one.  DHCP is
    /// excluded here, so it is always false: the interface gates its whole
    /// DHCP section on this field, and answering true sends it off to
    /// `/control/dhcp/status` and renders a settings page whose every save
    /// answers 501.
    pub dhcp_available: bool,
    /// Whether the server is past the setup wizard.
    pub running: bool,
}

/// Upstream's default HTTPS port, the one it leaves out of the DNS-over-HTTPS
/// address it reports.
const DEFAULT_PORT_HTTPS: u16 = 443;

/// The encrypted addresses `/control/status` reports alongside the plain ones.
///
/// Upstream's `getDNSAddresses` appends these to `dns_addresses`, and its web
/// interface builds the whole DNS privacy section by filtering that list by
/// scheme.  Reporting only the plain addresses -- which this build did -- tells
/// every such client that encryption is unconfigured on a server that is
/// serving DNS-over-TLS perfectly well.
///
/// Three details are Go's and are copied rather than tidied: nothing is
/// reported without a `server_name`, since there is no name to hand a client
/// that has to validate the certificate; the port is spelled out for
/// DNS-over-TLS and DNS-over-QUIC even when it is the default 853, but left off
/// HTTPS when it is 443; and this is derived from the settings rather than from
/// the running listeners, so a port changed through `/control/tls/configure`
/// is reported before the restart that moves the listener.
fn encrypted_addresses(cfg: &sift_config::model::Config) -> Vec<String> {
    let t = &cfg.tls;
    if !t.enabled || t.server_name.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();

    if t.port_https != 0 {
        let host = if t.port_https == DEFAULT_PORT_HTTPS {
            t.server_name.clone()
        } else {
            join_host_port(&t.server_name, t.port_https)
        };
        out.push(format!("https://{host}/dns-query"));
    }

    for (scheme, port) in [("tls", t.port_dns_over_tls), ("quic", t.port_dns_over_quic)] {
        if port != 0 {
            out.push(format!(
                "{scheme}://{}",
                join_host_port(&t.server_name, port)
            ));
        }
    }

    out
}

/// `host:port`, bracketing the host when it is an IPv6 literal.
///
/// Go reaches these addresses through `netutil.JoinHostPort`, which brackets;
/// a `server_name` is normally a hostname, but nothing stops it being an
/// address, and `::1:853` would parse as neither.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `GET /control/status`
pub async fn status(State(s): State<Shared>) -> Json<StatusResp> {
    let cfg = s.config.read();

    let mut dns_addresses = s.dns_addresses.read().clone();
    dns_addresses.extend(encrypted_addresses(&cfg));

    Json(StatusResp {
        version: sift_core::VERSION.to_string(),
        language: cfg.language.clone(),
        dns_addresses,
        dns_port: cfg.dns.port,
        http_port: cfg.http.address.0.port(),
        protection_disabled_duration: s.protection_pause_left(),
        start_time: sift_core::gotime::unix_millis_f64(s.started),
        protection_enabled: cfg.filtering.protection_enabled,
        dhcp_available: false,
        running: !cfg.users.is_empty(),
    })
}

/// The `/control/dns_info` response and the `/control/dns_config` request.
#[derive(Serialize, Deserialize, Default)]
pub struct DnsConfigJson {
    /// Upstream resolvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_dns: Option<Vec<String>>,
    /// The file to read extra upstreams from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_dns_file: Option<String>,
    /// Bootstrap resolvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_dns: Option<Vec<String>>,
    /// Fallback resolvers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_dns: Option<Vec<String>>,
    /// Whether protection is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection_enabled: Option<bool>,
    /// Queries per second per client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratelimit: Option<u32>,
    /// IPv4 prefix used for rate-limit grouping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratelimit_subnet_len_ipv4: Option<u8>,
    /// IPv6 prefix used for rate-limit grouping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratelimit_subnet_len_ipv6: Option<u8>,
    /// How long to wait for an upstream, in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_timeout: Option<u64>,
    /// Clients exempt from rate limiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratelimit_whitelist: Option<Vec<String>>,
    /// How blocked queries are answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_mode: Option<String>,
    /// Whether EDNS Client Subnet is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edns_cs_enabled: Option<bool>,
    /// Whether a custom ECS address is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edns_cs_use_custom: Option<bool>,
    /// Whether DNSSEC is requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dnssec_enabled: Option<bool>,
    /// Whether `AAAA` answers are dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_ipv6: Option<bool>,
    /// How upstreams are selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_mode: Option<String>,
    /// The TTL of blocked responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_response_ttl: Option<u32>,
    /// The cache size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_size: Option<u32>,
    /// The lower TTL bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_min: Option<u32>,
    /// The upper TTL bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_ttl_max: Option<u32>,
    /// Whether the cache is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_enabled: Option<bool>,
    /// Whether stale entries may be served while refreshing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_optimistic: Option<bool>,
    /// Whether clients are resolved by reverse DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve_clients: Option<bool>,
    /// Whether private reverse DNS resolvers are used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_private_ptr_resolvers: Option<bool>,
    /// Resolvers used for private reverse DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ptr_upstreams: Option<Vec<String>>,
    /// The IPv4 address used in custom-IP blocking mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ipv4: Option<String>,
    /// The IPv6 address used in custom-IP blocking mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocking_ipv6: Option<String>,
    /// When protection re-enables itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protection_disabled_until: Option<serde_json::Value>,
    /// The custom ECS address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edns_cs_custom_ip: Option<String>,
    /// The OS-provided resolvers, for the UI's placeholder text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_local_ptr_upstreams: Option<Vec<String>>,
}

/// `GET /control/dns_info`
pub async fn dns_info(State(s): State<Shared>) -> Json<DnsConfigJson> {
    let cfg = s.config.read();
    let d = &cfg.dns;

    Json(DnsConfigJson {
        upstream_dns: Some(d.upstream_dns.clone()),
        upstream_dns_file: Some(d.upstream_dns_file.clone()),
        bootstrap_dns: Some(d.bootstrap_dns.clone()),
        fallback_dns: Some(d.fallback_dns.clone()),
        protection_enabled: Some(cfg.filtering.protection_enabled),
        ratelimit: Some(d.ratelimit),
        ratelimit_subnet_len_ipv4: Some(d.ratelimit_subnet_len_ipv4),
        ratelimit_subnet_len_ipv6: Some(d.ratelimit_subnet_len_ipv6),
        upstream_timeout: Some(d.upstream_timeout.as_secs() as u64),
        ratelimit_whitelist: Some(
            d.ratelimit_whitelist
                .iter()
                .map(|i| i.to_string())
                .collect(),
        ),
        blocking_mode: Some(blocking_mode_str(cfg.filtering.blocking_mode).to_string()),
        edns_cs_enabled: Some(d.edns_client_subnet.enabled),
        edns_cs_use_custom: Some(d.edns_client_subnet.use_custom),
        dnssec_enabled: Some(d.enable_dnssec),
        disable_ipv6: Some(d.aaaa_disabled),
        upstream_mode: Some(d.upstream_mode.api_str().to_string()),
        blocked_response_ttl: Some(cfg.filtering.blocked_response_ttl),
        cache_size: Some(d.cache_size),
        cache_ttl_min: Some(d.cache_ttl_min),
        cache_ttl_max: Some(d.cache_ttl_max),
        cache_enabled: Some(d.cache_enabled),
        cache_optimistic: Some(d.cache_optimistic),
        resolve_clients: Some(cfg.clients.runtime_sources.rdns),
        use_private_ptr_resolvers: Some(d.use_private_ptr_resolvers),
        local_ptr_upstreams: Some(d.local_ptr_upstreams.clone()),
        blocking_ipv4: Some(cfg.filtering.blocking_ipv4.to_string()),
        blocking_ipv6: Some(cfg.filtering.blocking_ipv6.to_string()),
        protection_disabled_until: Some(match &cfg.filtering.protection_disabled_until {
            Some(t) => serde_json::Value::String(t.clone()),
            None => serde_json::Value::Null,
        }),
        edns_cs_custom_ip: Some(d.edns_client_subnet.custom_ip.to_string()),
        default_local_ptr_upstreams: Some(Vec::new()),
    })
}

/// Maps a blocking mode onto its API name.
fn blocking_mode_str(m: sift_config::model::BlockingMode) -> &'static str {
    use sift_config::model::BlockingMode as B;

    match m {
        B::Default => "default",
        B::CustomIp => "custom_ip",
        B::Nxdomain => "nxdomain",
        B::NullIp => "null_ip",
        B::Refused => "refused",
    }
}

/// Parses a blocking mode from its API name.
fn blocking_mode_from(s: &str) -> Option<sift_config::model::BlockingMode> {
    use sift_config::model::BlockingMode as B;

    Some(match s {
        "default" => B::Default,
        "custom_ip" => B::CustomIp,
        "nxdomain" => B::Nxdomain,
        "null_ip" => B::NullIp,
        "refused" => B::Refused,
        _ => return None,
    })
}

/// `POST /control/dns_config`
pub async fn set_dns_config(
    State(s): State<Shared>,
    Json(req): Json<DnsConfigJson>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();

        if let Some(v) = req.upstream_dns {
            validate_upstreams(&v)?;
            cfg.dns.upstream_dns = v;
        }
        if let Some(v) = req.bootstrap_dns {
            cfg.dns.bootstrap_dns = v;
        }
        if let Some(v) = req.fallback_dns {
            validate_upstreams(&v)?;
            cfg.dns.fallback_dns = v;
        }
        if let Some(v) = req.upstream_dns_file {
            cfg.dns.upstream_dns_file = v;
        }
        if let Some(v) = req.protection_enabled {
            cfg.filtering.protection_enabled = v;
        }
        if let Some(v) = req.ratelimit {
            cfg.dns.ratelimit = v;
        }
        if let Some(v) = req.ratelimit_subnet_len_ipv4 {
            cfg.dns.ratelimit_subnet_len_ipv4 = v;
        }
        if let Some(v) = req.ratelimit_subnet_len_ipv6 {
            cfg.dns.ratelimit_subnet_len_ipv6 = v;
        }
        if let Some(v) = req.upstream_timeout {
            cfg.dns.upstream_timeout = sift_core::GoDuration::from_secs(v as i64);
        }
        if let Some(v) = req.ratelimit_whitelist {
            cfg.dns.ratelimit_whitelist = v.iter().filter_map(|s| s.parse().ok()).collect();
        }
        if let Some(v) = req.blocking_mode {
            cfg.filtering.blocking_mode = blocking_mode_from(&v)
                .ok_or_else(|| ApiError::bad_request(format!("unknown blocking mode {v:?}")))?;
        }
        if let Some(v) = req.edns_cs_enabled {
            cfg.dns.edns_client_subnet.enabled = v;
        }
        if let Some(v) = req.edns_cs_use_custom {
            cfg.dns.edns_client_subnet.use_custom = v;
        }
        if let Some(v) = req.edns_cs_custom_ip {
            cfg.dns.edns_client_subnet.custom_ip = sift_config::types::OptAddr(v.parse().ok());
        }
        if let Some(v) = req.dnssec_enabled {
            cfg.dns.enable_dnssec = v;
        }
        if let Some(v) = req.disable_ipv6 {
            cfg.dns.aaaa_disabled = v;
        }
        if let Some(v) = req.upstream_mode {
            cfg.dns.upstream_mode = UpstreamMode::from_api_str(&v)
                .ok_or_else(|| ApiError::bad_request(format!("unknown upstream mode {v:?}")))?;
        }
        if let Some(v) = req.blocked_response_ttl {
            cfg.filtering.blocked_response_ttl = v;
        }
        if let Some(v) = req.cache_size {
            cfg.dns.cache_size = v;
        }
        if let Some(v) = req.cache_ttl_min {
            cfg.dns.cache_ttl_min = v;
        }
        if let Some(v) = req.cache_ttl_max {
            cfg.dns.cache_ttl_max = v;
        }
        if cfg.dns.cache_ttl_max > 0 && cfg.dns.cache_ttl_min > cfg.dns.cache_ttl_max {
            return Err(ApiError::bad_request(
                "cache_ttl_min must not exceed cache_ttl_max",
            ));
        }
        if let Some(v) = req.cache_enabled {
            cfg.dns.cache_enabled = v;
        }
        if let Some(v) = req.cache_optimistic {
            cfg.dns.cache_optimistic = v;
        }
        if let Some(v) = req.resolve_clients {
            cfg.clients.runtime_sources.rdns = v;
        }
        if let Some(v) = req.use_private_ptr_resolvers {
            cfg.dns.use_private_ptr_resolvers = v;
        }
        if let Some(v) = req.local_ptr_upstreams {
            cfg.dns.local_ptr_upstreams = v;
        }
        if let Some(v) = req.blocking_ipv4 {
            cfg.filtering.blocking_ipv4 = sift_config::types::OptAddr(v.parse().ok());
        }
        if let Some(v) = req.blocking_ipv6 {
            cfg.filtering.blocking_ipv6 = sift_config::types::OptAddr(v.parse().ok());
        }
    }

    s.save_config().map_err(ApiError::internal)
}

/// Rejects upstream specifications the DNS layer could not use.
fn validate_upstreams(v: &[String]) -> ApiResult<()> {
    for line in v {
        if let Err(e) = sift_dns::addr::parse(line)
            && !matches!(e, sift_dns::addr::ParseError::Empty)
        {
            return Err(ApiError::bad_request(format!(
                "invalid upstream {line:?}: {e}"
            )));
        }
    }

    Ok(())
}

/// The `/control/protection` request.
/// Every field defaults: Go's `encoding/json` leaves a field the caller
/// omitted at its zero value rather than failing, so a partial body that
/// upstream answers 200 must not become a 422 here.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ProtectionReq {
    /// Whether protection should be on.
    pub enabled: bool,
    /// How long to keep it off, in milliseconds.
    #[serde(default)]
    pub duration: Option<u64>,
}

/// `POST /control/protection`
pub async fn set_protection(
    State(s): State<Shared>,
    Json(req): Json<ProtectionReq>,
) -> ApiResult<()> {
    {
        let mut cfg = s.config.write();
        cfg.filtering.protection_enabled = req.enabled;

        // A deadline, not a countdown, so the pause means the same thing
        // across a restart.  Turning protection on -- or off with no duration
        // -- clears it: "off until I say otherwise" has no deadline, and
        // leaving a stale one behind would turn protection back on by itself.
        cfg.filtering.protection_disabled_until =
            crate::state::pause_deadline(req.enabled, req.duration, jiff::Timestamp::now());
    }

    s.save_config().map_err(ApiError::internal)
}

/// `POST /control/cache_clear`
pub async fn cache_clear(State(s): State<Shared>) -> ApiResult<()> {
    s.resolver.cache.clear();

    Ok(())
}

/// How long an announcement is reused before it is fetched again.
///
/// Upstream's interval: the interface asks on every page load, and the
/// announcement server should not hear about each one.
const VERSION_CHECK_PERIOD: std::time::Duration = std::time::Duration::from_secs(8 * 60 * 60);

/// The body `POST /control/version.json` may carry.
#[derive(Deserialize, Default)]
pub struct VersionReq {
    /// Whether to fetch now rather than reuse the cached announcement.
    #[serde(default)]
    pub recheck_now: bool,
}

/// The highest port number that needs privileges to bind.
const MAX_PRIVILEGED_PORT: u16 = 1024;

/// Reports whether the running configuration binds a privileged port.
///
/// Upstream's `setAllowedToAutoUpdate` asks the same question, for the same
/// reason: a process that cannot bind port 53 after a restart must not be
/// offered a button that restarts it.
pub fn needs_privileged_ports(cfg: &sift_config::Config) -> bool {
    let low = |p: u16| p < MAX_PRIVILEGED_PORT;

    low(cfg.dns.port)
        || low(cfg.http.address.0.port())
        || (cfg.tls.enabled
            && (low(cfg.tls.port_https)
                || low(cfg.tls.port_dns_over_tls)
                || low(cfg.tls.port_dns_over_quic)))
}

/// `GET /control/version.json` and `POST /control/version.json`
///
/// `can_autoupdate` is answered by the binary, which is the only part that
/// knows whether it can write over itself here: it is false inside a
/// container, false when the executable's directory is read-only, and false
/// when a restart could not bind the ports this configuration uses.
pub async fn version(
    State(s): State<Shared>,
    body: Option<Json<VersionReq>>,
) -> Json<serde_json::Value> {
    if s.version.disabled() {
        return Json(json!({ "disabled": true }));
    }

    let recheck = body.map(|Json(b)| b.recheck_now).unwrap_or(false);

    if !recheck
        && let Some((at, cached)) = s.version_cache.read().clone()
        && jiff::Timestamp::now().duration_since(at).unsigned_abs() < VERSION_CHECK_PERIOD
    {
        return Json(cached);
    }

    let fetched = s.version.fetch().await.ok().and_then(parse_version);
    let Some(mut info) = fetched else {
        // Upstream answers 502 here; reporting the running version keeps the
        // interface usable when the announcement server is unreachable, and
        // reads as "nothing newer" rather than as an update banner.
        return Json(json!({
            "new_version": sift_core::VERSION,
            "can_autoupdate": false,
            "disabled": false,
        }));
    };

    // The interface reads `can_autoupdate` as "offer the button", so it is
    // only ever true for a release worth pressing it for.
    let can = pending_update(Some(&info)).is_some()
        && s.updater
            .can_update(needs_privileged_ports(&s.config.read()));
    info["can_autoupdate"] = json!(can);

    *s.version_cache.write() = Some((jiff::Timestamp::now(), info.clone()));

    Json(info)
}

/// The release to install, if the last check found one worth installing.
///
/// Split out from the handler because it is the guard that keeps this
/// endpoint from installing whatever a caller asks for: the only version it
/// will ever install is the one the announcement named, and only when that is
/// strictly newer than the one running.
pub fn pending_update(cached: Option<&serde_json::Value>) -> Option<String> {
    cached?
        .get("new_version")
        .and_then(serde_json::Value::as_str)
        .filter(|v| is_newer(v, sift_core::VERSION))
        .map(str::to_string)
}

/// Reports whether `candidate` is a later release than `running`.
///
/// Simple inequality is not enough once there is a button behind this: the
/// announcement is whatever the newest *published* release is, so a build
/// running ahead of it -- anything built from `main` -- would be offered a
/// downgrade, and would take it.  A version this cannot read is not newer,
/// because the safe answer to "should this replace itself" is no.
pub fn is_newer(candidate: &str, running: &str) -> bool {
    let parts = |v: &str| -> Option<(u64, u64, u64)> {
        let v = v.trim().trim_start_matches('v');
        // A pre-release or build suffix is ignored rather than ordered; the
        // releases this reads are plain `vX.Y.Z`.
        let v = v.split(['-', '+']).next().unwrap_or("");
        let mut it = v.split('.');
        let mut next = || it.next()?.parse::<u64>().ok();

        Some((next()?, next()?, next()?))
    };

    match (parts(candidate), parts(running)) {
        (Some(c), Some(r)) => c > r,
        _ => false,
    }
}

/// How long the response is given to reach the browser before this process
/// hands itself over to the new binary.
///
/// Upstream flushes the response and restarts from a goroutine.  The same
/// thing is done here with a pause instead of a flush, because the restart
/// replaces the process image and there is nothing left afterwards to notice
/// that the write had not finished.
const RESTART_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// `POST /control/update`
///
/// Downloads the release `/control/version.json` last reported, checks it,
/// puts it in place of the running binary, and restarts into it.  What is
/// replaced is only the binary: the config file and the data directory are
/// read by the new one exactly where they are, and the previous binary and a
/// copy of the config are left in `<work>/agh-backup`.
pub async fn update(State(s): State<Shared>) -> ApiResult<Json<serde_json::Value>> {
    // Upstream refuses unless a check has already found something newer: the
    // button is the end of that conversation rather than the start of one.
    let cached = s.version_cache.read().clone().map(|(_, v)| v);

    let Some(version) = pending_update(cached.as_ref()) else {
        return Err(ApiError::bad_request(
            "no newer release has been found; check for one first",
        ));
    };

    if !s
        .updater
        .can_update(needs_privileged_ports(&s.config.read()))
    {
        return Err(ApiError::bad_request(
            "this installation cannot replace its own binary;              update the image, or run the installer",
        ));
    }

    s.updater
        .update(version.clone())
        .await
        .map_err(ApiError::internal)?;

    let updater = s.updater.clone();
    tokio::spawn(async move {
        tokio::time::sleep(RESTART_DELAY).await;

        // Only returns if the hand-over failed, in which case this process is
        // running a binary that is no longer on disk.  Exiting is what gets a
        // supervised service back onto the new one.
        let err = updater.restart();
        tracing::error!(error = %err, "restarting into the new binary");

        std::process::exit(1);
    });

    Ok(Json(json!({ "new_version": version })))
}

/// Parses the announcement document into the API's response shape.
///
/// Two documents are accepted, because both are announcements of a release and
/// an operator may prefer either.  GitHub's `releases/latest` names the version
/// `tag_name` and the page `html_url`; the flat document AdGuard Home's own
/// announcement server serves names them `version` and `announcement_url`.
/// Whichever field is present wins, so pointing the checker at a hand-written
/// `version.json` keeps working.
pub fn parse_version(body: String) -> Option<serde_json::Value> {
    let doc: serde_json::Value = serde_json::from_str(&body).ok()?;
    let field = |k: &str| doc.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let first = |keys: &[&str]| {
        keys.iter()
            .map(|k| field(k))
            .find(|v| !v.is_empty())
            .unwrap_or("")
            .to_string()
    };

    let new_version = first(&["version", "tag_name"]);
    if new_version.is_empty() {
        return None;
    }

    Some(json!({
        "new_version": new_version,
        "announcement": first(&["announcement", "name"]),
        "announcement_url": first(&["announcement_url", "html_url"]),
        // The announcement does not know whether this machine can replace
        // its binary; `version` decides that and overwrites this.
        "can_autoupdate": false,
        "disabled": false,
    }))
}

/// The `/control/test_upstream_dns` request.
#[derive(Deserialize)]
pub struct TestUpstreamReq {
    /// The upstreams to test.
    #[serde(default)]
    pub upstream_dns: Vec<String>,
    /// Bootstrap resolvers to use for the test.
    #[serde(default)]
    pub bootstrap_dns: Vec<String>,
    /// Fallback resolvers to test as well.
    #[serde(default)]
    pub fallback_dns: Vec<String>,
    /// Private reverse DNS resolvers to test as well.
    #[serde(default)]
    pub private_upstream: Vec<String>,
}

/// `POST /control/test_upstream_dns`
///
/// Answers with one entry per upstream: `"OK"` when it resolved a probe
/// query, otherwise the reason it failed.
pub async fn test_upstream(
    State(s): State<Shared>,
    Json(req): Json<TestUpstreamReq>,
) -> Json<serde_json::Map<String, serde_json::Value>> {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    let timeout = s.config.read().dns.upstream_timeout.to_std();
    let bootstrap: Vec<std::net::SocketAddr> = req
        .bootstrap_dns
        .iter()
        .filter_map(|b| {
            let e = sift_dns::addr::parse(b).ok()?;
            let u = e.upstream?;
            let ip: std::net::IpAddr = u.host.parse().ok()?;

            Some(std::net::SocketAddr::new(ip, u.port))
        })
        .collect();

    let tls = sift_dns::client::tls_config();
    let mut out = serde_json::Map::new();

    let all = req
        .upstream_dns
        .iter()
        .chain(&req.fallback_dns)
        .chain(&req.private_upstream);

    for spec in all {
        let result = match sift_dns::addr::parse(spec) {
            Err(e) => format!("invalid upstream: {e}"),
            Ok(entry) => match entry.upstream {
                // The `#` form defers to the defaults; nothing to test.
                None => "OK".to_string(),
                Some(u) => {
                    match sift_dns::client::Client::connect(
                        u,
                        &bootstrap,
                        timeout,
                        false,
                        tls.clone(),
                    )
                    .await
                    {
                        Err(e) => e.to_string(),
                        Ok(c) => {
                            let mut probe = Message::query();
                            probe.metadata.id = rand::random();
                            probe.metadata.recursion_desired = true;
                            probe.add_query(Query::query(
                                Name::from_utf8("www.google.com.").expect("static name"),
                                RecordType::A,
                            ));

                            match c.exchange(&probe, timeout).await {
                                Ok(_) => "OK".to_string(),
                                Err(e) => e.to_string(),
                            }
                        }
                    }
                }
            },
        };

        out.insert(spec.clone(), serde_json::Value::String(result));
    }

    Json(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocking_modes_round_trip_through_their_api_names() {
        use sift_config::model::BlockingMode as B;

        for m in [B::Default, B::CustomIp, B::Nxdomain, B::NullIp, B::Refused] {
            assert_eq!(blocking_mode_from(blocking_mode_str(m)), Some(m));
        }
        assert_eq!(blocking_mode_from("nonsense"), None);
    }

    #[test]
    fn upstream_validation_accepts_the_default_config() {
        assert!(
            validate_upstreams(&[
                "https://dns10.quad9.net/dns-query".into(),
                "[/example.com/]1.1.1.1".into(),
                "[/example.com/]#".into(),
                "# a comment".into(),
            ])
            .is_ok()
        );
    }

    #[test]
    fn upstream_validation_rejects_nonsense() {
        assert!(validate_upstreams(&["ftp://example.com".into()]).is_err());
    }

    #[test]
    fn a_privileged_port_is_one_below_1024() {
        let mut c = sift_config::Config::default();
        c.dns.port = 5353;
        c.http.address = sift_config::types::AddrPort("127.0.0.1:3000".parse().unwrap());
        c.tls.enabled = false;
        c.tls.port_https = 443;

        assert!(!needs_privileged_ports(&c), "nothing privileged is bound");

        c.dns.port = 53;
        assert!(needs_privileged_ports(&c), "the DNS port");

        c.dns.port = 5353;
        c.http.address = sift_config::types::AddrPort("127.0.0.1:80".parse().unwrap());
        assert!(needs_privileged_ports(&c), "the web interface port");

        c.http.address = sift_config::types::AddrPort("127.0.0.1:3000".parse().unwrap());
        assert!(
            !needs_privileged_ports(&c),
            "an encrypted port that is not served does not count"
        );

        c.tls.enabled = true;
        assert!(needs_privileged_ports(&c), "and does once it is");
    }

    #[test]
    fn only_a_strictly_newer_release_is_installed() {
        // The endpoint takes no version from the caller: it installs what the
        // announcement named, and only when that is later than this build.
        assert_eq!(pending_update(None), None);
        assert_eq!(pending_update(Some(&json!({}))), None);
        assert_eq!(pending_update(Some(&json!({ "new_version": "" }))), None);
        assert_eq!(
            pending_update(Some(&json!({ "new_version": sift_core::VERSION }))),
            None,
            "the running version is not an update"
        );
        assert_eq!(
            pending_update(Some(&json!({ "new_version": "v0.0.1" }))),
            None,
            "an older release is not an update"
        );
        assert_eq!(
            pending_update(Some(&json!({ "new_version": "v9.9.9" }))).as_deref(),
            Some("v9.9.9")
        );
    }

    #[test]
    fn a_build_running_ahead_of_the_newest_release_is_not_downgraded() {
        // Every build from `main` is ahead of the newest published release,
        // and the announcement is that release.  Inequality alone would offer
        // it, and the button would take it.
        assert!(is_newer("v0.5.1", "v0.5.0"));
        assert!(is_newer("v0.6.0", "v0.5.9"));
        assert!(is_newer("v1.0.0", "v0.99.99"));
        assert!(!is_newer("v0.5.0", "v0.5.0"));
        assert!(!is_newer("v0.4.9", "v0.5.0"));
        assert!(!is_newer("v0.5.0", "v0.5.1"));

        // A suffix is ignored rather than ordered.
        assert!(is_newer("v0.6.0-rc1", "v0.5.0"));
        assert!(!is_newer("v0.5.0-rc1", "v0.5.0"));

        // Anything unreadable is not newer, in either position.
        assert!(!is_newer("latest", "v0.5.0"));
        assert!(!is_newer("v0.5", "v0.5.0"));
        assert!(!is_newer("", "v0.5.0"));
        assert!(!is_newer("v9.9.9", "nightly"));
    }

    #[test]
    fn a_github_release_is_read_as_an_announcement() {
        // Trimmed from what api.github.com/repos/.../releases/latest answers.
        let body = r#"{
            "tag_name": "v0.3.0",
            "name": "Sift v0.3.0",
            "html_url": "https://github.com/openhoangnc/sift/releases/tag/v0.3.0",
            "draft": false
        }"#;

        let got = parse_version(body.to_string()).expect("a release parses");
        assert_eq!(got["new_version"], "v0.3.0");
        assert_eq!(got["announcement"], "Sift v0.3.0");
        assert_eq!(
            got["announcement_url"],
            "https://github.com/openhoangnc/sift/releases/tag/v0.3.0"
        );
        assert_eq!(got["can_autoupdate"], false);
        assert_eq!(got["disabled"], false);
    }

    #[test]
    fn the_flat_announcement_document_still_parses() {
        // The shape AdGuard Home's own announcement server serves, so an
        // operator pointing the checker at a hand-written file keeps working.
        let body = r#"{
            "version": "v0.9.9",
            "announcement": "v0.9.9 is out",
            "announcement_url": "https://example.org/notes"
        }"#;

        let got = parse_version(body.to_string()).expect("a version.json parses");
        assert_eq!(got["new_version"], "v0.9.9");
        assert_eq!(got["announcement"], "v0.9.9 is out");
        assert_eq!(got["announcement_url"], "https://example.org/notes");
    }

    #[test]
    fn a_document_naming_no_version_is_not_an_announcement() {
        // GitHub answers this when a repository has published no release yet.
        assert!(parse_version(r#"{"message":"Not Found"}"#.to_string()).is_none());
        assert!(parse_version("not json".to_string()).is_none());
    }

    /// A config with encryption on, a name, and the default ports.
    fn encrypted_config() -> sift_config::model::Config {
        let mut cfg = sift_config::model::Config::default();
        cfg.tls.enabled = true;
        cfg.tls.server_name = "dns.example.org".to_string();
        cfg
    }

    #[test]
    fn status_reports_the_encrypted_addresses_go_reports() {
        // What `getDNSAddresses` builds from the same settings: HTTPS without
        // its default port, DoT and DoQ with theirs.
        assert_eq!(
            encrypted_addresses(&encrypted_config()),
            [
                "https://dns.example.org/dns-query",
                "tls://dns.example.org:853",
                "quic://dns.example.org:853",
            ]
        );
    }

    #[test]
    fn a_moved_https_port_is_named_in_the_address() {
        let mut cfg = encrypted_config();
        cfg.tls.port_https = 8443;

        assert_eq!(
            encrypted_addresses(&cfg)[0],
            "https://dns.example.org:8443/dns-query"
        );
    }

    #[test]
    fn a_port_left_at_zero_is_not_listened_on_and_not_reported() {
        let mut cfg = encrypted_config();
        cfg.tls.port_https = 0;
        cfg.tls.port_dns_over_quic = 0;

        assert_eq!(encrypted_addresses(&cfg), ["tls://dns.example.org:853"]);
    }

    #[test]
    fn nothing_is_reported_without_encryption_or_a_server_name() {
        let mut off = encrypted_config();
        off.tls.enabled = false;
        assert!(encrypted_addresses(&off).is_empty());

        // The listeners still run without a name -- they serve whatever the
        // certificate covers -- but there is no name to report them under.
        let mut nameless = encrypted_config();
        nameless.tls.server_name = String::new();
        assert!(encrypted_addresses(&nameless).is_empty());

        assert!(encrypted_addresses(&sift_config::model::Config::default()).is_empty());
    }

    #[test]
    fn an_ipv6_server_name_is_bracketed_in_its_address() {
        let mut cfg = encrypted_config();
        cfg.tls.server_name = "2001:db8::1".to_string();

        assert_eq!(encrypted_addresses(&cfg)[1], "tls://[2001:db8::1]:853");
    }
}
