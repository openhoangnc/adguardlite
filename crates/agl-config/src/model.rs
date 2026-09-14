//! The `AdGuardHome.yaml` document model for schema version 34.
//!
//! Field declaration order **is** the emitted YAML key order, and upstream
//! treats that order as part of the file format.  Do not reorder fields; add
//! new ones where upstream puts them.

use std::net::IpAddr;

use agl_core::{ByteSize, GoDuration};
use serde::{Deserialize, Serialize};

use crate::types::{AddrPort, OptAddr, Prefix};

/// The whole configuration document.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Web interface settings.
    pub http: HttpConfig,
    /// Users allowed to access the web interface.
    pub users: Vec<WebUser>,
    /// Failed login attempts before a block kicks in.
    pub auth_attempts: u32,
    /// Length of the login block, in minutes.
    pub block_auth_min: u32,
    /// Proxy for the internal HTTP client.
    pub http_proxy: String,
    /// Two-letter ISO 639-1 UI language code.
    pub language: String,
    /// UI theme.
    pub theme: Theme,
    /// DNS server settings.
    pub dns: DnsConfig,
    /// Encryption settings.
    pub tls: TlsConfig,
    /// Query log settings.
    pub querylog: QueryLogConfig,
    /// Statistics settings.
    pub statistics: StatsConfig,
    /// Blocklists.
    pub filters: Vec<FilterYaml>,
    /// Allowlists.
    pub whitelist_filters: Vec<FilterYaml>,
    /// Custom filtering rules.
    pub user_rules: Vec<String>,
    /// DHCP server settings.
    ///
    /// This build serves no DHCP; the section is kept because the file must
    /// round-trip byte for byte, and because a user switching back to the Go
    /// build would otherwise lose their settings.  Do not remove it.
    pub dhcp: DhcpConfig,
    /// Filtering engine settings.
    pub filtering: FilteringConfig,
    /// Client settings.
    pub clients: ClientsConfig,
    /// Logging settings.
    pub log: LogConfig,
    /// OS-level settings.
    pub os: OsConfig,
    /// The schema version of this document.
    pub schema_version: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http: HttpConfig::default(),
            users: Vec::new(),
            auth_attempts: 5,
            block_auth_min: 15,
            http_proxy: String::new(),
            language: String::new(),
            theme: Theme::Auto,
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
            querylog: QueryLogConfig::default(),
            statistics: StatsConfig::default(),
            filters: FilterYaml::defaults(),
            whitelist_filters: Vec::new(),
            user_rules: Vec::new(),
            dhcp: DhcpConfig::default(),
            filtering: FilteringConfig::default(),
            clients: ClientsConfig::default(),
            log: LogConfig::default(),
            os: OsConfig::default(),
            schema_version: agl_core::SCHEMA_VERSION,
        }
    }
}

/// The UI theme.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Follow the system preference.
    #[default]
    Auto,
    /// Always dark.
    Dark,
    /// Always light.
    Light,
}

/// Web interface settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Profiling handler settings.
    pub pprof: PprofConfig,
    /// DNS-over-HTTPS settings.
    pub doh: DohConfig,
    /// Address the web UI listens on.
    pub address: AddrPort,
    /// Lifetime of a web session.
    pub session_ttl: GoDuration,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            pprof: PprofConfig::default(),
            doh: DohConfig::default(),
            address: AddrPort::default(),
            session_ttl: GoDuration::from_days(30),
        }
    }
}

/// Profiling handler settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PprofConfig {
    /// Port the profiling handler listens on.
    pub port: u16,
    /// Whether the profiling handler is enabled.
    pub enabled: bool,
}

impl Default for PprofConfig {
    fn default() -> Self {
        Self {
            port: 6060,
            enabled: false,
        }
    }
}

/// DNS-over-HTTPS routing settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DohConfig {
    /// HTTP route patterns that accept DoH requests.
    pub routes: Vec<String>,
    /// Whether DoH is served over plain HTTP too.
    pub insecure_enabled: bool,
}

impl Default for DohConfig {
    fn default() -> Self {
        Self {
            routes: vec![
                "GET /dns-query".into(),
                "POST /dns-query".into(),
                "GET /dns-query/{ClientID}".into(),
                "POST /dns-query/{ClientID}".into(),
            ],
            insecure_enabled: false,
        }
    }
}

/// A web interface user.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebUser {
    /// The login name.
    pub name: String,
    /// The bcrypt hash of the password.
    pub password: String,
}

/// DNS server settings.
///
/// This flattens Go's embedded `dnsforward.Config` so the key order matches
/// the file exactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Addresses the DNS server listens on.
    pub bind_hosts: Vec<IpAddr>,
    /// Port the DNS server listens on.
    pub port: u16,
    /// Whether to anonymise client IPs in the log and statistics.
    pub anonymize_client_ip: bool,
    /// Queries per second allowed per client, or 0 for unlimited.
    pub ratelimit: u32,
    /// IPv4 subnet size used for rate-limit grouping.
    pub ratelimit_subnet_len_ipv4: u8,
    /// IPv6 subnet size used for rate-limit grouping.
    pub ratelimit_subnet_len_ipv6: u8,
    /// Clients exempt from rate limiting.
    pub ratelimit_whitelist: Vec<IpAddr>,
    /// Whether to refuse `ANY` queries.
    pub refuse_any: bool,
    /// Upstream resolvers.
    pub upstream_dns: Vec<String>,
    /// File to read additional upstream resolvers from.
    pub upstream_dns_file: String,
    /// Resolvers used to bootstrap encrypted upstreams.
    pub bootstrap_dns: Vec<String>,
    /// Resolvers used when the main upstreams fail.
    pub fallback_dns: Vec<String>,
    /// How upstreams are selected.
    pub upstream_mode: UpstreamMode,
    /// How long to wait when probing for the fastest address.
    pub fastest_timeout: GoDuration,
    /// Clients allowed to query, as an allowlist.
    pub allowed_clients: Vec<String>,
    /// Clients forbidden from querying.
    pub disallowed_clients: Vec<String>,
    /// Hosts answered with `NXDOMAIN` outright.
    pub blocked_hosts: Vec<String>,
    /// Networks whose `X-Forwarded-For` headers are honoured.
    pub trusted_proxies: Vec<Prefix>,
    /// Whether the DNS cache is on.
    pub cache_enabled: bool,
    /// Cache size in bytes.
    pub cache_size: u32,
    /// Lower bound applied to cached TTLs.
    pub cache_ttl_min: u32,
    /// Upper bound applied to cached TTLs.
    pub cache_ttl_max: u32,
    /// Whether to serve stale entries while refreshing.
    pub cache_optimistic: bool,
    /// TTL given to optimistically served answers.
    pub cache_optimistic_answer_ttl: GoDuration,
    /// How long a stale entry may still be served.
    pub cache_optimistic_max_age: GoDuration,
    /// Addresses treated as a bogus `NXDOMAIN` response.
    pub bogus_nxdomain: Vec<String>,
    /// Whether to drop `AAAA` answers.
    pub aaaa_disabled: bool,
    /// Whether to request DNSSEC validation.
    pub enable_dnssec: bool,
    /// EDNS Client Subnet settings.
    pub edns_client_subnet: EdnsClientSubnet,
    /// Maximum number of concurrent upstream queries.
    pub max_goroutines: u32,
    /// Whether to answer Discovery of Designated Resolvers queries.
    pub handle_ddr: bool,
    /// ipset rules.
    pub ipset: Vec<String>,
    /// File to read ipset rules from.
    pub ipset_file: String,
    /// Whether bootstrap resolution prefers IPv6.
    pub bootstrap_prefer_ipv6: bool,
    /// How long to wait for an upstream reply.
    pub upstream_timeout: GoDuration,
    /// Networks considered private for reverse DNS.
    pub private_networks: Vec<Prefix>,
    /// Whether private reverse DNS resolvers are used.
    pub use_private_ptr_resolvers: bool,
    /// Resolvers used for private reverse DNS.
    pub local_ptr_upstreams: Vec<String>,
    /// Whether DNS64 synthesis is on.
    pub use_dns64: bool,
    /// NAT64 prefixes used for DNS64.
    pub dns64_prefixes: Vec<Prefix>,
    /// Whether HTTP/3 is accepted for incoming requests.
    pub serve_http3: bool,
    /// Whether HTTP/3 is used for DoH upstreams.
    pub use_http3_upstreams: bool,
    /// Whether plain DNS is served.
    pub serve_plain_dns: bool,
    /// Whether the system hosts file is consulted.
    pub hostsfile_enabled: bool,
    /// Duplicate-request handling.
    pub pending_requests: PendingRequests,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            bind_hosts: vec![IpAddr::from([0, 0, 0, 0])],
            port: 53,
            anonymize_client_ip: false,
            ratelimit: 20,
            ratelimit_subnet_len_ipv4: 24,
            ratelimit_subnet_len_ipv6: 56,
            ratelimit_whitelist: Vec::new(),
            refuse_any: true,
            upstream_dns: vec!["https://dns10.quad9.net/dns-query".into()],
            upstream_dns_file: String::new(),
            bootstrap_dns: vec![
                "9.9.9.10".into(),
                "149.112.112.10".into(),
                "2620:fe::10".into(),
                "2620:fe::fe:10".into(),
            ],
            fallback_dns: Vec::new(),
            upstream_mode: UpstreamMode::LoadBalance,
            fastest_timeout: GoDuration::from_secs(1),
            allowed_clients: Vec::new(),
            disallowed_clients: Vec::new(),
            blocked_hosts: vec![
                "version.bind".into(),
                "id.server".into(),
                "hostname.bind".into(),
            ],
            trusted_proxies: vec![
                "127.0.0.0/8".parse().expect("static prefix"),
                "::1/128".parse().expect("static prefix"),
            ],
            cache_enabled: true,
            cache_size: 4 * 1024 * 1024,
            cache_ttl_min: 0,
            cache_ttl_max: 0,
            cache_optimistic: false,
            cache_optimistic_answer_ttl: GoDuration::from_secs(30),
            cache_optimistic_max_age: GoDuration::from_hours(12),
            bogus_nxdomain: Vec::new(),
            aaaa_disabled: false,
            enable_dnssec: true,
            edns_client_subnet: EdnsClientSubnet::default(),
            max_goroutines: 300,
            handle_ddr: true,
            ipset: Vec::new(),
            ipset_file: String::new(),
            bootstrap_prefer_ipv6: false,
            upstream_timeout: GoDuration::from_secs(10),
            private_networks: Vec::new(),
            use_private_ptr_resolvers: true,
            local_ptr_upstreams: Vec::new(),
            use_dns64: false,
            dns64_prefixes: Vec::new(),
            serve_http3: false,
            use_http3_upstreams: false,
            serve_plain_dns: true,
            hostsfile_enabled: true,
            pending_requests: PendingRequests::default(),
        }
    }
}

/// How upstream resolvers are selected for a query.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamMode {
    /// Pick one upstream, weighted by recent latency.
    #[default]
    LoadBalance,
    /// Query all upstreams and take the first answer.
    Parallel,
    /// Query all upstreams and return the fastest-responding address.
    FastestAddr,
}

impl UpstreamMode {
    /// The value the HTTP API uses.  `load_balance` is reported as an empty
    /// string for backwards compatibility, as upstream does.
    pub const fn api_str(self) -> &'static str {
        match self {
            UpstreamMode::LoadBalance => "",
            UpstreamMode::Parallel => "parallel",
            UpstreamMode::FastestAddr => "fastest_addr",
        }
    }

    /// Parses the value the HTTP API accepts.
    pub fn from_api_str(s: &str) -> Option<Self> {
        Some(match s {
            "" | "load_balance" => UpstreamMode::LoadBalance,
            "parallel" => UpstreamMode::Parallel,
            "fastest_addr" => UpstreamMode::FastestAddr,
            _ => return None,
        })
    }
}

/// EDNS Client Subnet settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EdnsClientSubnet {
    /// The address sent when `use_custom` is set.
    pub custom_ip: OptAddr,
    /// Whether ECS is enabled at all.
    pub enabled: bool,
    /// Whether `custom_ip` is used instead of the client's address.
    pub use_custom: bool,
}

/// Duplicate-request handling.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PendingRequests {
    /// Whether duplicate in-flight requests are coalesced.
    pub enabled: bool,
}

impl Default for PendingRequests {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Encryption settings for DoH, DoT, DoQ and the HTTPS UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// Whether encryption is on.
    pub enabled: bool,
    /// The server's hostname.
    pub server_name: String,
    /// Whether plain HTTP redirects to HTTPS.
    pub force_https: bool,
    /// The HTTPS port, or 0 to disable.
    pub port_https: u16,
    /// The DNS-over-TLS port, or 0 to disable.
    pub port_dns_over_tls: u16,
    /// The DNS-over-QUIC port, or 0 to disable.
    pub port_dns_over_quic: u16,
    /// The DNSCrypt port, or 0 to disable.
    pub port_dnscrypt: u16,
    /// Path to the DNSCrypt configuration file.
    pub dnscrypt_config_file: String,
    /// The PEM-encoded certificate chain.
    pub certificate_chain: String,
    /// The PEM-encoded private key.
    pub private_key: String,
    /// Path to the certificate file.
    pub certificate_path: String,
    /// Path to the private key file.
    pub private_key_path: String,
    /// Cipher suites to use instead of the safe defaults.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub override_tls_ciphers: Vec<String>,
    /// Whether connections with a mismatched SNI are rejected.
    pub strict_sni_check: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: String::new(),
            force_https: false,
            port_https: 443,
            port_dns_over_tls: 853,
            port_dns_over_quic: 853,
            port_dnscrypt: 0,
            dnscrypt_config_file: String::new(),
            certificate_chain: String::new(),
            private_key: String::new(),
            certificate_path: String::new(),
            private_key_path: String::new(),
            override_tls_ciphers: Vec::new(),
            strict_sni_check: false,
        }
    }
}

/// Query log settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct QueryLogConfig {
    /// Directory the log is written to, or empty for the default.
    pub dir_path: String,
    /// Hosts excluded from the log.
    pub ignored: Vec<String>,
    /// Rotation interval.
    pub interval: GoDuration,
    /// Entries kept in memory before flushing.
    pub size_memory: u32,
    /// Whether the query log is on.
    pub enabled: bool,
    /// Whether `ignored` is honoured.
    pub ignored_enabled: bool,
    /// Whether the log is written to disk.
    pub file_enabled: bool,
}

impl Default for QueryLogConfig {
    fn default() -> Self {
        Self {
            dir_path: String::new(),
            ignored: Vec::new(),
            interval: GoDuration::from_days(90),
            size_memory: 1000,
            enabled: true,
            ignored_enabled: false,
            file_enabled: true,
        }
    }
}

/// Statistics settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StatsConfig {
    /// Directory the database is written to, or empty for the default.
    pub dir_path: String,
    /// Hosts excluded from statistics.
    pub ignored: Vec<String>,
    /// Retention interval.
    pub interval: GoDuration,
    /// Whether statistics are collected.
    pub enabled: bool,
    /// Whether `ignored` is honoured.
    pub ignored_enabled: bool,
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            dir_path: String::new(),
            ignored: Vec::new(),
            interval: GoDuration::from_days(1),
            enabled: true,
            ignored_enabled: false,
        }
    }
}

/// A filter list as stored in the configuration file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterYaml {
    /// Whether the list is applied.
    pub enabled: bool,
    /// The list's URL or file path.
    pub url: String,
    /// The list's display name.
    pub name: String,
    /// The list's identifier.
    pub id: i64,
}

impl FilterYaml {
    /// The blocklists a fresh installation starts with.
    pub fn defaults() -> Vec<Self> {
        vec![
            FilterYaml {
                enabled: true,
                url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt".into(),
                name: "AdGuard DNS filter".into(),
                id: 1,
            },
            FilterYaml {
                enabled: false,
                url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt".into(),
                name: "AdAway Default Blocklist".into(),
                id: 2,
            },
        ]
    }
}

/// DHCP server settings.
///
/// Read and written so the configuration file survives a round trip; nothing
/// in this build acts on them.  See the DHCP section of `TASK.md`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DhcpConfig {
    /// Whether the DHCP server runs.
    pub enabled: bool,
    /// The interface it serves on.
    pub interface_name: String,
    /// The domain suffix given to leases.
    pub local_domain_name: String,
    /// IPv4 settings.
    pub dhcpv4: Dhcpv4Config,
    /// IPv6 settings.
    pub dhcpv6: Dhcpv6Config,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_name: String::new(),
            local_domain_name: "lan".into(),
            dhcpv4: Dhcpv4Config::default(),
            dhcpv6: Dhcpv6Config::default(),
        }
    }
}

/// DHCPv4 settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Dhcpv4Config {
    /// The gateway handed to clients.
    pub gateway_ip: OptAddr,
    /// The subnet mask handed to clients.
    pub subnet_mask: OptAddr,
    /// The first address of the lease pool.
    pub range_start: OptAddr,
    /// The last address of the lease pool.
    pub range_end: OptAddr,
    /// Lease lifetime in seconds.
    pub lease_duration: u32,
    /// How long to wait for an ICMP echo when probing for conflicts.
    pub icmp_timeout_msec: u32,
    /// Extra DHCP options.
    pub options: Vec<String>,
}

impl Default for Dhcpv4Config {
    fn default() -> Self {
        Self {
            gateway_ip: OptAddr(None),
            subnet_mask: OptAddr(None),
            range_start: OptAddr(None),
            range_end: OptAddr(None),
            lease_duration: 86400,
            icmp_timeout_msec: 1000,
            options: Vec::new(),
        }
    }
}

/// DHCPv6 settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Dhcpv6Config {
    /// The first address of the lease pool.
    pub range_start: OptAddr,
    /// Lease lifetime in seconds.
    pub lease_duration: u32,
    /// Whether only SLAAC is advertised.
    pub ra_slaac_only: bool,
    /// Whether SLAAC is allowed alongside DHCPv6.
    pub ra_allow_slaac: bool,
}

impl Default for Dhcpv6Config {
    fn default() -> Self {
        Self {
            range_start: OptAddr(None),
            lease_duration: 86400,
            ra_slaac_only: false,
            ra_allow_slaac: false,
        }
    }
}

/// Filtering engine settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FilteringConfig {
    /// The IPv4 address returned in `custom_ip` blocking mode.
    pub blocking_ipv4: OptAddr,
    /// The IPv6 address returned in `custom_ip` blocking mode.
    pub blocking_ipv6: OptAddr,
    /// Blocked services and their schedule.
    pub blocked_services: BlockedServices,
    /// When protection re-enables itself, if it was paused.
    pub protection_disabled_until: Option<String>,
    /// Safe-search settings.
    pub safe_search: SafeSearchConfig,
    /// How blocked queries are answered.
    pub blocking_mode: BlockingMode,
    /// Host used for parental-control block pages.
    pub parental_block_host: String,
    /// Host used for safe-browsing block pages.
    pub safebrowsing_block_host: String,
    /// DNS rewrite rules.
    pub rewrites: Vec<Rewrite>,
    /// Glob patterns for filesystem paths lists may be loaded from.
    pub safe_fs_patterns: Vec<String>,
    /// Maximum size of a downloaded filter list.
    pub max_http_size: ByteSize,
    /// Safe-browsing cache size in bytes.
    pub safebrowsing_cache_size: u64,
    /// Safe-search cache size in bytes.
    pub safesearch_cache_size: u64,
    /// Parental-control cache size in bytes.
    pub parental_cache_size: u64,
    /// Cache entry lifetime in minutes.
    pub cache_time: u32,
    /// Hours between filter list refreshes.
    pub filters_update_interval: u32,
    /// TTL of a blocked response.
    pub blocked_response_ttl: u32,
    /// Whether filtering is on.
    pub filtering_enabled: bool,
    /// Whether DNS rewrites are applied.
    pub rewrites_enabled: bool,
    /// Whether parental control is on.
    pub parental_enabled: bool,
    /// Whether safe browsing is on.
    pub safebrowsing_enabled: bool,
    /// The master protection switch.
    pub protection_enabled: bool,
}

impl Default for FilteringConfig {
    fn default() -> Self {
        Self {
            blocking_ipv4: OptAddr(None),
            blocking_ipv6: OptAddr(None),
            blocked_services: BlockedServices::default(),
            protection_disabled_until: None,
            safe_search: SafeSearchConfig::default(),
            blocking_mode: BlockingMode::Default,
            parental_block_host: "family-block.dns.adguard.com".into(),
            safebrowsing_block_host: "standard-block.dns.adguard.com".into(),
            rewrites: Vec::new(),
            safe_fs_patterns: Vec::new(),
            max_http_size: ByteSize::from_mb(256),
            safebrowsing_cache_size: 1024 * 1024,
            safesearch_cache_size: 1024 * 1024,
            parental_cache_size: 1024 * 1024,
            cache_time: 30,
            filters_update_interval: 24,
            blocked_response_ttl: 10,
            filtering_enabled: true,
            rewrites_enabled: true,
            parental_enabled: false,
            safebrowsing_enabled: false,
            protection_enabled: true,
        }
    }
}

/// How blocked queries are answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockingMode {
    /// `0.0.0.0` for A, `::` for AAAA — or the blocking rule's own address.
    #[default]
    Default,
    /// The addresses in `blocking_ipv4` and `blocking_ipv6`.
    CustomIp,
    /// `NODATA`.
    Nxdomain,
    /// `NODATA` with an empty answer section.
    NullIp,
    /// `REFUSED`.
    Refused,
}

/// Blocked services and their schedule.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockedServices {
    /// When the block applies.
    pub schedule: Schedule,
    /// Identifiers of the blocked services.
    pub ids: Vec<String>,
}

/// A weekly schedule.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Schedule {
    /// The IANA time zone the day ranges are interpreted in.
    pub time_zone: String,
    /// Monday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mon: Option<DayRange>,
    /// Tuesday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tue: Option<DayRange>,
    /// Wednesday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wed: Option<DayRange>,
    /// Thursday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thu: Option<DayRange>,
    /// Friday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fri: Option<DayRange>,
    /// Saturday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sat: Option<DayRange>,
    /// Sunday's active range.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sun: Option<DayRange>,
}

impl Default for Schedule {
    fn default() -> Self {
        // Upstream writes `Local` rather than an empty zone, and the emitted
        // config must match.
        Self {
            time_zone: "Local".into(),
            ..Self::empty()
        }
    }
}

impl Schedule {
    /// A schedule with no day ranges and no time zone.
    fn empty() -> Self {
        Self {
            time_zone: String::new(),
            mon: None,
            tue: None,
            wed: None,
            thu: None,
            fri: None,
            sat: None,
            sun: None,
        }
    }
}

/// A time range within a day.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct DayRange {
    /// Start of the range, as a duration from midnight.
    pub start: GoDuration,
    /// End of the range, as a duration from midnight.
    pub end: GoDuration,
}

/// Safe-search settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SafeSearchConfig {
    /// Whether safe search is enforced.
    pub enabled: bool,
    /// Enforce on Bing.
    pub bing: bool,
    /// Enforce on DuckDuckGo.
    pub duckduckgo: bool,
    /// Enforce on Ecosia.
    pub ecosia: bool,
    /// Enforce on Google.
    pub google: bool,
    /// Enforce on Pixabay.
    pub pixabay: bool,
    /// Enforce on Yandex.
    pub yandex: bool,
    /// Enforce on YouTube.
    pub youtube: bool,
}

impl Default for SafeSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bing: true,
            duckduckgo: true,
            ecosia: true,
            google: true,
            pixabay: true,
            yandex: true,
            youtube: true,
        }
    }
}

/// A legacy DNS rewrite rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Rewrite {
    /// The domain pattern the rewrite applies to.
    pub domain: String,
    /// The address, canonical name, or the literal `A` or `AAAA`.
    pub answer: String,
    /// Whether the rewrite is active.
    pub enabled: bool,
}

impl Default for Rewrite {
    fn default() -> Self {
        Self {
            domain: String::new(),
            answer: String::new(),
            enabled: true,
        }
    }
}

/// Client settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientsConfig {
    /// Where runtime clients are discovered from.
    pub runtime_sources: ClientSources,
    /// Explicitly configured clients.
    pub persistent: Vec<PersistentClient>,
}

/// Sources of runtime client information.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientSources {
    /// Look clients up over WHOIS.
    pub whois: bool,
    /// Discover clients from the ARP table.
    pub arp: bool,
    /// Discover clients by reverse DNS.
    pub rdns: bool,
    /// Discover clients from DHCP leases.
    pub dhcp: bool,
    /// Discover clients from the hosts file.
    pub hosts: bool,
}

impl Default for ClientSources {
    fn default() -> Self {
        Self {
            whois: true,
            arp: true,
            rdns: true,
            dhcp: true,
            hosts: true,
        }
    }
}

/// An explicitly configured client.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistentClient {
    /// Whether the client is safe-search-enforced.
    pub safe_search: SafeSearchConfig,
    /// Blocked services for this client.
    pub blocked_services: BlockedServices,
    /// The client's display name.
    pub name: String,
    /// Addresses, CIDRs, MACs and ClientIDs identifying the client.
    pub ids: Vec<String>,
    /// Tags applied to the client.
    pub tags: Vec<String>,
    /// Per-client upstream resolvers.
    pub upstreams: Vec<String>,
    /// A stable identifier for the client.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub uid: String,
    /// Per-client upstream selection mode.
    pub upstreams_cache_size: u32,
    /// Whether the per-client upstream cache is on.
    pub upstreams_cache_enabled: bool,
    /// Whether global settings are used instead of the per-client ones.
    pub use_global_settings: bool,
    /// Whether global filtering settings apply.
    pub filtering_enabled: bool,
    /// Whether parental control applies.
    pub parental_enabled: bool,
    /// Whether safe browsing applies.
    pub safebrowsing_enabled: bool,
    /// Whether the client's queries are kept **out** of the query log.
    ///
    /// The sense is the field's name, not the feature's: absent means the
    /// client is logged, which is what an operator who never set it expects.
    pub ignore_querylog: bool,
    /// Whether the client's queries are kept **out** of the statistics.
    pub ignore_statistics: bool,
    /// Whether global blocked-services settings apply.
    pub use_global_blocked_services: bool,
}

impl Default for PersistentClient {
    fn default() -> Self {
        Self {
            safe_search: SafeSearchConfig::default(),
            blocked_services: BlockedServices::default(),
            name: String::new(),
            ids: Vec::new(),
            tags: Vec::new(),
            upstreams: Vec::new(),
            uid: String::new(),
            upstreams_cache_size: 0,
            upstreams_cache_enabled: false,
            use_global_settings: true,
            filtering_enabled: true,
            parental_enabled: false,
            safebrowsing_enabled: false,
            ignore_querylog: false,
            ignore_statistics: false,
            use_global_blocked_services: true,
        }
    }
}

/// Logging settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Whether logging is on.
    pub enabled: bool,
    /// Log file path, `syslog`, or empty for stdout.
    pub file: String,
    /// Rotated files kept.
    pub max_backups: u32,
    /// Size in megabytes at which the log rotates.
    pub max_size: u32,
    /// Days a rotated file is kept.
    pub max_age: u32,
    /// Whether rotated files are gzipped.
    pub compress: bool,
    /// Whether timestamps use local time.
    pub local_time: bool,
    /// Whether debug logging is on.
    pub verbose: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            file: String::new(),
            max_backups: 0,
            max_size: 100,
            max_age: 3,
            compress: false,
            local_time: false,
            verbose: false,
        }
    }
}

/// OS-level settings.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OsConfig {
    /// Group to switch to at startup.
    pub group: String,
    /// User to switch to at startup.
    pub user: String,
    /// Maximum open file descriptors, or 0 for the system default.
    pub rlimit_nofile: u64,
}
