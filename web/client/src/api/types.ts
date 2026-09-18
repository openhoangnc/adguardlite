/**
 * The shapes the control API exchanges.
 *
 * These mirror `crates/sift-api/src/handlers/*.rs` rather than anything the
 * frontend would have chosen: the API is AdGuard Home v0.107.79's, and the
 * oddities in it -- an interval reported in days by one endpoint and
 * milliseconds by another, a list that is `null` rather than empty -- are the
 * format, not mistakes to correct here.
 */

/** `GET /control/status` */
export interface ServerStatus {
    version: string;
    language: string;
    dns_addresses: string[];
    dns_port: number;
    http_port: number;
    protection_disabled_duration: number;
    start_time: number;
    protection_enabled: boolean;
    dhcp_available: boolean;
    running: boolean;
}

/** `GET /control/profile` */
export interface Profile {
    name: string;
    language: string;
    theme: Theme;
}

export type Theme = 'auto' | 'light' | 'dark';

/** `GET /control/version.json` */
export interface VersionInfo {
    disabled?: boolean;
    new_version?: string;
    announcement?: string;
    announcement_url?: string;
    can_autoupdate?: boolean;
}

/** `GET /control/dns_info`, and the body `POST /control/dns_config` takes. */
export interface DnsConfig {
    upstream_dns: string[];
    upstream_dns_file: string;
    bootstrap_dns: string[];
    fallback_dns: string[];
    protection_enabled: boolean;
    ratelimit: number;
    ratelimit_subnet_len_ipv4: number;
    ratelimit_subnet_len_ipv6: number;
    ratelimit_whitelist: string[];
    upstream_timeout: number;
    blocking_mode: BlockingMode;
    blocking_ipv4: string;
    blocking_ipv6: string;
    blocked_response_ttl: number;
    edns_cs_enabled: boolean;
    edns_cs_use_custom: boolean;
    edns_cs_custom_ip: string;
    dnssec_enabled: boolean;
    disable_ipv6: boolean;
    upstream_mode: UpstreamMode;
    cache_size: number;
    cache_ttl_min: number;
    cache_ttl_max: number;
    cache_enabled: boolean;
    cache_optimistic: boolean;
    resolve_clients: boolean;
    use_private_ptr_resolvers: boolean;
    local_ptr_upstreams: string[];
    default_local_ptr_upstreams: string[] | null;
}

export type BlockingMode = 'default' | 'refused' | 'nxdomain' | 'null_ip' | 'custom_ip';

/**
 * How several upstreams are used.
 *
 * Load balancing is reported as an **empty string**, not as `load_balance`:
 * that is the value upstream's config has always written, and the API echoes
 * it.  `POST /control/dns_config` accepts either spelling.
 */
export type UpstreamMode = '' | 'load_balance' | 'parallel' | 'fastest_addr';

/** `GET /control/filtering/status` */
export interface FilteringStatus {
    filters: Filter[] | null;
    whitelist_filters: Filter[] | null;
    user_rules: string[] | null;
    interval: number;
    enabled: boolean;
}

export interface Filter {
    url: string;
    name: string;
    last_updated?: string;
    id: number;
    rules_count: number;
    enabled: boolean;
}

/** `GET /control/filtering/check_host` */
export interface CheckHostResult {
    reason: FilterReason;
    rule: string;
    rules: { text: string; filter_list_id: number }[];
    service_name: string;
    cname: string;
    ip_addrs: string[] | null;
    filter_id: number;
}

/**
 * Why a query was answered the way it was.
 *
 * The spellings are the wire's, not the server's own identifiers: upstream
 * kept the older names when it renamed the constants, so an allowlist hit
 * arrives as `NotFilteredWhiteList`.
 */
export type FilterReason =
    | 'NotFilteredNotFound'
    | 'NotFilteredWhiteList'
    | 'NotFilteredError'
    | 'FilteredBlackList'
    | 'FilteredSafeBrowsing'
    | 'FilteredParental'
    | 'FilteredInvalid'
    | 'FilteredSafeSearch'
    | 'FilteredBlockedService'
    | 'Rewrite'
    | 'RewriteEtcHosts'
    | 'RewriteRule';

export interface Rewrite {
    domain: string;
    answer: string;
    enabled?: boolean;
}

export interface SafeSearchConfig {
    enabled: boolean;
    bing: boolean;
    duckduckgo: boolean;
    ecosia: boolean;
    google: boolean;
    pixabay: boolean;
    yandex: boolean;
    youtube: boolean;
}

/**
 * `GET /control/filtering/catalogue`
 *
 * The known lists the interface offers to add without typing an address.
 * This path is **not** one of upstream's: AdGuard Home bundles the catalogue
 * in its client, and this build serves it instead, so the interface carries
 * nothing of AdGuard's.
 */
export interface BlocklistCatalogue {
    categories: { id: string }[];
    /** Every non-country tag in use, sorted. */
    tags: string[];
    /** The countries lists serve, as code and name. Drawn as flags. */
    countries: Record<string, string>;
    filters: CatalogueEntry[];
}

export interface CatalogueEntry {
    id: string;
    name: string;
    category_id: string;
    homepage?: string;
    url: string;
    /** Rules counted the last time the catalogue was built. */
    rules: number;
    /** What the list is for. Exactly one is a size; two letters is a country. */
    tags: string[];
    /** When to pick this list, in a sentence or two. */
    note?: string;
}

/** `GET /control/querylog` */
export interface QueryLog {
    data: LogEntry[] | null;
    oldest: string;
}

export interface LogEntry {
    answer?: LogAnswer[];
    answer_dnssec: boolean;
    cached: boolean;
    client: string;
    client_id?: string;
    client_info?: { name?: string; whois?: Whois; disallowed?: boolean; disallowed_rule?: string };
    client_proto: string;
    elapsedMs: string;
    filterId?: number;
    question: { class: string; name: string; type: string };
    reason: FilterReason;
    rule?: string;
    rules: { filter_list_id: number; text: string }[];
    status: string;
    time: string;
    upstream?: string;
    ecs?: string;
    service_name?: string;
}

export interface LogAnswer {
    type: string;
    value: string;
    ttl: number;
}

export interface Whois {
    city?: string;
    country?: string;
    orgname?: string;
}

/** `GET /control/querylog/config` -- interval in **milliseconds**. */
export interface QueryLogConfig {
    enabled: boolean;
    interval: number;
    anonymize_client_ip: boolean;
    ignored: string[] | null;
    ignored_enabled?: boolean;
}

/** `GET /control/stats/config` -- interval in **milliseconds**. */
export interface StatsConfig {
    enabled: boolean;
    interval: number;
    ignored: string[] | null;
    ignored_enabled?: boolean;
}

/** One `{name: count}` pair, which is how the API renders every top list. */
export type TopEntry = Record<string, number>;

/** `GET /control/stats` */
export interface Stats {
    time_units: 'hours' | 'days';
    top_queried_domains: TopEntry[];
    top_clients: TopEntry[];
    top_blocked_domains: TopEntry[];
    top_upstreams_responses: TopEntry[];
    top_upstreams_avg_time: TopEntry[];
    dns_queries: number[];
    blocked_filtering: number[];
    replaced_safebrowsing: number[];
    replaced_parental: number[];
    num_dns_queries: number;
    num_blocked_filtering: number;
    num_replaced_safebrowsing: number;
    num_replaced_safesearch: number;
    num_replaced_parental: number;
    avg_processing_time: number;
}

/** `GET /control/clients` */
export interface ClientsResponse {
    clients: Client[] | null;
    auto_clients: AutoClient[] | null;
    supported_tags: string[] | null;
}

export interface Client {
    name: string;
    ids: string[];
    use_global_settings: boolean;
    filtering_enabled: boolean;
    use_global_blocked_services: boolean;
    blocked_services: string[];
    blocked_services_schedule?: Schedule;
    safe_search?: SafeSearchConfig | null;
    upstreams: string[];
    tags: string[];
    ignore_querylog: boolean;
    ignore_statistics: boolean;
}

export interface AutoClient {
    ip: string;
    name: string;
    source: string;
    whois_info?: Whois;
}

/** `GET /control/access/list` */
export interface AccessList {
    allowed_clients: string[] | null;
    disallowed_clients: string[] | null;
    blocked_hosts: string[] | null;
}

/** `GET /control/blocked_services/all` */
export interface ServiceCatalogue {
    blocked_services: BlockedService[];
    groups?: { id: string; name?: string }[];
}

export interface BlockedService {
    id: string;
    name: string;
    icon_svg?: string;
    rules?: string[];
    group_id?: string;
}

/** `GET /control/blocked_services/get` */
export interface BlockedServices {
    ids: string[] | null;
    schedule?: Schedule;
}

/**
 * When a blocked-services rule is **paused**.
 *
 * A day's range says when the block does *not* apply, so an empty schedule
 * blocks around the clock.  See `sift-core/src/schedule.rs`.
 */
export interface Schedule {
    time_zone: string;
    sun?: DayRange;
    mon?: DayRange;
    tue?: DayRange;
    wed?: DayRange;
    thu?: DayRange;
    fri?: DayRange;
    sat?: DayRange;
}

/** Milliseconds from midnight. */
export interface DayRange {
    start: number;
    end: number;
}

export const WEEKDAYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'] as const;

export type Weekday = (typeof WEEKDAYS)[number];

/** `GET /control/tls/status`, and the body `POST /control/tls/configure` takes. */
export interface TlsConfig {
    enabled: boolean;
    server_name: string;
    force_https: boolean;
    port_https: number;
    port_dns_over_tls: number;
    port_dns_over_quic: number;
    certificate_chain: string;
    private_key: string;
    certificate_path: string;
    private_key_path: string;
    private_key_saved?: boolean;
    serve_plain_dns: boolean;
}

/** What `GET /control/tls/status` adds to the settings it echoes. */
export interface TlsStatus extends TlsConfig {
    valid_cert: boolean;
    valid_chain: boolean;
    valid_key: boolean;
    valid_pair: boolean;
    not_before: string;
    not_after: string;
    dns_names: string[] | null;
    subject?: string;
    issuer?: string;
    key_type?: string;
    warning_validation?: string;
}

/** `GET /control/install/get_addresses` */
export interface InstallAddresses {
    web_port: number;
    dns_port: number;
    version: string;
    interfaces: Record<string, NetInterface>;
}

export interface NetInterface {
    name: string;
    mtu?: number;
    hardware_address?: string;
    flags?: string;
    ip_addresses?: string[];
    gateway_ip?: string;
}
