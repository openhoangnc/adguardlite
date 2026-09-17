//! Upgrading an older `AdGuardHome.yaml` to the schema this build reads.
//!
//! A port of `internal/configmigrate`.  Each step takes the document from one
//! schema version to the next and the chain runs from whatever the file says
//! up to [`sift_core::SCHEMA_VERSION`], exactly as upstream's migrator does —
//! including the odd details, like migration 16 keeping a one-day interval
//! while turning statistics *off* when the old interval was zero.
//!
//! The document is manipulated as a YAML tree rather than as the typed model:
//! the older shapes have fields the model no longer has, and going through the
//! model would silently drop them.

use std::path::{Path, PathBuf};

use serde_yaml_ng::{Mapping, Value};

/// Where the migrator may look on disk.
///
/// Two migrations touch the filesystem: the first two delete files that later
/// versions stopped using, and the twenty-ninth records the directory that
/// local filter lists may be read from.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// The working directory.
    pub work_dir: PathBuf,
    /// The data directory, normally `<work_dir>/data`.
    pub data_dir: PathBuf,
}

impl Context {
    /// Builds a context from a working directory, using upstream's layout.
    pub fn new(work_dir: impl Into<PathBuf>) -> Self {
        let work_dir = work_dir.into();
        let data_dir = work_dir.join("data");

        Self { work_dir, data_dir }
    }
}

/// A migration failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The document is not a mapping.
    #[error("the config file is not a YAML mapping")]
    NotAMapping,

    /// A field held something the migration could not use.
    #[error("migrating schema {from} to {to}: {reason}")]
    Step {
        /// The version being migrated from.
        from: u32,
        /// The version being migrated to.
        to: u32,
        /// What went wrong.
        reason: String,
    },
}

/// The schema version recorded in a parsed document, defaulting to 0.
///
/// A file written before the field existed is schema 0, which is what upstream
/// assumes too.
pub fn schema_version(doc: &Value) -> u32 {
    doc.get("schema_version")
        .and_then(Value::as_i64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

/// Upgrades `doc` in place to `target`, returning whether anything changed.
///
/// A document already at or above `target` is left alone; the caller decides
/// whether a newer-than-supported version is an error.
pub fn upgrade(doc: &mut Value, target: u32, ctx: &Context) -> Result<bool, Error> {
    let current = schema_version(doc);
    if current >= target {
        return Ok(false);
    }

    let root = doc.as_mapping_mut().ok_or(Error::NotAMapping)?;

    for from in current..target {
        let to = from + 1;
        step(root, to, ctx).map_err(|reason| Error::Step { from, to, reason })?;
        root.insert("schema_version".into(), Value::from(i64::from(to)));
    }

    Ok(true)
}

/// Runs the migration that produces schema version `to`.
fn step(root: &mut Mapping, to: u32, ctx: &Context) -> Result<(), String> {
    match to {
        1 => to_1(ctx),
        2 => to_2(root, ctx),
        3 => to_3(root),
        4 => to_4(root),
        5 => to_5(root),
        6 => to_6(root),
        7 => to_7(root),
        8 => to_8(root),
        9 => to_9(root),
        10 => to_10(root),
        11 => to_11(root),
        12 => to_12(root),
        13 => to_13(root),
        14 => to_14(root),
        15 => to_15(root),
        16 => to_16(root),
        17 => to_17(root),
        18 => to_18(root),
        19 => to_19(root),
        20 => to_20(root),
        21 => to_21(root),
        22 => to_22(root),
        23 => to_23(root),
        24 => to_24(root),
        25 => to_25(root),
        26 => to_26(root),
        27 => to_27(root),
        28 => to_28(root),
        29 => to_29(root, ctx),
        30 => to_30(root),
        31 => to_31(root),
        32 => to_32(root),
        33 => to_33(root),
        34 => to_34(root),
        other => Err(format!("no migration to schema version {other}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers, mirroring `configmigrate/yaml.go`.
// ---------------------------------------------------------------------------

/// Borrows a nested mapping, if the key holds one.
fn submap<'a>(m: &'a mut Mapping, key: &str) -> Option<&'a mut Mapping> {
    m.get_mut(key)?.as_mapping_mut()
}

/// Borrows a nested sequence, if the key holds one.
fn subseq<'a>(m: &'a mut Mapping, key: &str) -> Option<&'a mut Vec<Value>> {
    m.get_mut(key)?.as_sequence_mut()
}

/// Moves a value between mappings, renaming it, and does nothing if absent.
///
/// Upstream's `moveVal` writes the destination key only when the source key
/// exists, so a missing field stays missing rather than becoming a zero value.
fn move_val(src: &mut Mapping, dst: &mut Mapping, src_key: &str, dst_key: &str) {
    if let Some(v) = src.remove(src_key) {
        dst.insert(dst_key.into(), v);
    }
}

/// Moves a value between mappings under the same key.
fn move_same(src: &mut Mapping, dst: &mut Mapping, key: &str) {
    move_val(src, dst, key, key);
}

/// Builds a mapping from key-value pairs, preserving their order.
fn mapping<const N: usize>(pairs: [(&str, Value); N]) -> Value {
    let mut m = Mapping::new();
    for (k, v) in pairs {
        m.insert(k.into(), v);
    }

    Value::Mapping(m)
}

/// The safe-search block that migrations 18 and 19 install.
fn default_safe_search() -> Value {
    mapping([
        ("enabled", true.into()),
        ("bing", true.into()),
        ("duckduckgo", true.into()),
        ("google", true.into()),
        ("pixabay", true.into()),
        ("yandex", true.into()),
        ("youtube", true.into()),
    ])
}

/// Removes a file that a later schema version stopped using.
///
/// A missing file is the normal case, and a failure to remove one is not worth
/// aborting a migration over: upstream logs it and carries on too.
fn discard(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// The migrations.
// ---------------------------------------------------------------------------

/// Schema 1: the version field appears; `dnsfilter.txt` is no longer read.
fn to_1(ctx: &Context) -> Result<(), String> {
    discard(&ctx.work_dir.join("dnsfilter.txt"));

    Ok(())
}

/// Schema 2: `coredns` becomes `dns`; the CoreDNS `Corefile` is dropped.
fn to_2(root: &mut Mapping, ctx: &Context) -> Result<(), String> {
    discard(&ctx.work_dir.join("Corefile"));

    if let Some(v) = root.remove("coredns") {
        root.insert("dns".into(), v);
    }

    Ok(())
}

/// Schema 3: `bootstrap_dns` becomes a list.
fn to_3(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };
    if let Some(v) = dns.remove("bootstrap_dns") {
        dns.insert("bootstrap_dns".into(), Value::Sequence(vec![v]));
    }

    Ok(())
}

/// Schema 4: every client gains `use_global_blocked_services`.
fn to_4(root: &mut Mapping) -> Result<(), String> {
    let Some(clients) = subseq(root, "clients") else {
        return Ok(());
    };
    for c in clients.iter_mut() {
        if let Some(m) = c.as_mapping_mut() {
            m.insert("use_global_blocked_services".into(), true.into());
        }
    }

    Ok(())
}

/// Schema 5: `auth_name`/`auth_pass` become a `users` list with a hash.
fn to_5(root: &mut Mapping) -> Result<(), String> {
    let mut user = Mapping::new();
    move_val(root, &mut user, "auth_name", "name");

    let Some(pass) = root.remove("auth_pass") else {
        return Ok(());
    };
    let pass = pass.as_str().unwrap_or_default().to_string();

    let hash = bcrypt::hash(&pass, bcrypt::DEFAULT_COST)
        .map_err(|e| format!("generating password hash: {e}"))?;
    user.insert("password".into(), hash.into());

    root.insert("users".into(), Value::Sequence(vec![Value::Mapping(user)]));

    Ok(())
}

/// Schema 6: a client's `ip` and `mac` become its `ids` list.
fn to_6(root: &mut Mapping) -> Result<(), String> {
    let Some(clients) = subseq(root, "clients") else {
        return Ok(());
    };

    for (i, c) in clients.iter_mut().enumerate() {
        let Some(m) = c.as_mapping_mut() else {
            return Err(format!("unexpected type of client at index {i}"));
        };

        let mut ids = Vec::new();
        for key in ["ip", "mac"] {
            match m.get(key) {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) if s.is_empty() => {}
                Some(Value::String(s)) => ids.push(Value::String(s.clone())),
                Some(_) => return Err(format!("client at index {i}: unexpected type of {key:?}")),
            }
        }

        m.insert("ids".into(), Value::Sequence(ids));
    }

    Ok(())
}

/// Schema 7: the IPv4 DHCP settings move under `dhcp.dhcpv4`.
fn to_7(root: &mut Mapping) -> Result<(), String> {
    let Some(dhcp) = submap(root, "dhcp") else {
        return Ok(());
    };

    let mut v4 = Mapping::new();
    for key in [
        "gateway_ip",
        "subnet_mask",
        "range_start",
        "range_end",
        "lease_duration",
        "icmp_timeout_msec",
    ] {
        move_same(dhcp, &mut v4, key);
    }
    dhcp.insert("dhcpv4".into(), Value::Mapping(v4));

    Ok(())
}

/// Schema 8: `bind_host` becomes the `bind_hosts` list.
fn to_8(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };
    let Some(host) = dns.remove("bind_host") else {
        return Ok(());
    };
    dns.insert("bind_hosts".into(), Value::Sequence(vec![host]));

    Ok(())
}

/// Schema 9: `autohost_tld` becomes `local_domain_name`.
fn to_9(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };
    if let Some(v) = dns.remove("autohost_tld") {
        dns.insert("local_domain_name".into(), v);
    }

    Ok(())
}

/// Schema 10: `quic://` upstreams without a port get the then-default 784.
fn to_10(root: &mut Mapping) -> Result<(), String> {
    const QUIC_PORT: u16 = 784;

    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    for key in ["upstream_dns", "local_ptr_upstreams"] {
        let Some(ups) = subseq(dns, key) else {
            continue;
        };
        for u in ups.iter_mut() {
            let Some(s) = u.as_str() else {
                return Err(format!("unexpected type of upstream in {key:?}"));
            };
            *u = Value::String(add_quic_port(s, QUIC_PORT));
        }
    }

    Ok(())
}

/// Inserts a port into a `quic://` upstream that has none.
fn add_quic_port(spec: &str, port: u16) -> String {
    if spec.is_empty() || spec.starts_with('#') {
        return spec.to_string();
    }

    // A `[/domain/]upstream` form keeps its prefix and rewrites the rest.
    let (domains, rest) = match spec.strip_prefix("[/") {
        Some(after) => match after.split_once("/]") {
            Some((doms, ups)) => (format!("[/{doms}/]"), ups),
            None => return spec.to_string(),
        },
        None => (String::new(), spec),
    };

    let Some(authority) = rest.strip_prefix("quic://") else {
        return spec.to_string();
    };

    // Only a bare host gets a port; anything with a port, a path or brackets
    // is left alone, as upstream's `netutil.SplitHost` check does.
    let host = authority
        .split('/')
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');
    if host.is_empty() || host.contains(':') || host.contains('[') || host != authority {
        return spec.to_string();
    }

    format!("{domains}quic://{host}:{port}")
}

/// Schema 11: `rlimit_nofile` moves into the `os` block.
fn to_11(root: &mut Mapping) -> Result<(), String> {
    let rlimit = root.remove("rlimit_nofile").unwrap_or(Value::from(0i64));
    root.insert(
        "os".into(),
        mapping([
            ("group", "".into()),
            ("rlimit_nofile", rlimit),
            ("user", "".into()),
        ]),
    );

    Ok(())
}

/// Schema 12: the query log interval becomes a duration string.
fn to_12(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    // 90 days is the value `home.initConfig` used before this field moved.
    let days = dns
        .remove("querylog_interval")
        .and_then(|v| v.as_i64())
        .unwrap_or(90);
    dns.insert("querylog_interval".into(), format!("{}h", days * 24).into());

    Ok(())
}

/// Schema 13: `local_domain_name` moves from `dns` to `dhcp`.
fn to_13(root: &mut Mapping) -> Result<(), String> {
    let Some(v) = submap(root, "dns").and_then(|d| d.remove("local_domain_name")) else {
        return Ok(());
    };
    if let Some(dhcp) = submap(root, "dhcp") {
        dhcp.insert("local_domain_name".into(), v);
    }

    Ok(())
}

/// Schema 14: clients gain `persistent` and `runtime_sources`.
fn to_14(root: &mut Mapping) -> Result<(), String> {
    let persistent = match root.remove("clients") {
        Some(Value::Sequence(s)) => Value::Sequence(s),
        _ => Value::Sequence(Vec::new()),
    };

    // `resolve_clients` defaulted off, unlike the other sources.
    let resolve = submap(root, "dns").and_then(|d| d.remove("resolve_clients"));

    let runtime = mapping([
        ("whois", true.into()),
        ("arp", true.into()),
        ("rdns", resolve.unwrap_or(false.into())),
        ("dhcp", true.into()),
        ("hosts", true.into()),
    ]);

    root.insert(
        "clients".into(),
        mapping([("persistent", persistent), ("runtime_sources", runtime)]),
    );

    Ok(())
}

/// Schema 15: the query log settings move into their own block.
fn to_15(root: &mut Mapping) -> Result<(), String> {
    let mut qlog = Mapping::new();
    qlog.insert("ignored".into(), Value::Sequence(Vec::new()));
    qlog.insert("enabled".into(), true.into());
    qlog.insert("file_enabled".into(), true.into());
    qlog.insert("interval".into(), "2160h".into());
    qlog.insert("size_memory".into(), Value::from(1000i64));

    if let Some(dns) = submap(root, "dns") {
        move_val(dns, &mut qlog, "querylog_enabled", "enabled");
        move_val(dns, &mut qlog, "querylog_file_enabled", "file_enabled");
        move_val(dns, &mut qlog, "querylog_interval", "interval");
        move_val(dns, &mut qlog, "querylog_size_memory", "size_memory");
    }

    root.insert("querylog".into(), Value::Mapping(qlog));

    Ok(())
}

/// Schema 16: the statistics settings move into their own block.
///
/// An interval of zero meant "off"; the interval is kept at one day so it
/// still validates, and `enabled` carries the meaning instead.
fn to_16(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };
    let Some(ivl) = dns.remove("statistics_interval") else {
        return Ok(());
    };
    let ivl = ivl.as_i64().unwrap_or(0);

    root.insert(
        "statistics".into(),
        mapping([
            ("enabled", (ivl != 0).into()),
            ("interval", Value::from(if ivl == 0 { 1 } else { ivl })),
            ("ignored", Value::Sequence(Vec::new())),
        ]),
    );

    Ok(())
}

/// Schema 17: `edns_client_subnet` becomes a block.
fn to_17(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    let enabled = dns
        .remove("edns_client_subnet")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    dns.insert(
        "edns_client_subnet".into(),
        mapping([
            ("enabled", enabled.into()),
            ("use_custom", false.into()),
            ("custom_ip", "".into()),
        ]),
    );

    Ok(())
}

/// Schema 18: `safesearch_enabled` becomes the `safe_search` block.
fn to_18(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    let mut ss = default_safe_search();
    if let (Some(m), Some(v)) = (ss.as_mapping_mut(), dns.remove("safesearch_enabled")) {
        m.insert("enabled".into(), v);
    }
    dns.insert("safe_search".into(), ss);

    Ok(())
}

/// Schema 19: the same move, for each persistent client.
fn to_19(root: &mut Mapping) -> Result<(), String> {
    let Some(clients) = submap(root, "clients") else {
        return Ok(());
    };
    let Some(persistent) = subseq(clients, "persistent") else {
        return Ok(());
    };

    for c in persistent.iter_mut() {
        let Some(m) = c.as_mapping_mut() else {
            continue;
        };

        let mut ss = default_safe_search();
        if let (Some(ssm), Some(v)) = (ss.as_mapping_mut(), m.remove("safesearch_enabled")) {
            ssm.insert("enabled".into(), v);
        }
        m.insert("safe_search".into(), ss);
    }

    Ok(())
}

/// Schema 20: the statistics interval becomes a duration string.
fn to_20(root: &mut Mapping) -> Result<(), String> {
    let Some(stats) = submap(root, "statistics") else {
        return Ok(());
    };

    let days = match stats.remove("interval").and_then(|v| v.as_i64()) {
        Some(0) | None => 1,
        Some(d) => d,
    };
    stats.insert("interval".into(), format!("{}h", days * 24).into());

    Ok(())
}

/// Schema 21: `blocked_services` becomes a block with a schedule.
fn to_21(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    let mut svcs = Mapping::new();
    svcs.insert("schedule".into(), mapping([("time_zone", "Local".into())]));
    if let Some(ids) = dns.remove("blocked_services") {
        svcs.insert("ids".into(), ids);
    }
    dns.insert("blocked_services".into(), Value::Mapping(svcs));

    Ok(())
}

/// Schema 22: the same shape, for each persistent client.
fn to_22(root: &mut Mapping) -> Result<(), String> {
    let Some(clients) = submap(root, "clients") else {
        return Ok(());
    };
    let Some(persistent) = subseq(clients, "persistent") else {
        return Ok(());
    };

    for (i, c) in persistent.iter_mut().enumerate() {
        let Some(m) = c.as_mapping_mut() else {
            return Err(format!("persistent client at index {i}: unexpected type"));
        };
        let Some(ids) = m.remove("blocked_services") else {
            continue;
        };

        m.insert(
            "blocked_services".into(),
            mapping([
                ("ids", ids),
                ("schedule", mapping([("time_zone", "Local".into())])),
            ]),
        );
    }

    Ok(())
}

/// Schema 23: the web binding and session lifetime move into `http`.
fn to_23(root: &mut Mapping) -> Result<(), String> {
    let Some(host) = root.remove("bind_host") else {
        return Ok(());
    };
    let host = host.as_str().unwrap_or_default().to_string();
    if host.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("invalid bind_host value: {host}"));
    }

    let port = root
        .remove("bind_port")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    let ttl = root
        .remove("web_session_ttl")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    root.insert(
        "http".into(),
        mapping([
            ("address", address.into()),
            ("session_ttl", format!("{ttl}h").into()),
        ]),
    );

    Ok(())
}

/// Schema 24: the `log_*` fields move into the `log` block.
fn to_24(root: &mut Mapping) -> Result<(), String> {
    let mut log = Mapping::new();
    for (from, to) in [
        ("log_file", "file"),
        ("log_max_backups", "max_backups"),
        ("log_max_size", "max_size"),
        ("log_max_age", "max_age"),
        ("log_compress", "compress"),
        ("log_localtime", "local_time"),
        ("verbose", "verbose"),
    ] {
        move_val(root, &mut log, from, to);
    }

    if !log.is_empty() {
        root.insert("log".into(), Value::Mapping(log));
    }

    Ok(())
}

/// Schema 25: `debug_pprof` becomes `http.pprof`.
fn to_25(root: &mut Mapping) -> Result<(), String> {
    let enabled = root.remove("debug_pprof");
    let Some(http) = submap(root, "http") else {
        return Ok(());
    };

    let mut pprof = Mapping::new();
    pprof.insert("enabled".into(), enabled.unwrap_or(false.into()));
    pprof.insert("port".into(), Value::from(6060i64));
    http.insert("pprof".into(), Value::Mapping(pprof));

    Ok(())
}

/// Schema 26: the filtering settings move out of `dns` into `filtering`.
fn to_26(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    let mut flt = Mapping::new();
    for key in [
        "filtering_enabled",
        "filters_update_interval",
        "parental_enabled",
        "safebrowsing_enabled",
        "safebrowsing_cache_size",
        "safesearch_cache_size",
        "parental_cache_size",
        "safe_search",
        "rewrites",
        "blocked_services",
        "protection_enabled",
        "blocking_mode",
        "blocking_ipv4",
        "blocking_ipv6",
        "blocked_response_ttl",
        "protection_disabled_until",
        "parental_block_host",
        "safebrowsing_block_host",
    ] {
        move_same(dns, &mut flt, key);
    }

    if !flt.is_empty() {
        root.insert("filtering".into(), Value::Mapping(flt));
    }

    Ok(())
}

/// Schema 27: a bare `.` in an ignore list becomes the AdBlock form `|.^`.
fn to_27(root: &mut Mapping) -> Result<(), String> {
    for key in ["querylog", "statistics"] {
        let Some(obj) = submap(root, key) else {
            continue;
        };
        let Some(ignored) = subseq(obj, "ignored") else {
            continue;
        };
        for host in ignored.iter_mut() {
            if host.as_str() == Some(".") {
                *host = "|.^".into();
            }
        }
    }

    Ok(())
}

/// Schema 28: `all_servers` and `fastest_addr` become `upstream_mode`.
fn to_28(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };

    let all = dns.remove("all_servers").and_then(|v| v.as_bool());
    let fastest = dns.remove("fastest_addr").and_then(|v| v.as_bool());
    let mode = if all == Some(true) {
        "parallel"
    } else if fastest == Some(true) {
        "fastest_addr"
    } else {
        "load_balance"
    };
    dns.insert("upstream_mode".into(), mode.into());

    Ok(())
}

/// Schema 29: local filter list paths are recorded as allowed to be read.
fn to_29(root: &mut Mapping, ctx: &Context) -> Result<(), String> {
    let mut paths = vec![Value::String(
        ctx.data_dir
            .join("userfilters")
            .join("*")
            .display()
            .to_string(),
    )];

    if let Some(filters) = subseq(root, "filters") {
        for (i, f) in filters.iter().enumerate() {
            let Some(m) = f.as_mapping() else {
                return Err(format!("filters: at index {i}: expected a mapping"));
            };
            if let Some(u) = m.get("url").and_then(Value::as_str)
                && Path::new(u).is_absolute()
            {
                paths.push(Value::String(u.to_string()));
            }
        }
    } else {
        return Ok(());
    }

    if let Some(flt) = submap(root, "filtering") {
        flt.insert("safe_fs_patterns".into(), Value::Sequence(paths));
    }

    Ok(())
}

/// Schema 30: `cache_enabled` is derived from a non-zero `cache_size`.
fn to_30(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };
    let Some(size) = dns.get("cache_size").and_then(Value::as_i64) else {
        return Ok(());
    };
    dns.insert("cache_enabled".into(), (size > 0).into());

    Ok(())
}

/// Schema 31: every rewrite gains an `enabled` flag.
fn to_31(root: &mut Mapping) -> Result<(), String> {
    let Some(flt) = submap(root, "filtering") else {
        return Ok(());
    };
    let Some(rewrites) = subseq(flt, "rewrites") else {
        return Ok(());
    };
    for r in rewrites.iter_mut() {
        if let Some(m) = r.as_mapping_mut() {
            m.insert("enabled".into(), true.into());
        }
    }

    Ok(())
}

/// Schema 32: the optimistic-cache durations become explicit.
fn to_32(root: &mut Mapping) -> Result<(), String> {
    let Some(dns) = submap(root, "dns") else {
        return Ok(());
    };
    dns.insert("cache_optimistic_answer_ttl".into(), "30s".into());
    dns.insert("cache_optimistic_max_age".into(), "12h".into());

    Ok(())
}

/// Schema 33: a non-empty ignore list turns `ignored_enabled` on.
fn to_33(root: &mut Mapping) -> Result<(), String> {
    for key in ["querylog", "statistics"] {
        let Some(obj) = submap(root, key) else {
            continue;
        };
        let Some(n) = obj
            .get("ignored")
            .and_then(Value::as_sequence)
            .map(Vec::len)
        else {
            continue;
        };
        obj.insert("ignored_enabled".into(), (n > 0).into());
    }

    Ok(())
}

/// Schema 34: the DoH routes become explicit and move out of `tls`.
fn to_34(root: &mut Mapping) -> Result<(), String> {
    let insecure = submap(root, "tls").and_then(|t| t.remove("allow_unencrypted_doh"));

    let Some(http) = submap(root, "http") else {
        return Ok(());
    };

    let mut doh = Mapping::new();
    doh.insert(
        "routes".into(),
        Value::Sequence(
            [
                "GET /dns-query",
                "POST /dns-query",
                "GET /dns-query/{ClientID}",
                "POST /dns-query/{ClientID}",
            ]
            .map(Value::from)
            .to_vec(),
        ),
    );
    if let Some(v) = insecure {
        doh.insert("insecure_enabled".into(), v);
    }
    http.insert("doh".into(), Value::Mapping(doh));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Value {
        serde_yaml_ng::from_str(s).expect("test yaml must parse")
    }

    fn migrate(s: &str) -> Value {
        let mut doc = parse(s);
        upgrade(&mut doc, sift_core::SCHEMA_VERSION, &Context::default()).expect("must migrate");

        doc
    }

    #[test]
    fn a_missing_version_field_means_schema_zero() {
        assert_eq!(schema_version(&parse("dns: {}\n")), 0);
        assert_eq!(schema_version(&parse("schema_version: 12\n")), 12);
    }

    #[test]
    fn a_current_document_is_left_alone() {
        let mut doc = parse("schema_version: 34\n");
        let before = doc.clone();
        assert!(!upgrade(&mut doc, 34, &Context::default()).unwrap());
        assert_eq!(doc, before);
    }

    #[test]
    fn coredns_becomes_dns() {
        let got = migrate("schema_version: 1\ncoredns:\n  port: 53\n");
        assert!(got.get("coredns").is_none());
        assert_eq!(
            got.get("dns").unwrap().get("port").unwrap().as_i64(),
            Some(53)
        );
    }

    #[test]
    fn bootstrap_becomes_a_list() {
        let got = migrate("schema_version: 2\ndns:\n  bootstrap_dns: 1.1.1.1\n");
        let b = got.get("dns").unwrap().get("bootstrap_dns").unwrap();
        assert_eq!(b.as_sequence().unwrap().len(), 1);
    }

    #[test]
    fn credentials_become_a_hashed_user() {
        let got = migrate("schema_version: 4\nauth_name: admin\nauth_pass: secret\n");
        let users = got.get("users").unwrap().as_sequence().unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].get("name").unwrap().as_str(), Some("admin"));

        let hash = users[0].get("password").unwrap().as_str().unwrap();
        assert!(
            hash.starts_with("$2"),
            "expected a bcrypt hash, got {hash:?}"
        );
        assert!(bcrypt::verify("secret", hash).unwrap());
    }

    #[test]
    fn client_addresses_become_ids() {
        let got =
            migrate("schema_version: 5\nclients:\n- ip: 127.0.0.1\n  mac: AA:BB:CC:DD:EE:FF\n");
        let p = got.get("clients").unwrap().get("persistent").unwrap();
        let ids = p.as_sequence().unwrap()[0].get("ids").unwrap();
        assert_eq!(ids.as_sequence().unwrap().len(), 2);
    }

    #[test]
    fn quic_upstreams_gain_the_old_default_port() {
        assert_eq!(
            add_quic_port("quic://dns.example", 784),
            "quic://dns.example:784"
        );
        assert_eq!(
            add_quic_port("quic://dns.example:853", 784),
            "quic://dns.example:853"
        );
        assert_eq!(add_quic_port("tls://dns.example", 784), "tls://dns.example");
        assert_eq!(add_quic_port("1.1.1.1", 784), "1.1.1.1");
        assert_eq!(add_quic_port("#", 784), "#");
        assert_eq!(
            add_quic_port("[/example.com/]quic://dns.example", 784),
            "[/example.com/]quic://dns.example:784"
        );
    }

    #[test]
    fn a_zero_statistics_interval_disables_rather_than_persisting_zero() {
        // Upstream keeps a one-day interval so validation still passes and
        // carries the old meaning in `enabled` instead.
        let got = migrate("schema_version: 15\ndns:\n  statistics_interval: 0\n");
        let s = got.get("statistics").unwrap();
        assert_eq!(s.get("enabled").unwrap().as_bool(), Some(false));
        assert_eq!(s.get("interval").unwrap().as_str(), Some("24h"));
    }

    #[test]
    fn a_statistics_interval_becomes_hours() {
        let got = migrate("schema_version: 15\ndns:\n  statistics_interval: 3\n");
        let s = got.get("statistics").unwrap();
        assert_eq!(s.get("enabled").unwrap().as_bool(), Some(true));
        assert_eq!(s.get("interval").unwrap().as_str(), Some("72h"));
    }

    #[test]
    fn the_web_binding_moves_into_http() {
        let got = migrate(
            "schema_version: 22\nbind_host: 127.0.0.1\nbind_port: 8080\nweb_session_ttl: 720\n",
        );
        let http = got.get("http").unwrap();
        assert_eq!(
            http.get("address").unwrap().as_str(),
            Some("127.0.0.1:8080")
        );
        assert_eq!(http.get("session_ttl").unwrap().as_str(), Some("720h"));
    }

    #[test]
    fn upstream_mode_replaces_the_two_booleans() {
        for (before, want) in [
            ("all_servers: true\n  fastest_addr: false", "parallel"),
            ("all_servers: false\n  fastest_addr: true", "fastest_addr"),
            ("all_servers: false\n  fastest_addr: false", "load_balance"),
        ] {
            let got = migrate(&format!("schema_version: 27\ndns:\n  {before}\n"));
            let m = got.get("dns").unwrap().get("upstream_mode").unwrap();
            assert_eq!(m.as_str(), Some(want));
        }
    }

    #[test]
    fn doh_routes_appear_and_the_tls_flag_moves() {
        let got = migrate("schema_version: 33\nhttp: {}\ntls:\n  allow_unencrypted_doh: true\n");
        let doh = got.get("http").unwrap().get("doh").unwrap();
        assert_eq!(doh.get("routes").unwrap().as_sequence().unwrap().len(), 4);
        assert_eq!(doh.get("insecure_enabled").unwrap().as_bool(), Some(true));
        assert!(
            got.get("tls")
                .unwrap()
                .get("allow_unencrypted_doh")
                .is_none()
        );
    }

    #[test]
    fn ignore_lists_gain_their_enabled_flag() {
        let got = migrate(
            "schema_version: 32\nquerylog:\n  ignored:\n  - '|.^'\nstatistics:\n  ignored: []\n",
        );
        assert_eq!(
            got.get("querylog")
                .unwrap()
                .get("ignored_enabled")
                .unwrap()
                .as_bool(),
            Some(true)
        );
        assert_eq!(
            got.get("statistics")
                .unwrap()
                .get("ignored_enabled")
                .unwrap()
                .as_bool(),
            Some(false)
        );
    }

    #[test]
    fn a_bare_dot_in_an_ignore_list_becomes_the_adblock_form() {
        let got = migrate("schema_version: 26\nquerylog:\n  ignored:\n  - '.'\n");
        let ignored = got.get("querylog").unwrap().get("ignored").unwrap();
        assert_eq!(ignored.as_sequence().unwrap()[0].as_str(), Some("|.^"));
    }

    #[test]
    fn the_version_field_ends_at_the_target() {
        let got = migrate("schema_version: 0\n");
        assert_eq!(schema_version(&got), sift_core::SCHEMA_VERSION);
    }
}
