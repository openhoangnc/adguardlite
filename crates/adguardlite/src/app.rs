//! Building a running server from a configuration file.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use agl_config::Config;
use agl_config::model::{BlockingMode as CfgBlockingMode, UpstreamMode};
use agl_dns::addr;
use agl_dns::cache::{Cache, Config as CacheConfig};
use agl_dns::client::{Client, tls_config};
use agl_dns::msg::{BlockingConfig, BlockingMode};
use agl_dns::pool::{self, Mode, Pool, SharedPool};
use agl_dns::ratelimit::{Config as RlConfig, Limiter};
use agl_dns::resolver::{Resolver, Settings};
use agl_dns::rewrite::Table;
use agl_dns::server::{Access, NoopObserver, Observer, Server, bind_tcp, bind_udp, serve_tcp, serve_udp};

use agl_config::Paths;
use agl_filter::lists::Manager;

/// A startup failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The configuration could not be read or written.
    #[error(transparent)]
    Config(#[from] agl_config::file::Error),

    /// A listener could not be bound.
    #[error("binding {addr}: {source}")]
    Bind {
        /// The address that could not be bound.
        addr: SocketAddr,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// A filesystem operation failed.
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// A configured, not-yet-running server.
pub struct App {
    /// Where everything lives on disk.
    pub paths: Paths,
    /// The parsed configuration.
    pub config: Config,
    /// The loaded filter lists.
    pub filters: Manager,
    /// The resolver.
    pub resolver: Arc<Resolver>,
    /// The listener front end.
    pub server: Arc<Server>,
}

impl App {
    /// Builds an application from a configuration file.
    ///
    /// Upstream resolution happens here, so a misconfigured upstream is
    /// reported at startup rather than on the first query.
    pub async fn build(paths: Paths, config: Config, observer: Arc<dyn Observer>) -> Result<Self, Error> {
        paths.ensure()?;

        let filters = Manager::load(
            &paths,
            &config.filters,
            &config.whitelist_filters,
            &config.user_rules,
        );
        let engine = filters.build_engine();

        let rewrites = Table::build(
            config
                .filtering
                .rewrites
                .iter()
                .map(|r| (r.domain.as_str(), r.answer.as_str(), r.enabled)),
        );

        let cache = Cache::new(cache_config(&config));
        let pool = SharedPool::new(build_pool(&config).await);
        let resolver = Arc::new(Resolver::new(engine, rewrites, cache, pool, settings(&config)));

        let limiter = Arc::new(Limiter::new(RlConfig {
            per_second: config.dns.ratelimit,
            subnet_len_v4: config.dns.ratelimit_subnet_len_ipv4,
            subnet_len_v6: config.dns.ratelimit_subnet_len_ipv6,
            allowlist: config.dns.ratelimit_whitelist.clone(),
        }));

        let server = Arc::new(Server::new(resolver.clone(), limiter, observer));
        *server.access.write() = Access {
            allowed: parse_ips(&config.dns.allowed_clients),
            disallowed: parse_ips(&config.dns.disallowed_clients),
        };

        Ok(Self { paths, config, filters, resolver, server })
    }

    /// Builds an application with no query observer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn build_quiet(paths: Paths, config: Config) -> Result<Self, Error> {
        Self::build(paths, config, Arc::new(NoopObserver)).await
    }

    /// The addresses the DNS server should listen on.
    pub fn dns_addrs(&self) -> Vec<SocketAddr> {
        self.config
            .dns
            .bind_hosts
            .iter()
            .map(|ip| SocketAddr::new(*ip, self.config.dns.port))
            .collect()
    }

    /// Starts every DNS listener and serves until `shutdown` resolves.
    pub async fn serve_dns(
        &self,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>, Error> {
        let mut tasks = Vec::new();

        for addr in self.dns_addrs() {
            if self.config.dns.serve_plain_dns {
                let sock = bind_udp(addr)
                    .await
                    .map_err(|source| Error::Bind { addr, source })?;
                let server = self.server.clone();
                let mut rx = shutdown.clone();
                tasks.push(tokio::spawn(async move {
                    let _ = serve_udp(sock, server, async move {
                        let _ = rx.changed().await;
                    })
                    .await;
                }));

                let listener = bind_tcp(addr)
                    .await
                    .map_err(|source| Error::Bind { addr, source })?;
                let server = self.server.clone();
                let mut rx = shutdown.clone();
                tasks.push(tokio::spawn(async move {
                    let _ = serve_tcp(listener, server, async move {
                        let _ = rx.changed().await;
                    })
                    .await;
                }));
            }
        }

        Ok(tasks)
    }

}

/// Derives resolver settings from the configuration.
pub fn settings(c: &Config) -> Settings {
    Settings {
        protection_enabled: c.filtering.protection_enabled,
        filtering_enabled: c.filtering.filtering_enabled,
        rewrites_enabled: c.filtering.rewrites_enabled,
        blocking: BlockingConfig {
            mode: match c.filtering.blocking_mode {
                CfgBlockingMode::Default => BlockingMode::Default,
                CfgBlockingMode::CustomIp => BlockingMode::CustomIp,
                CfgBlockingMode::Nxdomain => BlockingMode::Nxdomain,
                CfgBlockingMode::NullIp => BlockingMode::NullIp,
                CfgBlockingMode::Refused => BlockingMode::Refused,
            },
            custom_v4: match c.filtering.blocking_ipv4.get() {
                Some(std::net::IpAddr::V4(a)) => Some(a),
                _ => None,
            },
            custom_v6: match c.filtering.blocking_ipv6.get() {
                Some(std::net::IpAddr::V6(a)) => Some(a),
                _ => None,
            },
            ttl: c.filtering.blocked_response_ttl,
        },
        blocked_hosts: c.dns.blocked_hosts.clone(),
        aaaa_disabled: c.dns.aaaa_disabled,
        refuse_any: c.dns.refuse_any,
        cache_ttl_min: c.dns.cache_ttl_min,
        cache_ttl_max: c.dns.cache_ttl_max,
    }
}

/// Derives cache settings from the configuration.
pub fn cache_config(c: &Config) -> CacheConfig {
    CacheConfig {
        size_bytes: if c.dns.cache_enabled { c.dns.cache_size as usize } else { 0 },
        ttl_min: c.dns.cache_ttl_min,
        ttl_max: c.dns.cache_ttl_max,
        optimistic: c.dns.cache_optimistic,
        optimistic_max_age: c.dns.cache_optimistic_max_age.to_std(),
    }
}

/// Resolves every configured upstream and builds the pool.
///
/// Upstreams that fail to resolve are skipped with a warning rather than
/// aborting startup, so one dead resolver cannot keep the server down.
pub async fn build_pool(c: &Config) -> Pool {
    let timeout = c.dns.upstream_timeout.to_std();
    let bootstrap = bootstrap_addrs(&c.dns.bootstrap_dns);
    let tls = tls_config();

    let (bad_lines, entries) = {
        let (entries, bad) = addr::parse_list(c.dns.upstream_dns.iter().map(String::as_str));
        (bad, entries)
    };
    for (line, err) in bad_lines {
        tracing::warn!(upstream = %line, error = %err, "ignoring invalid upstream");
    }

    let (default_specs, group_specs) = pool::partition(entries);

    let connect = async |specs: Vec<addr::Upstream>| -> Vec<Arc<Client>> {
        let mut out = Vec::new();
        for s in specs {
            let label = s.original.clone();
            match Client::connect(s, &bootstrap, timeout, c.dns.bootstrap_prefer_ipv6, tls.clone())
                .await
            {
                Ok(cl) => out.push(Arc::new(cl)),
                Err(e) => tracing::warn!(upstream = %label, error = %e, "upstream unavailable"),
            }
        }

        out
    };

    let defaults = connect(default_specs).await;

    let mut groups = Vec::new();
    for (domains, specs) in group_specs {
        groups.push((domains, connect(specs).await));
    }

    let (fallback_entries, _) = addr::parse_list(c.dns.fallback_dns.iter().map(String::as_str));
    let (fallback_specs, _) = pool::partition(fallback_entries);
    let fallbacks = connect(fallback_specs).await;

    Pool::new(
        defaults,
        groups,
        fallbacks,
        match c.dns.upstream_mode {
            UpstreamMode::LoadBalance => Mode::LoadBalance,
            UpstreamMode::Parallel => Mode::Parallel,
            UpstreamMode::FastestAddr => Mode::FastestAddr,
        },
        timeout,
        c.dns.fastest_timeout.to_std(),
    )
}

/// Turns bootstrap specifications into plain socket addresses.
fn bootstrap_addrs(specs: &[String]) -> Vec<SocketAddr> {
    specs
        .iter()
        .filter_map(|s| {
            let e = addr::parse(s).ok()?;
            let u = e.upstream?;
            let ip: std::net::IpAddr = u.host.parse().ok()?;

            Some(SocketAddr::new(ip, u.port))
        })
        .collect()
}

/// Parses the address entries of the access lists, ignoring CIDRs and
/// ClientIDs, which are matched elsewhere.
fn parse_ips(v: &[String]) -> Vec<std::net::IpAddr> {
    v.iter().filter_map(|s| s.parse().ok()).collect()
}

/// Loads the configuration, writing a default one on a fresh installation.
pub fn load_or_init(paths: &Paths) -> Result<Config, Error> {
    if paths.is_first_run() {
        let c = Config::default();
        paths.ensure()?;
        agl_config::save(&paths.config, &c)?;

        return Ok(c);
    }

    Ok(agl_config::load(&paths.config)?)
}

/// A timeout used when downloading filter lists.
pub const LIST_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use agl_config::model::Rewrite;

    /// A config that binds nothing privileged.
    fn test_config() -> Config {
        let mut c = Config::default();
        c.dns.bind_hosts = vec!["127.0.0.1".parse().unwrap()];
        c.dns.port = 0;
        c.dns.upstream_dns = vec![];
        c.dns.bootstrap_dns = vec![];
        c.filters = vec![];

        c
    }

    fn tmp_paths(tag: &str) -> Paths {
        let base = std::env::temp_dir().join(format!("agl-app-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let p = Paths::new(base.join("work"), base.join("conf/AdGuardHome.yaml"));
        p.ensure().unwrap();

        p
    }

    #[test]
    fn settings_map_from_the_config() {
        let mut c = test_config();
        c.filtering.blocking_mode = CfgBlockingMode::Nxdomain;
        c.filtering.blocked_response_ttl = 42;
        c.dns.aaaa_disabled = true;
        c.dns.refuse_any = false;

        let s = settings(&c);
        assert_eq!(s.blocking.mode, BlockingMode::Nxdomain);
        assert_eq!(s.blocking.ttl, 42);
        assert!(s.aaaa_disabled);
        assert!(!s.refuse_any);
    }

    #[test]
    fn custom_ip_blocking_takes_the_configured_addresses() {
        let mut c = test_config();
        c.filtering.blocking_mode = CfgBlockingMode::CustomIp;
        c.filtering.blocking_ipv4 = "10.0.0.1".parse::<std::net::IpAddr>().unwrap().into();
        c.filtering.blocking_ipv6 = "::1".parse::<std::net::IpAddr>().unwrap().into();

        let s = settings(&c);
        assert_eq!(s.blocking.custom_v4.unwrap().to_string(), "10.0.0.1");
        assert_eq!(s.blocking.custom_v6.unwrap().to_string(), "::1");
    }

    #[test]
    fn a_disabled_cache_gets_a_zero_budget() {
        let mut c = test_config();
        c.dns.cache_enabled = false;
        assert_eq!(cache_config(&c).size_bytes, 0);

        c.dns.cache_enabled = true;
        c.dns.cache_size = 1024;
        assert_eq!(cache_config(&c).size_bytes, 1024);
    }

    #[test]
    fn bootstrap_specs_become_socket_addresses() {
        let got = bootstrap_addrs(&[
            "9.9.9.10".into(),
            "2620:fe::10".into(),
            "dns.example".into(),
            "1.1.1.1:5353".into(),
        ]);

        // The hostname is not usable as a bootstrap address and is dropped.
        assert_eq!(got.len(), 3);
        assert!(got.contains(&"9.9.9.10:53".parse().unwrap()));
        assert!(got.contains(&"[2620:fe::10]:53".parse().unwrap()));
        assert!(got.contains(&"1.1.1.1:5353".parse().unwrap()));
    }

    #[tokio::test]
    async fn builds_and_serves_on_an_ephemeral_port() {
        let paths = tmp_paths("serve");
        let mut c = test_config();
        c.dns.port = 0;

        let app = App::build_quiet(paths.clone(), c).await.unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let tasks = app.serve_dns(rx).await.unwrap();
        assert_eq!(tasks.len(), 2, "one UDP and one TCP listener");

        let _ = tx.send(true);
        std::fs::remove_dir_all(paths.work.parent().unwrap()).ok();
    }

    #[tokio::test]
    async fn rewrites_reach_the_resolver() {
        let paths = tmp_paths("rewrite");
        let mut c = test_config();
        c.filtering.rewrites = vec![Rewrite {
            domain: "nas.lan".into(),
            answer: "192.168.1.5".into(),
            enabled: true,
        }];

        let app = App::build_quiet(paths.clone(), c).await.unwrap();
        let mut req = hickory_proto::op::Message::query();
        req.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_utf8("nas.lan.").unwrap(),
            hickory_proto::rr::RecordType::A,
        ));

        let out = app
            .resolver
            .resolve(&req, agl_dns::resolver::Proto::Udp, &Default::default())
            .await;
        assert_eq!(out.reason, agl_core::Reason::Rewritten);

        std::fs::remove_dir_all(paths.work.parent().unwrap()).ok();
    }

    #[test]
    fn a_fresh_installation_writes_a_default_config() {
        let paths = tmp_paths("init");
        std::fs::remove_file(&paths.config).ok();
        assert!(paths.is_first_run());

        let c = load_or_init(&paths).unwrap();
        assert_eq!(c.schema_version, agl_core::SCHEMA_VERSION);
        assert!(!paths.is_first_run(), "the config should now exist");

        // And it must be readable back by the same parser.
        let again = load_or_init(&paths).unwrap();
        assert_eq!(again.dns.port, c.dns.port);

        std::fs::remove_dir_all(paths.work.parent().unwrap()).ok();
    }
}
