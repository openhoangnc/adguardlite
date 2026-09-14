//! Connecting the DNS server to the query log, the statistics collector and
//! the HTTP API.

use std::sync::Arc;
use std::time::Duration;

use agl_api::state::{FetchFuture, ListFetcher, Reloader};
use agl_config::{Config, Paths};
use agl_dns::resolver::Action;
use agl_dns::server::{Event, Observer};
use agl_filter::lists::Manager;
use agl_querylog::entry::{ClientProto, Entry, Result as EntryResult, ResultRule};
use agl_querylog::log::QueryLog;
use agl_stats::stats::Stats;
use agl_stats::unit::{Entry as StatEntry, Result as StatResult, UpstreamStat};

/// Feeds every handled query into the log and the statistics.
pub struct Recorder {
    /// The query log.
    pub querylog: Arc<QueryLog>,
    /// The statistics collector.
    pub stats: Arc<Stats>,
    /// Whether client addresses are anonymised.
    pub anonymize: std::sync::atomic::AtomicBool,
    /// Where unknown client addresses are sent to be named.
    discovery: parking_lot::RwLock<Option<crate::discovery::Queue>>,
    /// The store of names already known, so discovery is asked only once.
    runtime: parking_lot::RwLock<Option<Arc<agl_dns::clients::Runtime>>>,
    /// Feeds resolved addresses into the configured ipsets.
    ipset: parking_lot::RwLock<Option<Arc<crate::ipset::Manager>>>,
}

impl Recorder {
    /// Creates a recorder.
    pub fn new(querylog: Arc<QueryLog>, stats: Arc<Stats>, anonymize: bool) -> Self {
        Self {
            querylog,
            stats,
            anonymize: std::sync::atomic::AtomicBool::new(anonymize),
            discovery: parking_lot::RwLock::new(None),
            runtime: parking_lot::RwLock::new(None),
            ipset: parking_lot::RwLock::new(None),
        }
    }

    /// Connects the recorder to the ipset manager.
    ///
    /// The observer is the point where an answer is complete, which is where
    /// upstream adds the addresses too.
    pub fn set_ipset(&self, m: Option<Arc<crate::ipset::Manager>>) {
        *self.ipset.write() = m;
    }

    /// Connects the recorder to client discovery.
    ///
    /// Done after construction because discovery needs the resolver, which is
    /// built from this recorder.
    pub fn set_discovery(
        &self,
        queue: crate::discovery::Queue,
        runtime: Arc<agl_dns::clients::Runtime>,
    ) {
        *self.discovery.write() = Some(queue);
        *self.runtime.write() = Some(runtime);
    }

    /// Asks for a name for a client that has none yet.
    fn note_client(&self, addr: std::net::IpAddr) {
        let known = self
            .runtime
            .read()
            .as_ref()
            .is_some_and(|r| r.is_known(addr));
        if known {
            return;
        }

        if let Some(q) = self.discovery.read().as_ref() {
            q.submit(addr);
        }
    }
}

impl Observer for Recorder {
    fn observe(&self, ev: &Event<'_>) {
        use hickory_proto::serialize::binary::BinEncodable as _;
        use std::sync::atomic::Ordering;

        let Some(q) = ev.request.queries.first() else {
            return;
        };

        let host = q
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let client = if self.anonymize.load(Ordering::Relaxed) {
            anonymize_ip(ev.client.ip())
        } else {
            ev.client.ip().to_string()
        };

        let answer = match &ev.outcome.action {
            Action::Respond(m) => m.to_bytes().ok().map(|w| Entry::encode_answer(&w)),
            Action::Drop => None,
        };

        self.note_client(ev.client.ip());

        if let Some(m) = self.ipset.read().as_ref()
            && let Some(resp) = ev.outcome.response()
        {
            let addrs = agl_dns::resolver::answer_addrs(resp);
            let n = m.add(&host, &addrs);
            if n > 0 {
                tracing::debug!(host = %host, added = n, "ipset updated");
            }
        }

        let entry = Entry {
            time: agl_core::gotime::format_local(jiff::Timestamp::now()),
            question_host: host.clone(),
            question_type: q.query_type().to_string(),
            question_class: q.query_class().to_string(),
            req_ecs: ev.outcome.req_ecs.clone(),
            client_id: ev.outcome.client_id.clone(),
            client_proto: proto_of(ev.proto),
            upstream: ev.outcome.upstream.clone().unwrap_or_default(),
            answer,
            orig_answer: None,
            ip: client.clone(),
            result: EntryResult {
                service_name: ev.outcome.service_name.clone(),
                rules: ev
                    .outcome
                    .rules
                    .iter()
                    .map(|r| ResultRule {
                        text: r.text.clone(),
                        ip: r.ip,
                        filter_list_id: r.list_id,
                    })
                    .collect(),
                reason: ev.outcome.reason,
                is_filtered: ev.outcome.reason.is_filtered(),
                ..Default::default()
            },
            elapsed: ev.outcome.elapsed.as_nanos().min(u128::from(u64::MAX)) as u64,
            cached: ev.outcome.cached,
            authenticated_data: ev
                .outcome
                .response()
                .is_some_and(|m| m.metadata.authentic_data),
        };

        // A client may ask to be left out of one or both records.
        if !ev.outcome.ignore_querylog {
            self.querylog.push(entry);
        }

        if ev.outcome.ignore_statistics {
            return;
        }

        let upstreams = ev
            .outcome
            .upstream
            .as_ref()
            .map(|a| {
                vec![UpstreamStat {
                    address: a.clone(),
                    duration: ev.outcome.elapsed,
                    cached: ev.outcome.cached,
                    failed: false,
                }]
            })
            .unwrap_or_default();

        self.stats.add(&StatEntry {
            client,
            domain: host,
            result: StatResult::from_reason(ev.outcome.reason),
            processing_time: ev.outcome.elapsed,
            upstreams,
        });
    }
}

/// Masks a client address for the query log, as `anonymize_client_ip` does.
fn anonymize_ip(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();

            std::net::Ipv4Addr::new(o[0], o[1], o[2], 0).to_string()
        }
        std::net::IpAddr::V6(a) => {
            let mut o = a.octets();
            o[8..].fill(0);

            std::net::Ipv6Addr::from(o).to_string()
        }
    }
}

/// Maps a transport onto the query log's `CP` value.
fn proto_of(p: agl_dns::resolver::Proto) -> ClientProto {
    use agl_dns::resolver::Proto;

    match p {
        Proto::Udp | Proto::Tcp => ClientProto::Plain,
        Proto::Tls => ClientProto::Dot,
        Proto::Https => ClientProto::Doh,
        Proto::Quic => ClientProto::Doq,
    }
}

/// Downloads filter lists on the API's behalf.
pub struct Downloader {
    /// Where lists are stored.
    pub paths: Paths,
    /// The largest list this will accept.
    pub max_bytes: u64,
    /// How long a download may take.
    pub timeout: Duration,
}

impl ListFetcher for Downloader {
    fn fetch(&self, url: String) -> FetchFuture {
        let paths = self.paths.clone();
        let max = self.max_bytes;
        let timeout = self.timeout;

        Box::pin(async move {
            crate::lists::fetch(&paths, &url, max, timeout)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

/// The announcement document AdGuard publishes for the stable channel.
const VERSION_URL: &str = "https://static.adtidy.org/adguardhome/release/version.json";

/// How large an announcement may be.
const VERSION_MAX_BYTES: u64 = 64 * 1024;

/// How long a version check may take.
const VERSION_TIMEOUT: Duration = Duration::from_secs(10);

/// Reports what the latest AdGuard Home release is.
///
/// The announcement is only read, never acted on: this build cannot replace
/// itself with an AdGuard Home release, so the interface is told a new version
/// exists but not offered a button to install it.
pub struct ReleaseChecker {
    /// Whether `--no-check-update` was given.
    pub disabled: bool,
}

impl agl_api::state::VersionChecker for ReleaseChecker {
    fn fetch(&self) -> agl_api::state::VersionFuture {
        Box::pin(async move {
            let body = crate::fetch::get(VERSION_URL, VERSION_MAX_BYTES, VERSION_TIMEOUT)
                .await
                .map_err(|e| e.to_string())?;

            String::from_utf8(body).map_err(|e| e.to_string())
        })
    }

    fn disabled(&self) -> bool {
        self.disabled
    }
}

/// Pushes configuration changes into the running server.
pub struct LiveReloader {
    /// The resolver to reconfigure.
    pub resolver: Arc<agl_dns::resolver::Resolver>,
    /// The listener front end, for access control and the concurrency bound.
    pub server: Arc<agl_dns::server::Server>,
    /// The certificate the encrypted listeners serve.
    pub certificate: Arc<agl_dns::tls::Reloadable>,
}

impl Reloader for LiveReloader {
    fn reload(&self, cfg: &Config) {
        self.resolver.set_settings(crate::app::settings(cfg));
        self.resolver.set_rewrites(agl_dns::rewrite::Table::build(
            cfg.filtering
                .rewrites
                .iter()
                .map(|r| (r.domain.as_str(), r.answer.as_str(), r.enabled)),
        ));
        self.resolver.set_clients(crate::app::clients(cfg));
        self.resolver
            .set_safe_search(agl_filter::safesearch::engine(&crate::app::safe_search(
                &cfg.filtering.safe_search,
            )));
        self.resolver
            .runtime
            .set_sources(agl_dns::clients::Sources {
                whois: cfg.clients.runtime_sources.whois,
                arp: cfg.clients.runtime_sources.arp,
                rdns: cfg.clients.runtime_sources.rdns,
                dhcp: false,
                hosts: cfg.clients.runtime_sources.hosts,
            });
        self.server.set_max_concurrent(cfg.dns.max_goroutines);
        self.reload_certificate(cfg);
        *self.server.access.write() = agl_dns::server::Access {
            allowed: cfg
                .dns
                .allowed_clients
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
            disallowed: cfg
                .dns
                .disallowed_clients
                .iter()
                .filter_map(|s| s.parse().ok())
                .collect(),
        };
    }

    fn reload_filters(&self, filters: &Manager) {
        self.resolver.set_engine(filters.build_engine());
        self.resolver.set_services(filters.build_services_engine());
    }
}

impl LiveReloader {
    /// Installs the configured certificate into the running listeners.
    ///
    /// Only the certificate is live-reloadable: which ports are bound is
    /// decided when the listeners start, so changing a port still needs a
    /// restart.
    fn reload_certificate(&self, cfg: &Config) {
        let src = agl_dns::tls::Source {
            certificate_chain: cfg.tls.certificate_chain.clone(),
            private_key: cfg.tls.private_key.clone(),
            certificate_path: cfg.tls.certificate_path.clone(),
            private_key_path: cfg.tls.private_key_path.clone(),
        };

        if !cfg.tls.enabled || src.is_empty() {
            return;
        }

        match agl_dns::tls::install(&src, &self.certificate) {
            Ok(st) => tracing::info!(names = ?st.dns_names, "certificate reloaded"),
            Err(e) => tracing::error!(error = %e, "reloading the certificate"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymisation_masks_the_host_part() {
        assert_eq!(anonymize_ip("192.168.1.77".parse().unwrap()), "192.168.1.0");
        assert_eq!(
            anonymize_ip("2001:db8::dead:beef".parse().unwrap()),
            "2001:db8::"
        );
    }

    #[test]
    fn protocols_map_onto_the_log_field() {
        use agl_dns::resolver::Proto;

        assert_eq!(proto_of(Proto::Udp), ClientProto::Plain);
        assert_eq!(proto_of(Proto::Tcp), ClientProto::Plain);
        assert_eq!(proto_of(Proto::Tls), ClientProto::Dot);
        assert_eq!(proto_of(Proto::Https), ClientProto::Doh);
        assert_eq!(proto_of(Proto::Quic), ClientProto::Doq);
    }
}
