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
}

impl Recorder {
    /// Creates a recorder.
    pub fn new(querylog: Arc<QueryLog>, stats: Arc<Stats>, anonymize: bool) -> Self {
        Self {
            querylog,
            stats,
            anonymize: std::sync::atomic::AtomicBool::new(anonymize),
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

        let entry = Entry {
            time: agl_core::gotime::format_local(jiff::Timestamp::now()),
            question_host: host.clone(),
            question_type: q.query_type().to_string(),
            question_class: q.query_class().to_string(),
            req_ecs: String::new(),
            client_id: String::new(),
            client_proto: proto_of(ev.proto),
            upstream: ev.outcome.upstream.clone().unwrap_or_default(),
            answer,
            orig_answer: None,
            ip: client.clone(),
            result: EntryResult {
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

        self.querylog.push(entry);

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

/// Pushes configuration changes into the running server.
pub struct LiveReloader {
    /// The resolver to reconfigure.
    pub resolver: Arc<agl_dns::resolver::Resolver>,
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
    }

    fn reload_filters(&self, filters: &Manager) {
        self.resolver.set_engine(filters.build_engine());
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
