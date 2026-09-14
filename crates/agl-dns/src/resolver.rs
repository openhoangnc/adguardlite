//! Request handling: validation, filtering, rewrites, cache, upstreams.
//!
//! The order of steps mirrors `internal/dnsforward`, because the order is
//! observable: a rewrite applies even when protection is off, an allowlist
//! match short-circuits filtering, and an access-blocked host is dropped
//! outright on UDP rather than answered.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agl_core::Reason;
use agl_filter::engine::{Engine, MatchedRule, Request as FilterRequest};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use parking_lot::RwLock;

use crate::cache::{Cache, Freshness, Key};
use crate::msg::{self, BlockingConfig};
use crate::pool::SharedPool;
use crate::rewrite::{self, Table};

/// The transport a request arrived on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS-over-TLS.
    Tls,
    /// DNS-over-HTTPS.
    Https,
    /// DNS-over-QUIC.
    Quic,
}

impl Proto {
    /// The value written to the query log's `CP` field.
    pub const fn log_name(self) -> &'static str {
        match self {
            // Upstream writes an empty string for plain DNS.
            Proto::Udp | Proto::Tcp => "",
            Proto::Tls => "tls",
            Proto::Https => "doh",
            Proto::Quic => "doq",
        }
    }

    /// Reports whether the transport is connectionless, and therefore
    /// spoofable for amplification.
    pub const fn is_datagram(self) -> bool {
        matches!(self, Proto::Udp)
    }
}

/// Settings that affect how a query is handled.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The master protection switch.
    pub protection_enabled: bool,
    /// Whether blocklists are consulted.
    pub filtering_enabled: bool,
    /// Whether rewrites are applied.
    pub rewrites_enabled: bool,
    /// How blocked queries are answered.
    pub blocking: BlockingConfig,
    /// Hosts refused before any other processing.
    pub blocked_hosts: Vec<String>,
    /// Whether `AAAA` queries are answered with nothing.
    pub aaaa_disabled: bool,
    /// Whether `ANY` queries are refused.
    pub refuse_any: bool,
    /// Lower bound applied to answer TTLs.
    pub cache_ttl_min: u32,
    /// Upper bound applied to answer TTLs.
    pub cache_ttl_max: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            protection_enabled: true,
            filtering_enabled: true,
            rewrites_enabled: true,
            blocking: BlockingConfig::default(),
            blocked_hosts: vec![
                "version.bind".into(),
                "id.server".into(),
                "hostname.bind".into(),
            ],
            aaaa_disabled: false,
            refuse_any: true,
            cache_ttl_min: 0,
            cache_ttl_max: 0,
        }
    }
}

/// What the server should do with a request.
#[derive(Debug)]
pub enum Action {
    /// Send this response.
    Respond(Box<Message>),
    /// Send nothing, to avoid amplifying a spoofed request.
    Drop,
}

/// Everything the query log and statistics need about one request.
#[derive(Debug)]
pub struct Outcome {
    /// What to do with the request.
    pub action: Action,
    /// Why the request was filtered, allowed or rewritten.
    pub reason: Reason,
    /// The rules that matched.
    pub rules: Vec<MatchedRule>,
    /// The upstream that answered, if any.
    pub upstream: Option<String>,
    /// Whether the answer came from the cache.
    pub cached: bool,
    /// How long handling took.
    pub elapsed: Duration,
    /// The upstream's original answer, when filtering replaced it.
    pub orig_response: Option<Box<Message>>,
}

impl Outcome {
    /// The response, if one is being sent.
    pub fn response(&self) -> Option<&Message> {
        match &self.action {
            Action::Respond(m) => Some(m),
            Action::Drop => None,
        }
    }
}

/// Details of the client a request came from.
#[derive(Clone, Debug, Default)]
pub struct ClientInfo {
    /// The client's address.
    pub addr: Option<IpAddr>,
    /// The client's name or ClientID.
    pub name: Option<String>,
    /// The client's tags.
    pub tags: Vec<String>,
}

/// The DNS resolver.
pub struct Resolver {
    /// The filtering engine, replaceable while running.
    engine: RwLock<Arc<Engine>>,
    /// The rewrite table, replaceable while running.
    rewrites: RwLock<Arc<Table>>,
    /// The response cache.
    pub cache: Cache,
    /// The upstream pool.
    pub pool: SharedPool,
    /// Handling settings, replaceable while running.
    settings: RwLock<Arc<Settings>>,
}

impl Resolver {
    /// Builds a resolver.
    pub fn new(
        engine: Engine,
        rewrites: Table,
        cache: Cache,
        pool: SharedPool,
        settings: Settings,
    ) -> Self {
        Self {
            engine: RwLock::new(Arc::new(engine)),
            rewrites: RwLock::new(Arc::new(rewrites)),
            cache,
            pool,
            settings: RwLock::new(Arc::new(settings)),
        }
    }

    /// Replaces the filtering engine.
    pub fn set_engine(&self, e: Engine) {
        *self.engine.write() = Arc::new(e);
    }

    /// Replaces the rewrite table.
    pub fn set_rewrites(&self, t: Table) {
        *self.rewrites.write() = Arc::new(t);
    }

    /// Replaces the settings.
    pub fn set_settings(&self, s: Settings) {
        *self.settings.write() = Arc::new(s);
    }

    /// A snapshot of the current settings.
    pub fn settings(&self) -> Arc<Settings> {
        self.settings.read().clone()
    }

    /// A snapshot of the current filtering engine.
    pub fn engine(&self) -> Arc<Engine> {
        self.engine.read().clone()
    }

    /// Handles one request.
    pub async fn resolve(&self, req: &Message, proto: Proto, client: &ClientInfo) -> Outcome {
        let started = Instant::now();
        let settings = self.settings();

        let done = |action, reason, rules, upstream, cached, orig| Outcome {
            action,
            reason,
            rules,
            upstream,
            cached,
            elapsed: started.elapsed(),
            orig_response: orig,
        };

        // 1. Validate.  A request without exactly one question is malformed.
        if req.queries.len() != 1 {
            let resp = msg::reply(req, ResponseCode::FormErr);

            return done(
                Action::Respond(Box::new(resp)),
                Reason::FilteredInvalid,
                vec![],
                None,
                false,
                None,
            );
        }

        let q = &req.queries[0];
        let qtype = q.query_type();
        let host = q
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();

        // 2. `ANY` queries are refused as an amplification guard.
        if settings.refuse_any && qtype == RecordType::ANY {
            let resp = msg::reply(req, ResponseCode::NotImp);

            return done(
                Action::Respond(Box::new(resp)),
                Reason::NotFilteredNotFound,
                vec![],
                None,
                false,
                None,
            );
        }

        // 3. Access-blocked hosts.  On UDP the request is dropped rather than
        //    answered, so a spoofed source address gains nothing.
        if is_blocked_host(&settings.blocked_hosts, &host) {
            let action = if proto.is_datagram() {
                Action::Drop
            } else {
                Action::Respond(Box::new(msg::refused(req)))
            };

            return done(action, Reason::FilteredBlockList, vec![], None, false, None);
        }

        // 4. Rewrites, which apply even when protection is off.
        if settings.rewrites_enabled
            && let Some(outcome) = self.apply_rewrites(req, &host, qtype, &settings)
        {
            return done(outcome.0, Reason::Rewritten, outcome.1, None, false, None);
        }

        // 5. Filtering.
        //
        // An allowlist match does not stop resolution, but it *is* the
        // query's verdict: upstream records the `@@` rule and reason 1
        // alongside the upstream answer, and the UI shows the query as
        // explicitly allowed.
        let mut allowed: Option<(Reason, Vec<MatchedRule>)> = None;

        if settings.protection_enabled && settings.filtering_enabled {
            let engine = self.engine();
            let m = engine.match_request(&FilterRequest {
                hostname: &host,
                qtype: qtype.into(),
                client_ip: client.addr,
                client_name: client.name.as_deref(),
                client_tags: &client.tags,
            });

            match m.reason {
                Reason::FilteredBlockList
                | Reason::FilteredSafeBrowsing
                | Reason::FilteredParental
                | Reason::FilteredBlockedService => {
                    let addrs: Vec<IpAddr> = m.rules.iter().filter_map(|r| r.ip).collect();
                    let resp = msg::blocked(req, &settings.blocking, &addrs);
                    let reason = reason_for_list(m.reason, &m.rules);

                    return done(
                        Action::Respond(Box::new(resp)),
                        reason,
                        m.rules,
                        None,
                        false,
                        None,
                    );
                }
                Reason::RewrittenRule => {
                    if let Some(resp) = self.apply_dnsrewrite(req, qtype, &m.rewrites, &settings) {
                        return done(
                            Action::Respond(Box::new(resp)),
                            Reason::RewrittenRule,
                            m.rules,
                            None,
                            false,
                            None,
                        );
                    }
                }
                Reason::NotFilteredAllowList => {
                    allowed = Some((Reason::NotFilteredAllowList, m.rules));
                }
                _ => {}
            }
        }

        // 6. `AAAA` suppression.
        if settings.aaaa_disabled && qtype == RecordType::AAAA {
            let resp = msg::nodata(req, settings.blocking.ttl);
            let (reason, rules) = allowed.clone().unwrap_or_default();

            return done(
                Action::Respond(Box::new(resp)),
                reason,
                rules,
                None,
                false,
                None,
            );
        }

        // 7. Cache.
        let key = Key::from_request(req).filter(|_| crate::cache::is_cacheable_type(qtype));
        if let Some(k) = &key
            && let Some((mut cached, freshness)) = self.cache.get(k)
        {
            cached.metadata.id = req.metadata.id;
            if freshness == Freshness::Fresh {
                let (reason, rules) = allowed.clone().unwrap_or_default();

                return done(
                    Action::Respond(Box::new(cached)),
                    reason,
                    rules,
                    None,
                    true,
                    None,
                );
            }
        }

        // 8. Upstream.
        let pool = self.pool.load();
        match pool.exchange(req, &host).await {
            Ok(mut resp) => {
                resp.metadata.id = req.metadata.id;
                msg::clamp_ttls(&mut resp, settings.cache_ttl_min, settings.cache_ttl_max);

                if let Some(k) = key {
                    self.cache.put(k, &resp);
                }

                let upstream = pool
                    .select(&host)
                    .first()
                    .map(|m| m.client.upstream.label());
                let (reason, rules) = allowed.unwrap_or_default();

                done(
                    Action::Respond(Box::new(resp)),
                    reason,
                    rules,
                    upstream,
                    false,
                    None,
                )
            }
            Err(_) => {
                let (reason, rules) = allowed.unwrap_or_default();

                done(
                    Action::Respond(Box::new(msg::servfail(req))),
                    reason,
                    rules,
                    None,
                    false,
                    None,
                )
            }
        }
    }

    /// Applies the legacy rewrite table, if it matches.
    fn apply_rewrites(
        &self,
        req: &Message,
        host: &str,
        qtype: RecordType,
        settings: &Settings,
    ) -> Option<(Action, Vec<MatchedRule>)> {
        let table = self.rewrites.read().clone();
        let (outcome, matched) = table.apply(host, qtype)?;

        let rules: Vec<MatchedRule> = matched
            .iter()
            .map(|r| MatchedRule {
                text: format!("{} -> {}", r.domain, r.answer_text),
                list_id: 0,
                ip: None,
            })
            .collect();

        let ttl = settings.blocking.ttl.max(1);
        let resp = match outcome {
            rewrite::Outcome::Addrs(addrs) => msg::with_addrs(req, &addrs, ttl),
            rewrite::Outcome::CName(c) => msg::with_cname(req, &c, &[], ttl),
            rewrite::Outcome::Empty => msg::nodata(req, ttl),
        };

        Some((Action::Respond(Box::new(resp)), rules))
    }

    /// Builds a response from `$dnsrewrite` rules.
    fn apply_dnsrewrite(
        &self,
        req: &Message,
        qtype: RecordType,
        rewrites: &[agl_filter::rule::DnsRewrite],
        settings: &Settings,
    ) -> Option<Message> {
        use agl_filter::rule::DnsRewrite as R;

        let ttl = settings.blocking.ttl.max(1);

        // A response code wins over anything else.
        if let Some(R::RCode(rc)) = rewrites.iter().find(|r| matches!(r, R::RCode(_))) {
            let code = ResponseCode::from(0, *rc as u8);
            let mut resp = msg::reply(req, code);
            if code == ResponseCode::NXDomain {
                resp.authorities = vec![msg::soa_record(req, ttl)];
            }

            return Some(resp);
        }

        if let Some(R::CName(c)) = rewrites.iter().find(|r| matches!(r, R::CName(_))) {
            return Some(msg::with_cname(req, c, &[], ttl));
        }

        let addrs: Vec<IpAddr> = rewrites
            .iter()
            .filter_map(|r| match r {
                R::Addr(ip) => Some(*ip),
                _ => None,
            })
            .filter(|ip| match qtype {
                RecordType::A => ip.is_ipv4(),
                RecordType::AAAA => ip.is_ipv6(),
                _ => false,
            })
            .collect();

        if !addrs.is_empty() {
            return Some(msg::with_addrs(req, &addrs, ttl));
        }

        // Arbitrary record rewrites are matched but produce no answer here.
        rewrites
            .iter()
            .any(|r| matches!(r, R::Record { .. }))
            .then(|| msg::nodata(req, ttl))
    }
}

/// The list identifier for rules derived from the system hosts file.
const ETC_HOSTS_LIST_ID: i64 = -1;

/// The list identifier for the blocked-services rules.
const BLOCKED_SERVICE_LIST_ID: i64 = -2;

/// Refines a filtering reason using the list the winning rule came from.
///
/// The engine reports every blocking match as a blocklist match; upstream
/// distinguishes the built-in lists by their reserved identifiers, and the web
/// UI labels a query by that reason.
fn reason_for_list(reason: Reason, rules: &[MatchedRule]) -> Reason {
    let Some(first) = rules.first() else {
        return reason;
    };

    match first.list_id {
        BLOCKED_SERVICE_LIST_ID => Reason::FilteredBlockedService,
        ETC_HOSTS_LIST_ID => Reason::RewrittenAutoHosts,
        _ => reason,
    }
}

/// Reports whether `host` is in the access blocklist.
///
/// Entries match the host itself and any subdomain, as upstream's rule engine
/// does for bare domain rules.
fn is_blocked_host(blocked: &[String], host: &str) -> bool {
    blocked
        .iter()
        .any(|b| agl_core::name::is_subdomain_of(host, &b.to_ascii_lowercase()))
}

/// Extracts the addresses from a response, for statistics and DNS64.
pub fn answer_addrs(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::Config as CacheConfig;
    use crate::pool::{Mode, Pool};
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;

    fn request(name: &str, qt: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.id = 0x1111;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), qt));

        m
    }

    /// A resolver with no upstreams, so anything reaching step 8 fails loudly.
    fn resolver(block_rules: &str, rewrites: Table, settings: Settings) -> Resolver {
        Resolver::new(
            Engine::build([(1i64, block_rules)], []),
            rewrites,
            Cache::new(CacheConfig::default()),
            SharedPool::new(Pool::new(
                vec![],
                vec![],
                vec![],
                Mode::LoadBalance,
                Duration::from_millis(50),
                Duration::from_millis(50),
            )),
            settings,
        )
    }

    async fn resolve(r: &Resolver, name: &str, qt: RecordType, proto: Proto) -> Outcome {
        r.resolve(&request(name, qt), proto, &ClientInfo::default())
            .await
    }

    #[tokio::test]
    async fn blocks_a_filtered_host_with_a_null_address() {
        let r = resolver(
            "||ads.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "ads.example.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockList);
        let resp = out.response().unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            answer_addrs(resp),
            vec!["0.0.0.0".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(out.rules.len(), 1);
    }

    #[tokio::test]
    async fn a_malformed_question_count_gets_formerr() {
        let r = resolver("", Table::default(), Settings::default());
        let mut req = Message::query();
        req.metadata.id = 7;
        let out = r.resolve(&req, Proto::Udp, &ClientInfo::default()).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::FormErr
        );
        assert_eq!(out.reason, Reason::FilteredInvalid);
    }

    #[tokio::test]
    async fn any_queries_are_refused_when_configured() {
        let r = resolver("", Table::default(), Settings::default());
        let out = resolve(&r, "example.com.", RecordType::ANY, Proto::Udp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::NotImp
        );

        let s = Settings {
            refuse_any: false,
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);
        let out = resolve(&r, "example.com.", RecordType::ANY, Proto::Udp).await;
        // Falls through to the upstream step, which has no upstreams.
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn access_blocked_hosts_are_dropped_on_udp_and_refused_on_tcp() {
        let r = resolver("", Table::default(), Settings::default());

        let out = resolve(&r, "version.bind.", RecordType::TXT, Proto::Udp).await;
        assert!(
            matches!(out.action, Action::Drop),
            "UDP must not be answered"
        );

        let out = resolve(&r, "version.bind.", RecordType::TXT, Proto::Tcp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::Refused
        );
    }

    #[tokio::test]
    async fn rewrites_apply_before_filtering() {
        let t = Table::build([("nas.lan", "192.168.1.5", true)]);
        let r = resolver("||nas.lan^\n", t, Settings::default());
        let out = resolve(&r, "nas.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::Rewritten);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["192.168.1.5".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn rewrites_apply_even_with_protection_off() {
        let t = Table::build([("nas.lan", "192.168.1.5", true)]);
        let s = Settings {
            protection_enabled: false,
            ..Default::default()
        };
        let r = resolver("", t, s);
        let out = resolve(&r, "nas.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::Rewritten);
    }

    #[tokio::test]
    async fn protection_off_disables_blocking() {
        let s = Settings {
            protection_enabled: false,
            ..Default::default()
        };
        let r = resolver("||ads.example.com^\n", Table::default(), s);
        let out = resolve(&r, "ads.example.com.", RecordType::A, Proto::Udp).await;
        assert_ne!(out.reason, Reason::FilteredBlockList);
    }

    #[tokio::test]
    async fn allowlisted_hosts_are_resolved_not_blocked() {
        let r = resolver(
            "||example.com^\n@@||good.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "good.example.com.", RecordType::A, Proto::Udp).await;
        // No upstream is configured, so it reaches SERVFAIL rather than being blocked.
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
    }

    #[tokio::test]
    async fn an_allowlist_match_stays_the_recorded_verdict() {
        // Upstream writes the `@@` rule and reason 1 into the query log even
        // though the query is then resolved normally, and the UI relies on it.
        let r = resolver(
            "||example.com^\n@@||good.example.com^\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "good.example.com.", RecordType::A, Proto::Udp).await;

        assert_eq!(out.reason, Reason::NotFilteredAllowList);
        assert_eq!(out.rules.len(), 1);
        assert_eq!(out.rules[0].text, "@@||good.example.com^");
    }

    #[tokio::test]
    async fn an_unmatched_query_records_no_rules() {
        let r = resolver("||example.com^\n", Table::default(), Settings::default());
        let out = resolve(&r, "unrelated.org.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::NotFilteredNotFound);
        assert!(out.rules.is_empty());
    }

    #[tokio::test]
    async fn aaaa_can_be_suppressed() {
        let s = Settings {
            aaaa_disabled: true,
            ..Default::default()
        };
        let r = resolver("", Table::default(), s);
        let out = resolve(&r, "example.com.", RecordType::AAAA, Proto::Udp).await;
        let resp = out.response().unwrap();
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
    }

    #[tokio::test]
    async fn dnsrewrite_rules_synthesise_answers() {
        let r = resolver(
            "||a.example.com^$dnsrewrite=1.2.3.4\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::RewrittenRule);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn dnsrewrite_can_force_a_response_code() {
        let r = resolver(
            "||a.example.com^$dnsrewrite=REFUSED\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "a.example.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(
            out.response().unwrap().metadata.response_code,
            ResponseCode::Refused
        );
    }

    #[tokio::test]
    async fn hosts_rules_answer_with_their_own_address() {
        let r = resolver(
            "192.168.1.7 printer.lan\n",
            Table::default(),
            Settings::default(),
        );
        let out = resolve(&r, "printer.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockList);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["192.168.1.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn a_blocked_service_is_reported_as_such() {
        // The blocked-services rules carry the reserved list identifier, and
        // the UI labels the query by the reason that implies.
        let r = resolver("", Table::default(), Settings::default());
        r.set_engine(Engine::build([(-2i64, "||youtube.com^")], []));

        let out = resolve(&r, "www.youtube.com.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::FilteredBlockedService);
    }

    #[tokio::test]
    async fn a_hosts_file_entry_is_reported_as_a_rewrite() {
        let r = resolver("", Table::default(), Settings::default());
        r.set_engine(Engine::build([(-1i64, "192.168.1.7 printer.lan")], []));

        let out = resolve(&r, "printer.lan.", RecordType::A, Proto::Udp).await;
        assert_eq!(out.reason, Reason::RewrittenAutoHosts);
        assert_eq!(
            answer_addrs(out.response().unwrap()),
            vec!["192.168.1.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn blocked_host_matching_covers_subdomains() {
        let b = vec!["version.bind".to_string()];
        assert!(is_blocked_host(&b, "version.bind"));
        assert!(is_blocked_host(&b, "sub.version.bind"));
        assert!(!is_blocked_host(&b, "notversion.bind"));
    }

    #[test]
    fn protocol_log_names_match_upstream() {
        assert_eq!(Proto::Udp.log_name(), "");
        assert_eq!(Proto::Tcp.log_name(), "");
        assert_eq!(Proto::Tls.log_name(), "tls");
        assert_eq!(Proto::Https.log_name(), "doh");
        assert_eq!(Proto::Quic.log_name(), "doq");
    }
}
