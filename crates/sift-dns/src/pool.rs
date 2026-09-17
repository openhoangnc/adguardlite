//! Upstream selection: which resolvers to ask, and how.
//!
//! Mirrors `upstream_mode` from the config:
//!
//!   * `load_balance` — ask one upstream, preferring ones that have been
//!     answering quickly;
//!   * `parallel` — ask all of them and take the first good answer;
//!   * `fastest_addr` — ask all of them, then probe the addresses they return
//!     and answer with the one that connects fastest.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, RecordType};
use parking_lot::RwLock;

use crate::addr::{Upstream, UpstreamEntry};
use crate::client::{Client, Error, is_failure};

/// How upstreams are chosen for a query.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mode {
    /// Prefer the upstream that has been answering fastest.
    #[default]
    LoadBalance,
    /// Ask every upstream and take the first good answer.
    Parallel,
    /// Ask every upstream, then return the fastest-connecting address.
    FastestAddr,
}

/// One upstream plus the statistics used to rank it.
#[derive(Debug)]
pub struct Member {
    /// The client to send through.
    pub client: Arc<Client>,
    /// An exponentially weighted mean round-trip time, in microseconds.
    rtt_ewma_us: AtomicU64,
    /// Consecutive failures, used to back off from a dead upstream.
    failures: AtomicU64,
}

impl Member {
    /// Wraps a client with fresh statistics.
    pub fn new(client: Arc<Client>) -> Self {
        Self {
            client,
            // Start optimistic so a new upstream gets tried.
            rtt_ewma_us: AtomicU64::new(20_000),
            failures: AtomicU64::new(0),
        }
    }

    /// Folds a successful exchange's latency into the mean.
    fn record_success(&self, rtt: Duration) {
        let sample = rtt.as_micros().min(u128::from(u64::MAX)) as u64;
        let prev = self.rtt_ewma_us.load(Ordering::Relaxed);
        // A 1/4 weight on the new sample: responsive but not jumpy.
        let next = prev - prev / 4 + sample / 4;
        self.rtt_ewma_us.store(next.max(1), Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
    }

    /// Records a failure, penalising the upstream's ranking.
    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// The ranking score; lower is better.
    fn score(&self) -> u64 {
        let rtt = self.rtt_ewma_us.load(Ordering::Relaxed);
        let fails = self.failures.load(Ordering::Relaxed).min(8);

        // Each consecutive failure doubles the effective cost.
        rtt.saturating_mul(1u64 << fails)
    }

    /// The mean round-trip time observed so far.
    pub fn mean_rtt(&self) -> Duration {
        Duration::from_micros(self.rtt_ewma_us.load(Ordering::Relaxed))
    }
}

/// A group of upstreams serving a set of domains.
#[derive(Debug)]
pub struct Group {
    /// The domains this group serves; empty means all.
    pub domains: Vec<String>,
    /// The upstreams in the group.
    pub members: Vec<Arc<Member>>,
}

impl Group {
    /// Reports whether this group should handle `host`.
    ///
    /// An empty domain in the list is the `[//]` form, which matches only
    /// unqualified names.
    fn matches(&self, host: &str) -> Option<usize> {
        let mut best: Option<usize> = None;
        for d in &self.domains {
            let hit = if d.is_empty() {
                !host.contains('.')
            } else {
                sift_core::name::is_subdomain_of(host, d)
            };

            if hit {
                // Prefer the most specific domain that matched.
                best = Some(best.map_or(d.len(), |b| b.max(d.len())));
            }
        }

        best
    }
}

/// The configured upstreams and how to choose among them.
#[derive(Debug)]
pub struct Pool {
    /// Upstreams used when no domain-specific group matches.
    defaults: Vec<Arc<Member>>,
    /// Domain-specific groups.
    groups: Vec<Group>,
    /// Upstreams tried when the selected ones all fail.
    fallbacks: Vec<Arc<Member>>,
    /// How to choose among the selected upstreams.
    pub mode: Mode,
    /// How long to wait for an upstream.
    pub timeout: Duration,
    /// How long to probe addresses for in `fastest_addr` mode.
    pub fastest_timeout: Duration,
}

impl Pool {
    /// Builds a pool from resolved clients.
    pub fn new(
        defaults: Vec<Arc<Client>>,
        groups: Vec<(Vec<String>, Vec<Arc<Client>>)>,
        fallbacks: Vec<Arc<Client>>,
        mode: Mode,
        timeout: Duration,
        fastest_timeout: Duration,
    ) -> Self {
        let wrap = |v: Vec<Arc<Client>>| -> Vec<Arc<Member>> {
            v.into_iter().map(|c| Arc::new(Member::new(c))).collect()
        };

        Self {
            defaults: wrap(defaults),
            groups: groups
                .into_iter()
                .map(|(domains, cs)| Group {
                    domains,
                    members: wrap(cs),
                })
                .collect(),
            fallbacks: wrap(fallbacks),
            mode,
            timeout,
            fastest_timeout,
        }
    }

    /// Reports whether the pool has no usable upstream.
    pub fn is_empty(&self) -> bool {
        self.defaults.is_empty() && self.groups.is_empty()
    }

    /// The default upstreams.
    pub fn defaults(&self) -> &[Arc<Member>] {
        &self.defaults
    }

    /// Chooses the upstreams for a query name, preferring the most specific
    /// domain-specific group.
    pub fn select(&self, host: &str) -> &[Arc<Member>] {
        let mut best: Option<(usize, &Group)> = None;
        for g in &self.groups {
            if let Some(len) = g.matches(host)
                && best.is_none_or(|(b, _)| len > b)
            {
                best = Some((len, g));
            }
        }

        match best {
            // A group with no members is the `[/domain/]#` form: fall through
            // to the defaults for that domain.
            Some((_, g)) if !g.members.is_empty() => &g.members,
            _ => &self.defaults,
        }
    }

    /// Resolves a query against the appropriate upstreams.
    ///
    /// Reports the upstream that actually answered alongside the answer.  The
    /// caller cannot work it out for itself: every mode but a single-member
    /// `load_balance` may answer from any of them, and it is this upstream —
    /// not the first one configured — that the query log and the per-upstream
    /// statistics are meant to name, as `proxy.exchangeUpstreams` does.
    pub async fn exchange(
        &self,
        req: &Message,
        host: &str,
    ) -> Result<(Message, Arc<Member>), Error> {
        let members = self.select(host);
        if members.is_empty() {
            return Err(Error::Unsupported("no upstreams configured".into()));
        }

        let r = match self.mode {
            Mode::LoadBalance => self.exchange_load_balance(req, members).await,
            Mode::Parallel => self.exchange_parallel(req, members).await,
            Mode::FastestAddr => self.exchange_fastest_addr(req, members).await,
        };

        match r {
            Ok(resp) => Ok(resp),
            Err(e) if !self.fallbacks.is_empty() => {
                match self.exchange_parallel(req, &self.fallbacks).await {
                    Ok(won) => Ok(won),
                    Err(_) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Tries upstreams one at a time, best-ranked first.
    async fn exchange_load_balance(
        &self,
        req: &Message,
        members: &[Arc<Member>],
    ) -> Result<(Message, Arc<Member>), Error> {
        let mut order: Vec<&Arc<Member>> = members.iter().collect();
        order.sort_by_key(|m| m.score());

        let mut last: Option<Error> = None;
        for m in order {
            let started = Instant::now();
            match m.client.exchange(req, self.timeout).await {
                Ok(resp) if !is_failure(&resp) => {
                    m.record_success(started.elapsed());

                    return Ok((resp, Arc::clone(m)));
                }
                Ok(resp) => {
                    // A SERVFAIL still proves the upstream is reachable, but
                    // it is not an answer; try the next one.
                    m.record_failure();
                    last = Some(Error::Http(format!(
                        "upstream {} returned {}",
                        m.client.upstream, resp.metadata.response_code
                    )));
                }
                Err(e) => {
                    m.record_failure();
                    last = Some(e);
                }
            }
        }

        Err(last.unwrap_or_else(|| Error::Unsupported("no upstreams tried".into())))
    }

    /// Asks every upstream at once and returns the first good answer.
    async fn exchange_parallel(
        &self,
        req: &Message,
        members: &[Arc<Member>],
    ) -> Result<(Message, Arc<Member>), Error> {
        let mut set = tokio::task::JoinSet::new();
        for m in members {
            let m = m.clone();
            let req = req.clone();
            let timeout = self.timeout;
            set.spawn(async move {
                let started = Instant::now();
                let r = m.client.exchange(&req, timeout).await;
                match &r {
                    Ok(resp) if !is_failure(resp) => m.record_success(started.elapsed()),
                    _ => m.record_failure(),
                }

                r.map(|resp| (resp, m))
            });
        }

        let mut last: Option<Error> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok((resp, m))) if !is_failure(&resp) => {
                    set.abort_all();

                    return Ok((resp, m));
                }
                Ok(Ok((resp, _))) => {
                    last = Some(Error::Http(format!(
                        "upstream returned {}",
                        resp.metadata.response_code
                    )));
                }
                Ok(Err(e)) => last = Some(e),
                Err(e) => last = Some(Error::Http(e.to_string())),
            }
        }

        Err(last.unwrap_or_else(|| Error::Unsupported("no upstreams tried".into())))
    }

    /// Asks every upstream, then answers with the address that connects
    /// fastest.
    async fn exchange_fastest_addr(
        &self,
        req: &Message,
        members: &[Arc<Member>],
    ) -> Result<(Message, Arc<Member>), Error> {
        let mut set = tokio::task::JoinSet::new();
        for m in members {
            let m = m.clone();
            let req = req.clone();
            let timeout = self.timeout;
            set.spawn(async move {
                let started = Instant::now();
                let r = m.client.exchange(&req, timeout).await;
                match &r {
                    Ok(resp) if !is_failure(resp) => m.record_success(started.elapsed()),
                    _ => m.record_failure(),
                }

                r.map(|resp| (resp, m))
            });
        }

        let mut responses: Vec<(Message, Arc<Member>)> = Vec::new();
        let mut last: Option<Error> = None;
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(Ok(won)) if !is_failure(&won.0) => responses.push(won),
                Ok(Ok((resp, _))) => {
                    last = Some(Error::Http(format!(
                        "upstream returned {}",
                        resp.metadata.response_code
                    )))
                }
                Ok(Err(e)) => last = Some(e),
                Err(e) => last = Some(Error::Http(e.to_string())),
            }
        }

        let Some((first, won)) = responses.first().cloned() else {
            return Err(last.unwrap_or_else(|| Error::Unsupported("no upstreams tried".into())));
        };

        // Gather every address the upstreams offered.
        let mut addrs: Vec<IpAddr> = Vec::new();
        for (r, _) in &responses {
            for rec in &r.answers {
                match &rec.data {
                    RData::A(a) => addrs.push(IpAddr::V4(a.0)),
                    RData::AAAA(a) => addrs.push(IpAddr::V6(a.0)),
                    _ => {}
                }
            }
        }
        addrs.sort();
        addrs.dedup();

        if addrs.len() < 2 {
            return Ok((first, won));
        }

        match fastest_of(&addrs, self.fastest_timeout).await {
            Some(best) => {
                let ttl = crate::msg::min_ttl(&first).unwrap_or(300);

                Ok((crate::msg::with_addrs(req, &[best], ttl), won))
            }
            None => Ok((first, won)),
        }
    }
}

/// The ports probed when ranking addresses, matching upstream's choice.
const PROBE_PORTS: [u16; 2] = [443, 80];

/// Returns the address that accepts a TCP connection soonest.
async fn fastest_of(addrs: &[IpAddr], timeout: Duration) -> Option<IpAddr> {
    let mut set = tokio::task::JoinSet::new();
    for &ip in addrs {
        set.spawn(async move {
            let started = Instant::now();
            for port in PROBE_PORTS {
                let target = SocketAddr::new(ip, port);
                if tokio::time::timeout(timeout, tokio::net::TcpStream::connect(target))
                    .await
                    .is_ok_and(|r| r.is_ok())
                {
                    return Some((started.elapsed(), ip));
                }
            }

            None
        });
    }

    let mut best: Option<(Duration, IpAddr)> = None;
    while let Some(joined) = set.join_next().await {
        if let Ok(Some((d, ip))) = joined
            && best.is_none_or(|(bd, _)| d < bd)
        {
            best = Some((d, ip));
        }
    }

    best.map(|(_, ip)| ip)
}

/// A set of domains and the upstreams that serve them.
pub type UpstreamGroup = (Vec<String>, Vec<Upstream>);

/// Splits parsed upstream entries into default and domain-specific groups.
///
/// Returns the default specs and the grouped ones, ready to be connected.
pub fn partition(entries: Vec<UpstreamEntry>) -> (Vec<Upstream>, Vec<UpstreamGroup>) {
    let mut defaults = Vec::new();
    let mut groups: Vec<UpstreamGroup> = Vec::new();

    for e in entries {
        let Some(u) = e.upstream else {
            // `[/domain/]#` — record the domains with no members so selection
            // falls back to the defaults for them.
            if !e.domains.is_empty() {
                groups.push((e.domains, Vec::new()));
            }

            continue;
        };

        if e.domains.is_empty() {
            defaults.push(u);
        } else if let Some(g) = groups.iter_mut().find(|(d, _)| *d == e.domains) {
            g.1.push(u);
        } else {
            groups.push((e.domains, vec![u]));
        }
    }

    (defaults, groups)
}

/// A hot-swappable pool, so upstreams can be reconfigured without a restart.
#[derive(Debug)]
pub struct SharedPool(RwLock<Arc<Pool>>);

impl SharedPool {
    /// Wraps a pool.
    pub fn new(p: Pool) -> Self {
        Self(RwLock::new(Arc::new(p)))
    }

    /// Takes a snapshot for the duration of a query.
    pub fn load(&self) -> Arc<Pool> {
        self.0.read().clone()
    }

    /// Replaces the pool.
    pub fn store(&self, p: Pool) {
        *self.0.write() = Arc::new(p);
    }
}

/// Reports whether a query type asks for addresses, which `fastest_addr` mode
/// needs in order to rank anything.
pub fn is_address_query(qt: RecordType) -> bool {
    matches!(qt, RecordType::A | RecordType::AAAA)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr;

    fn entries(specs: &[&str]) -> Vec<UpstreamEntry> {
        specs.iter().map(|s| addr::parse(s).unwrap()).collect()
    }

    #[test]
    fn partitions_defaults_and_domain_groups() {
        let (defaults, groups) = partition(entries(&[
            "1.1.1.1",
            "8.8.8.8",
            "[/example.com/]9.9.9.9",
            "[/example.com/]9.9.9.10",
            "[/internal.lan/]192.168.1.1",
        ]));

        assert_eq!(defaults.len(), 2);
        assert_eq!(groups.len(), 2);
        let ex = groups.iter().find(|(d, _)| d == &["example.com"]).unwrap();
        assert_eq!(ex.1.len(), 2, "same-domain upstreams should group together");
    }

    #[test]
    fn the_hash_form_records_an_empty_group() {
        let (defaults, groups) = partition(entries(&["1.1.1.1", "[/example.com/]#"]));
        assert_eq!(defaults.len(), 1);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].1.is_empty());
    }

    #[test]
    fn group_matching_prefers_the_most_specific_domain() {
        let g = Group {
            domains: vec!["example.com".into()],
            members: vec![],
        };
        assert_eq!(g.matches("example.com"), Some("example.com".len()));
        assert_eq!(g.matches("a.example.com"), Some("example.com".len()));
        assert_eq!(g.matches("notexample.com"), None);
        assert_eq!(g.matches("example.org"), None);
    }

    #[test]
    fn the_empty_domain_matches_only_unqualified_names() {
        let g = Group {
            domains: vec![String::new()],
            members: vec![],
        };
        assert!(g.matches("printer").is_some());
        assert!(g.matches("printer.lan").is_none());
    }

    #[test]
    fn member_scoring_prefers_fast_and_healthy_upstreams() {
        let dummy = |rtt: u64, fails: u64| {
            let m = Member {
                client: unsafe_placeholder(),
                rtt_ewma_us: AtomicU64::new(rtt),
                failures: AtomicU64::new(fails),
            };

            m.score()
        };

        assert!(dummy(1_000, 0) < dummy(5_000, 0), "faster wins");
        assert!(
            dummy(1_000, 3) > dummy(5_000, 0),
            "repeated failures demote"
        );
    }

    /// A stand-in client for scoring tests, which never performs I/O.
    fn unsafe_placeholder() -> Arc<Client> {
        // Build a real client for a literal address; `connect` is async, so
        // construct the parts directly through the public constructor path.
        let up = addr::parse("127.0.0.1:1").unwrap().upstream.unwrap();

        Arc::new(
            futures_lite_block_on(Client::connect(
                up,
                &[],
                Duration::from_millis(1),
                false,
                crate::client::tls_config(),
            ))
            .expect("a literal address needs no bootstrap"),
        )
    }

    /// Minimal block-on so the scoring test needs no async runtime.
    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    #[test]
    fn ewma_moves_towards_recent_samples() {
        let m = Member {
            client: unsafe_placeholder(),
            rtt_ewma_us: AtomicU64::new(20_000),
            failures: AtomicU64::new(0),
        };
        for _ in 0..20 {
            m.record_success(Duration::from_micros(1_000));
        }
        assert!(
            m.mean_rtt() < Duration::from_micros(3_000),
            "got {:?}",
            m.mean_rtt()
        );
    }

    #[test]
    fn success_clears_the_failure_penalty() {
        let m = Member {
            client: unsafe_placeholder(),
            rtt_ewma_us: AtomicU64::new(1_000),
            failures: AtomicU64::new(5),
        };
        let before = m.score();
        m.record_success(Duration::from_micros(1_000));
        assert!(m.score() < before);
    }

    #[tokio::test]
    async fn selection_falls_back_to_defaults_for_unmatched_domains() {
        async fn mk(s: &str) -> Arc<Client> {
            let up = addr::parse(s).unwrap().upstream.unwrap();

            Arc::new(
                Client::connect(
                    up,
                    &[],
                    Duration::from_secs(1),
                    false,
                    crate::client::tls_config(),
                )
                .await
                .unwrap(),
            )
        }

        let pool = Pool::new(
            vec![mk("1.1.1.1").await],
            vec![(vec!["example.com".into()], vec![mk("9.9.9.9").await])],
            vec![],
            Mode::LoadBalance,
            Duration::from_secs(1),
            Duration::from_secs(1),
        );

        assert_eq!(
            pool.select("a.example.com")[0].client.upstream.host,
            "9.9.9.9"
        );
        assert_eq!(pool.select("other.org")[0].client.upstream.host, "1.1.1.1");
    }

    #[test]
    fn address_query_classification() {
        assert!(is_address_query(RecordType::A));
        assert!(is_address_query(RecordType::AAAA));
        assert!(!is_address_query(RecordType::TXT));
    }
}
