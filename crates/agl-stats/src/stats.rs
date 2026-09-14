//! Statistics collection and the `/control/stats` response.

use std::collections::BTreeMap;

use ahash::{AHashMap, AHashSet};
use parking_lot::Mutex;
use serde::Serialize;

use crate::unit::{
    CountPair, Entry, MAX_CLIENTS, MAX_DOMAINS, RESULT_COUNT, Result, Unit, UnitDb, current_hour,
    to_pairs,
};

/// Statistics settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Whether statistics are collected.
    pub enabled: bool,
    /// How many hours of history to keep and report.
    pub limit_hours: u32,
    /// Hosts excluded from the top-domain lists.
    pub ignored: Vec<String>,
    /// Whether `ignored` is honoured.
    pub ignored_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self { enabled: true, limit_hours: 24, ignored: Vec::new(), ignored_enabled: false }
    }
}

/// A top-N entry: one name mapped to its count.
///
/// The API renders these as single-key objects, e.g. `{"example.com": 12}`.
pub type TopAddrs = BTreeMap<String, u64>;

/// A top-N entry with a floating-point value.
pub type TopAddrsFloat = BTreeMap<String, f64>;

/// The `/control/stats` response.
#[derive(Clone, Debug, Serialize)]
pub struct StatsResp {
    /// Whether the per-unit arrays are hours or days.
    pub time_units: &'static str,

    /// The most queried domains.
    pub top_queried_domains: Vec<TopAddrs>,
    /// The busiest clients.
    pub top_clients: Vec<TopAddrs>,
    /// The most blocked domains.
    pub top_blocked_domains: Vec<TopAddrs>,
    /// Responses per upstream.
    pub top_upstreams_responses: Vec<TopAddrs>,
    /// Mean response time per upstream, in seconds.
    pub top_upstreams_avg_time: Vec<TopAddrsFloat>,

    /// Queries per time unit.
    pub dns_queries: Vec<u64>,
    /// Queries blocked by filtering, per time unit.
    pub blocked_filtering: Vec<u64>,
    /// Queries blocked by safe browsing, per time unit.
    pub replaced_safebrowsing: Vec<u64>,
    /// Queries blocked by parental control, per time unit.
    pub replaced_parental: Vec<u64>,

    /// Total queries.
    pub num_dns_queries: u64,
    /// Total blocked by filtering.
    pub num_blocked_filtering: u64,
    /// Total blocked by safe browsing.
    pub num_replaced_safebrowsing: u64,
    /// Total rewritten by safe search.
    pub num_replaced_safesearch: u64,
    /// Total blocked by parental control.
    pub num_replaced_parental: u64,
    /// Mean processing time, in seconds.
    pub avg_processing_time: f64,
}

impl StatsResp {
    /// The response returned when statistics are switched off.
    pub fn empty() -> Self {
        Self {
            time_units: "days",
            top_queried_domains: Vec::new(),
            top_clients: Vec::new(),
            top_blocked_domains: Vec::new(),
            top_upstreams_responses: Vec::new(),
            top_upstreams_avg_time: Vec::new(),
            dns_queries: Vec::new(),
            blocked_filtering: Vec::new(),
            replaced_safebrowsing: Vec::new(),
            replaced_parental: Vec::new(),
            num_dns_queries: 0,
            num_blocked_filtering: 0,
            num_replaced_safebrowsing: 0,
            num_replaced_safesearch: 0,
            num_replaced_parental: 0,
            avg_processing_time: 0.0,
        }
    }
}

/// The statistics collector.
pub struct Stats {
    cfg: Mutex<Config>,
    /// Units by hour identifier, oldest first.
    units: Mutex<BTreeMap<u32, Unit>>,
}

impl Stats {
    /// Creates an empty collector.
    pub fn new(cfg: Config) -> Self {
        Self { cfg: Mutex::new(cfg), units: Mutex::new(BTreeMap::new()) }
    }

    /// Replaces the settings.
    pub fn set_config(&self, cfg: Config) {
        *self.cfg.lock() = cfg;
        self.prune();
    }

    /// A snapshot of the settings.
    pub fn config(&self) -> Config {
        self.cfg.lock().clone()
    }

    /// Records one query.
    ///
    /// Returns whether it was counted.
    pub fn add(&self, e: &Entry) -> bool {
        if !self.cfg.lock().enabled || !e.is_valid() {
            return false;
        }

        let id = current_hour();
        let mut units = self.units.lock();
        units.entry(id).or_insert_with(|| Unit::new(id)).add(e);

        true
    }

    /// Loads previously stored units.
    pub fn load(&self, stored: impl IntoIterator<Item = (u32, UnitDb)>) {
        let mut units = self.units.lock();
        for (id, db) in stored {
            units.insert(id, Unit::from_db(id, &db));
        }
        drop(units);

        self.prune();
    }

    /// Returns every unit in serialisable form, for persistence.
    pub fn snapshot(&self) -> Vec<(u32, UnitDb)> {
        self.units.lock().iter().map(|(id, u)| (*id, u.to_db())).collect()
    }

    /// Discards units older than the configured window.
    pub fn prune(&self) {
        let limit = self.cfg.lock().limit_hours;
        let cur = current_hour();
        let oldest = cur.saturating_sub(limit.saturating_sub(1));
        self.units.lock().retain(|id, _| *id >= oldest);
    }

    /// Removes every unit.
    pub fn clear(&self) {
        self.units.lock().clear();
    }

    /// The number of stored units.
    pub fn len(&self) -> usize {
        self.units.lock().len()
    }

    /// Reports whether nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Builds the `/control/stats` response.
    pub fn data(&self) -> StatsResp {
        let cfg = self.cfg.lock().clone();
        if cfg.limit_hours == 0 {
            return StatsResp::empty();
        }

        let cur = current_hour();
        let limit = cfg.limit_hours as usize;

        // A dense, oldest-first window of exactly `limit` units, filling gaps
        // with empty ones so the per-unit arrays line up with wall-clock time.
        let stored = self.units.lock();
        let units: Vec<Unit> = (0..limit)
            .map(|i| {
                let id = cur.saturating_sub((limit - 1 - i) as u32);
                stored.get(&id).cloned().unwrap_or_else(|| Unit::new(id))
            })
            .collect();
        drop(stored);

        let ignored: AHashSet<String> = if cfg.ignored_enabled {
            cfg.ignored.iter().map(|s| s.to_ascii_lowercase()).collect()
        } else {
            AHashSet::new()
        };

        let mut resp = StatsResp::empty();

        resp.top_queried_domains =
            merge_top(&units, MAX_DOMAINS, &ignored, |u| &u.domains);
        resp.top_blocked_domains =
            merge_top(&units, MAX_DOMAINS, &ignored, |u| &u.blocked_domains);
        resp.top_clients = merge_top(&units, MAX_CLIENTS, &AHashSet::new(), |u| &u.clients);

        let (responses, avg_time) = merge_upstreams(&units);
        resp.top_upstreams_responses = responses;
        resp.top_upstreams_avg_time = avg_time;

        fill_per_unit(&mut resp, &units);

        // Totals.
        let mut n_result = [0u64; RESULT_COUNT];
        let mut n_total = 0u64;
        let mut time_avg_sum = 0u64;
        let mut time_units_counted = 0u64;

        for u in &units {
            n_total += u.n_total;
            for i in 0..RESULT_COUNT {
                n_result[i] += u.n_result[i];
            }
            let avg = if u.n_total == 0 { 0 } else { u.time_sum / u.n_total };
            if avg != 0 {
                time_avg_sum += avg;
                time_units_counted += 1;
            }
        }

        resp.num_dns_queries = n_total;
        resp.num_blocked_filtering = n_result[Result::Filtered as usize];
        resp.num_replaced_safebrowsing = n_result[Result::SafeBrowsing as usize];
        resp.num_replaced_safesearch = n_result[Result::SafeSearch as usize];
        resp.num_replaced_parental = n_result[Result::Parental as usize];

        if time_units_counted != 0 {
            // Upstream averages the per-hour means, then converts to seconds.
            resp.avg_processing_time = (time_avg_sum / time_units_counted) as f64 / 1_000_000.0;
        }

        resp
    }
}

/// Fills the per-time-unit arrays, collapsing to days past a week.
fn fill_per_unit(resp: &mut StatsResp, units: &[Unit]) {
    let days = units.len() / 24;

    if days > 7 {
        resp.time_units = "days";
        let size = days;
        resp.dns_queries = vec![0; size];
        resp.blocked_filtering = vec![0; size];
        resp.replaced_safebrowsing = vec![0; size];
        resp.replaced_parental = vec![0; size];

        // Drop the leading partial day so each bucket holds a full 24 hours.
        let hours = size * 24;
        let tail = &units[units.len() - hours..];
        for (i, u) in tail.iter().enumerate() {
            let d = i / 24;
            resp.dns_queries[d] += u.n_total;
            resp.blocked_filtering[d] += u.n_result[Result::Filtered as usize];
            resp.replaced_safebrowsing[d] += u.n_result[Result::SafeBrowsing as usize];
            resp.replaced_parental[d] += u.n_result[Result::Parental as usize];
        }

        return;
    }

    resp.time_units = "hours";
    resp.dns_queries = units.iter().map(|u| u.n_total).collect();
    resp.blocked_filtering =
        units.iter().map(|u| u.n_result[Result::Filtered as usize]).collect();
    resp.replaced_safebrowsing =
        units.iter().map(|u| u.n_result[Result::SafeBrowsing as usize]).collect();
    resp.replaced_parental =
        units.iter().map(|u| u.n_result[Result::Parental as usize]).collect();
}

/// Merges one counter map across units and returns the top `max` entries.
fn merge_top(
    units: &[Unit],
    max: usize,
    ignored: &AHashSet<String>,
    pick: impl Fn(&Unit) -> &AHashMap<String, u64>,
) -> Vec<TopAddrs> {
    let mut merged: AHashMap<String, u64> = AHashMap::new();
    for u in units {
        for (name, count) in pick(u) {
            if ignored.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            *merged.entry(name.clone()).or_insert(0) += count;
        }
    }

    to_top(&to_pairs(&merged, max))
}

/// Merges upstream counters and derives the mean response time per upstream.
fn merge_upstreams(units: &[Unit]) -> (Vec<TopAddrs>, Vec<TopAddrsFloat>) {
    let mut responses: AHashMap<String, u64> = AHashMap::new();
    let mut time_sum: AHashMap<String, u64> = AHashMap::new();

    for u in units {
        for (a, c) in &u.upstreams_responses {
            *responses.entry(a.clone()).or_insert(0) += c;
        }
        for (a, t) in &u.upstreams_time_sum {
            *time_sum.entry(a.clone()).or_insert(0) += t;
        }
    }

    let pairs = to_pairs(&responses, MAX_CLIENTS);
    let avg: Vec<TopAddrsFloat> = pairs
        .iter()
        .map(|p| {
            let total = time_sum.get(&p.name).copied().unwrap_or(0);
            let mean = if p.count == 0 {
                0.0
            } else {
                total as f64 / p.count as f64 / 1_000_000.0
            };

            TopAddrsFloat::from([(p.name.clone(), mean)])
        })
        .collect();

    (to_top(&pairs), avg)
}

/// Converts pairs into the API's list-of-single-key-objects shape.
fn to_top(pairs: &[CountPair]) -> Vec<TopAddrs> {
    pairs
        .iter()
        .map(|p| TopAddrs::from([(p.name.clone(), p.count)]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unit::UpstreamStat;
    use std::time::Duration;

    fn entry(domain: &str, client: &str, result: Result, micros: u64) -> Entry {
        Entry {
            client: client.into(),
            domain: domain.into(),
            result,
            processing_time: Duration::from_micros(micros),
            upstreams: Vec::new(),
        }
    }

    #[test]
    fn counts_totals_and_categories() {
        let s = Stats::new(Config::default());
        s.add(&entry("good.com", "1.1.1.1", Result::NotFiltered, 100));
        s.add(&entry("ads.com", "1.1.1.1", Result::Filtered, 200));
        s.add(&entry("bad.com", "2.2.2.2", Result::SafeBrowsing, 300));
        s.add(&entry("kid.com", "2.2.2.2", Result::Parental, 400));

        let d = s.data();
        assert_eq!(d.num_dns_queries, 4);
        assert_eq!(d.num_blocked_filtering, 1);
        assert_eq!(d.num_replaced_safebrowsing, 1);
        assert_eq!(d.num_replaced_parental, 1);
        assert!(d.avg_processing_time > 0.0);
    }

    #[test]
    fn reports_hours_for_a_day_long_window() {
        let s = Stats::new(Config { limit_hours: 24, ..Default::default() });
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        assert_eq!(d.time_units, "hours");
        assert_eq!(d.dns_queries.len(), 24);
        // The current hour is the last bucket.
        assert_eq!(*d.dns_queries.last().unwrap(), 1);
        assert_eq!(d.dns_queries[..23].iter().sum::<u64>(), 0);
    }

    #[test]
    fn collapses_to_days_past_a_week() {
        // 30 days of hours.
        let s = Stats::new(Config { limit_hours: 24 * 30, ..Default::default() });
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        assert_eq!(d.time_units, "days");
        assert_eq!(d.dns_queries.len(), 30);
        assert_eq!(d.dns_queries.iter().sum::<u64>(), 1);
    }

    #[test]
    fn a_week_still_reports_hours() {
        let s = Stats::new(Config { limit_hours: 24 * 7, ..Default::default() });
        let d = s.data();
        assert_eq!(d.time_units, "hours", "7 days is not more than 7, so hours");
        assert_eq!(d.dns_queries.len(), 24 * 7);
    }

    #[test]
    fn top_lists_are_shaped_as_single_key_objects() {
        let s = Stats::new(Config::default());
        for _ in 0..3 {
            s.add(&entry("popular.com", "1.1.1.1", Result::NotFiltered, 10));
        }
        s.add(&entry("rare.com", "1.1.1.1", Result::NotFiltered, 10));
        s.add(&entry("ads.com", "1.1.1.1", Result::Filtered, 10));

        let d = s.data();
        assert_eq!(d.top_queried_domains[0].get("popular.com"), Some(&3));
        assert_eq!(d.top_queried_domains[1].get("rare.com"), Some(&1));
        assert_eq!(d.top_blocked_domains[0].get("ads.com"), Some(&1));
        assert_eq!(d.top_clients[0].get("1.1.1.1"), Some(&5));
    }

    #[test]
    fn upstream_means_are_reported_in_seconds() {
        let s = Stats::new(Config::default());
        let mut e = entry("a.com", "c", Result::NotFiltered, 10);
        e.upstreams = vec![UpstreamStat {
            address: "9.9.9.10:53".into(),
            duration: Duration::from_micros(250_000),
            cached: false,
            failed: false,
        }];
        s.add(&e);
        s.add(&e);

        let d = s.data();
        assert_eq!(d.top_upstreams_responses[0].get("9.9.9.10:53"), Some(&2));
        let mean = d.top_upstreams_avg_time[0].get("9.9.9.10:53").copied().unwrap();
        assert!((mean - 0.25).abs() < 1e-9, "expected 0.25 s, got {mean}");
    }

    #[test]
    fn ignored_domains_are_excluded_from_the_top_lists() {
        let s = Stats::new(Config {
            ignored: vec!["secret.com".into()],
            ignored_enabled: true,
            ..Default::default()
        });
        s.add(&entry("secret.com", "c", Result::NotFiltered, 10));
        s.add(&entry("public.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        let names: Vec<&String> = d.top_queried_domains.iter().flat_map(|m| m.keys()).collect();
        assert!(!names.iter().any(|n| n.as_str() == "secret.com"));
        assert!(names.iter().any(|n| n.as_str() == "public.com"));
        // The query still counts towards the totals.
        assert_eq!(d.num_dns_queries, 2);
    }

    #[test]
    fn disabled_statistics_record_nothing() {
        let s = Stats::new(Config { enabled: false, ..Default::default() });
        assert!(!s.add(&entry("a.com", "c", Result::NotFiltered, 10)));
        assert_eq!(s.data().num_dns_queries, 0);
    }

    #[test]
    fn a_zero_window_returns_the_empty_response() {
        let s = Stats::new(Config { limit_hours: 0, ..Default::default() });
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));

        let d = s.data();
        assert_eq!(d.time_units, "days");
        assert!(d.dns_queries.is_empty());
        assert!(d.top_queried_domains.is_empty());
    }

    #[test]
    fn snapshots_round_trip_through_load() {
        let s = Stats::new(Config::default());
        s.add(&entry("a.com", "c", Result::NotFiltered, 1000));
        s.add(&entry("b.com", "c", Result::Filtered, 2000));

        let snap = s.snapshot();
        assert_eq!(snap.len(), 1);

        let s2 = Stats::new(Config::default());
        s2.load(snap);
        let d = s2.data();
        assert_eq!(d.num_dns_queries, 2);
        assert_eq!(d.num_blocked_filtering, 1);
    }

    #[test]
    fn clearing_drops_everything() {
        let s = Stats::new(Config::default());
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));
        assert!(!s.is_empty());
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.data().num_dns_queries, 0);
    }

    #[test]
    fn pruning_drops_units_outside_the_window() {
        let s = Stats::new(Config { limit_hours: 2, ..Default::default() });
        let cur = current_hour();
        s.load([
            (cur - 10, Unit::new(cur - 10).to_db()),
            (cur, Unit::new(cur).to_db()),
        ]);

        assert_eq!(s.len(), 1, "the old unit should have been pruned");
    }

    #[test]
    fn the_response_serialises_with_the_api_field_names() {
        let s = Stats::new(Config::default());
        s.add(&entry("a.com", "c", Result::NotFiltered, 10));
        let json = serde_json::to_string(&s.data()).unwrap();

        for key in [
            "time_units",
            "top_queried_domains",
            "top_clients",
            "top_blocked_domains",
            "top_upstreams_responses",
            "top_upstreams_avg_time",
            "dns_queries",
            "blocked_filtering",
            "replaced_safebrowsing",
            "replaced_parental",
            "num_dns_queries",
            "num_blocked_filtering",
            "num_replaced_safebrowsing",
            "num_replaced_safesearch",
            "num_replaced_parental",
            "avg_processing_time",
        ] {
            assert!(json.contains(&format!("\"{key}\"")), "missing {key} in {json}");
        }
    }
}
