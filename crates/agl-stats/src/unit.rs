//! Hourly statistics units.
//!
//! One unit covers one hour, identified by the absolute hour number since the
//! Unix epoch — the same identifier the Go implementation uses as its database
//! bucket name, so units line up across implementations.

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

/// The number of result buckets, matching upstream's `resultLast`.
pub const RESULT_COUNT: usize = 6;

/// The result categories counted per unit.
///
/// The discriminants are persisted, so they must not move.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum Result {
    /// The query was not filtered.
    NotFiltered = 1,
    /// The query was blocked by a filter list.
    Filtered = 2,
    /// The query was blocked by safe browsing.
    SafeBrowsing = 3,
    /// The query was rewritten by safe search.
    SafeSearch = 4,
    /// The query was blocked by parental control.
    Parental = 5,
}

impl Result {
    /// Maps a filtering reason onto its statistics bucket.
    pub const fn from_reason(r: agl_core::Reason) -> Self {
        use agl_core::Reason as R;

        match r {
            R::FilteredBlockList | R::FilteredBlockedService | R::FilteredInvalid => {
                Result::Filtered
            }
            R::FilteredSafeBrowsing => Result::SafeBrowsing,
            R::FilteredSafeSearch => Result::SafeSearch,
            R::FilteredParental => Result::Parental,
            _ => Result::NotFiltered,
        }
    }
}

/// One upstream's contribution to a query.
#[derive(Clone, Debug)]
pub struct UpstreamStat {
    /// The upstream's address, as it appears in the query log.
    pub address: String,
    /// How long the upstream took.
    pub duration: std::time::Duration,
    /// Whether the answer came from the cache, in which case it is not counted.
    pub cached: bool,
    /// Whether the exchange failed, in which case it is not counted.
    pub failed: bool,
}

/// One query, as recorded into the statistics.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The client, as an address or a name.
    pub client: String,
    /// The queried domain.
    pub domain: String,
    /// How the query was resolved.
    pub result: Result,
    /// How long handling took.
    pub processing_time: std::time::Duration,
    /// Which upstreams answered.
    pub upstreams: Vec<UpstreamStat>,
}

impl Entry {
    /// Reports whether the entry can be counted.
    pub fn is_valid(&self) -> bool {
        !self.domain.is_empty() && !self.client.is_empty()
    }
}

/// The live, mutable form of one hour's statistics.
#[derive(Clone, Debug)]
pub struct Unit {
    /// The hour this unit covers.
    pub id: u32,
    /// Queries per domain that were not blocked.
    pub domains: AHashMap<String, u64>,
    /// Queries per domain that were blocked.
    pub blocked_domains: AHashMap<String, u64>,
    /// Queries per client.
    pub clients: AHashMap<String, u64>,
    /// Responses per upstream.
    pub upstreams_responses: AHashMap<String, u64>,
    /// Summed response time per upstream, in microseconds.
    pub upstreams_time_sum: AHashMap<String, u64>,
    /// Query counts per result category.
    pub n_result: [u64; RESULT_COUNT],
    /// Total queries.
    pub n_total: u64,
    /// Summed processing time, in microseconds.
    pub time_sum: u64,
}

impl Unit {
    /// Creates an empty unit for the given hour.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            domains: AHashMap::new(),
            blocked_domains: AHashMap::new(),
            clients: AHashMap::new(),
            upstreams_responses: AHashMap::new(),
            upstreams_time_sum: AHashMap::new(),
            n_result: [0; RESULT_COUNT],
            n_total: 0,
            time_sum: 0,
        }
    }

    /// Counts one query.
    pub fn add(&mut self, e: &Entry) {
        self.n_result[e.result as usize] += 1;

        // A not-filtered query counts towards queried domains; anything else
        // counts towards blocked domains, as upstream does.
        let bucket = if e.result == Result::NotFiltered {
            &mut self.domains
        } else {
            &mut self.blocked_domains
        };
        *bucket.entry(e.domain.clone()).or_insert(0) += 1;

        *self.clients.entry(e.client.clone()).or_insert(0) += 1;
        self.time_sum += e.processing_time.as_micros() as u64;
        self.n_total += 1;

        for u in &e.upstreams {
            if u.cached || u.failed {
                continue;
            }
            *self.upstreams_responses.entry(u.address.clone()).or_insert(0) += 1;
            *self.upstreams_time_sum.entry(u.address.clone()).or_insert(0) +=
                u.duration.as_micros() as u64;
        }
    }

    /// Converts to the serialisable form.
    pub fn to_db(&self) -> UnitDb {
        UnitDb {
            n_result: self.n_result.to_vec(),
            domains: to_pairs(&self.domains, MAX_DOMAINS),
            blocked_domains: to_pairs(&self.blocked_domains, MAX_DOMAINS),
            clients: to_pairs(&self.clients, MAX_CLIENTS),
            upstreams_responses: to_pairs(&self.upstreams_responses, MAX_CLIENTS),
            upstreams_time_sum: to_pairs(&self.upstreams_time_sum, MAX_CLIENTS),
            n_total: self.n_total,
            // Upstream stores the mean, not the sum.
            time_avg: if self.n_total == 0 {
                0
            } else {
                (self.time_sum / self.n_total) as u32
            },
        }
    }

    /// Rebuilds a unit from its serialised form.
    pub fn from_db(id: u32, db: &UnitDb) -> Self {
        let mut u = Unit::new(id);
        u.n_total = db.n_total;
        for (i, v) in db.n_result.iter().take(RESULT_COUNT).enumerate() {
            u.n_result[i] = *v;
        }
        u.domains = from_pairs(&db.domains);
        u.blocked_domains = from_pairs(&db.blocked_domains);
        u.clients = from_pairs(&db.clients);
        u.upstreams_responses = from_pairs(&db.upstreams_responses);
        u.upstreams_time_sum = from_pairs(&db.upstreams_time_sum);
        u.time_sum = u64::from(db.time_avg) * db.n_total;

        u
    }
}

/// The maximum number of top domains reported.
pub const MAX_DOMAINS: usize = 100;

/// The maximum number of top clients reported.
pub const MAX_CLIENTS: usize = 100;

/// A name and its count.
///
/// The field names match the Go struct, because they are part of the gob
/// encoding used in `stats.db`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountPair {
    /// The name.
    pub name: String,
    /// The count.
    pub count: u64,
}

/// The serialisable form of a unit.
///
/// Field order and names mirror Go's `unitDB`, which is gob-encoded into
/// `stats.db`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitDb {
    /// Query counts per result category.
    pub n_result: Vec<u64>,
    /// Top queried domains.
    pub domains: Vec<CountPair>,
    /// Top blocked domains.
    pub blocked_domains: Vec<CountPair>,
    /// Top clients.
    pub clients: Vec<CountPair>,
    /// Responses per upstream.
    pub upstreams_responses: Vec<CountPair>,
    /// Summed response time per upstream, in microseconds.
    pub upstreams_time_sum: Vec<CountPair>,
    /// Total queries.
    pub n_total: u64,
    /// Mean processing time, in microseconds.
    pub time_avg: u32,
}

/// Converts a counter map into the top `max` pairs, highest count first.
pub fn to_pairs(m: &AHashMap<String, u64>, max: usize) -> Vec<CountPair> {
    let mut v: Vec<CountPair> = m
        .iter()
        .map(|(k, c)| CountPair { name: k.clone(), count: *c })
        .collect();

    // Sort by count descending, then by name so the output is deterministic.
    v.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    v.truncate(max);

    v
}

/// Rebuilds a counter map from pairs.
pub fn from_pairs(v: &[CountPair]) -> AHashMap<String, u64> {
    v.iter().map(|p| (p.name.clone(), p.count)).collect()
}

/// The absolute hour number for a Unix timestamp in seconds.
pub const fn hour_of(unix_secs: i64) -> u32 {
    (unix_secs / 3600) as u32
}

/// The current absolute hour number.
pub fn current_hour() -> u32 {
    hour_of(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn result_categories_match_upstreams_numbering() {
        // These indices are persisted in stats.db.
        assert_eq!(Result::NotFiltered as usize, 1);
        assert_eq!(Result::Filtered as usize, 2);
        assert_eq!(Result::SafeBrowsing as usize, 3);
        assert_eq!(Result::SafeSearch as usize, 4);
        assert_eq!(Result::Parental as usize, 5);
        assert_eq!(RESULT_COUNT, 6);
    }

    #[test]
    fn reasons_map_onto_categories() {
        use agl_core::Reason as R;

        assert_eq!(Result::from_reason(R::FilteredBlockList), Result::Filtered);
        assert_eq!(Result::from_reason(R::FilteredBlockedService), Result::Filtered);
        assert_eq!(Result::from_reason(R::FilteredSafeBrowsing), Result::SafeBrowsing);
        assert_eq!(Result::from_reason(R::FilteredParental), Result::Parental);
        assert_eq!(Result::from_reason(R::NotFilteredNotFound), Result::NotFiltered);
        assert_eq!(Result::from_reason(R::NotFilteredAllowList), Result::NotFiltered);
    }

    #[test]
    fn counts_queried_and_blocked_domains_separately() {
        let mut u = Unit::new(1);
        u.add(&entry("good.com", "1.1.1.1", Result::NotFiltered, 100));
        u.add(&entry("ads.com", "1.1.1.1", Result::Filtered, 200));
        u.add(&entry("ads.com", "1.1.1.1", Result::Filtered, 200));

        assert_eq!(u.domains.get("good.com"), Some(&1));
        assert_eq!(u.blocked_domains.get("ads.com"), Some(&2));
        assert!(!u.domains.contains_key("ads.com"), "blocked domains do not count as queried");
        assert_eq!(u.clients.get("1.1.1.1"), Some(&3));
        assert_eq!(u.n_total, 3);
        assert_eq!(u.n_result[Result::Filtered as usize], 2);
        assert_eq!(u.time_sum, 500);
    }

    #[test]
    fn upstream_statistics_skip_cached_and_failed_answers() {
        let mut u = Unit::new(1);
        let mut e = entry("a.com", "c", Result::NotFiltered, 10);
        e.upstreams = vec![
            UpstreamStat {
                address: "9.9.9.10:53".into(),
                duration: Duration::from_micros(500),
                cached: false,
                failed: false,
            },
            UpstreamStat {
                address: "8.8.8.8:53".into(),
                duration: Duration::from_micros(900),
                cached: true,
                failed: false,
            },
            UpstreamStat {
                address: "1.1.1.1:53".into(),
                duration: Duration::from_micros(900),
                cached: false,
                failed: true,
            },
        ];
        u.add(&e);

        assert_eq!(u.upstreams_responses.get("9.9.9.10:53"), Some(&1));
        assert_eq!(u.upstreams_time_sum.get("9.9.9.10:53"), Some(&500));
        assert!(!u.upstreams_responses.contains_key("8.8.8.8:53"));
        assert!(!u.upstreams_responses.contains_key("1.1.1.1:53"));
    }

    #[test]
    fn serialisation_stores_the_mean_not_the_sum() {
        let mut u = Unit::new(1);
        for _ in 0..4 {
            u.add(&entry("a.com", "c", Result::NotFiltered, 1000));
        }

        let db = u.to_db();
        assert_eq!(db.n_total, 4);
        assert_eq!(db.time_avg, 1000, "upstream persists the mean");

        // And the round trip restores the sum.
        let back = Unit::from_db(1, &db);
        assert_eq!(back.time_sum, 4000);
        assert_eq!(back.n_total, 4);
        assert_eq!(back.domains.get("a.com"), Some(&4));
    }

    #[test]
    fn top_pairs_are_capped_and_sorted_by_count() {
        let mut m = AHashMap::new();
        for i in 0..150 {
            m.insert(format!("d{i}.com"), i as u64);
        }

        let pairs = to_pairs(&m, MAX_DOMAINS);
        assert_eq!(pairs.len(), MAX_DOMAINS);
        assert_eq!(pairs[0].count, 149, "highest first");
        assert!(pairs.windows(2).all(|w| w[0].count >= w[1].count));
    }

    #[test]
    fn hour_numbering_matches_the_bucket_identifier() {
        assert_eq!(hour_of(0), 0);
        assert_eq!(hour_of(3599), 0);
        assert_eq!(hour_of(3600), 1);
        assert_eq!(hour_of(86_400), 24);
    }

    #[test]
    fn entries_need_a_domain_and_a_client() {
        assert!(entry("a.com", "c", Result::NotFiltered, 1).is_valid());
        assert!(!entry("", "c", Result::NotFiltered, 1).is_valid());
        assert!(!entry("a.com", "", Result::NotFiltered, 1).is_valid());
    }
}
