//! A TTL-aware DNS response cache.
//!
//! Sized in bytes to match `cache_size` in the config, and sharded so that
//! concurrent queries rarely contend on the same lock.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use parking_lot::Mutex;

/// How a cached entry was produced, so callers can decide whether to refresh.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    /// The entry is within its TTL.
    Fresh,
    /// The entry has expired but is being served optimistically.
    Stale,
}

/// The key identifying a cached response.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Key {
    /// The question name, lowercased and without a trailing dot.
    pub name: String,
    /// The question type.
    pub qtype: u16,
    /// The question class.
    pub qclass: u16,
    /// Whether the query asked for DNSSEC records.
    pub dnssec_ok: bool,
}

impl Key {
    /// Derives a cache key from a request, or `None` when it has no question.
    pub fn from_request(req: &Message) -> Option<Self> {
        let q = req.queries.first()?;

        Some(Key {
            name: q
                .name()
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            qtype: q.query_type().into(),
            qclass: q.query_class().into(),
            dnssec_ok: req.metadata.authentic_data,
        })
    }

    /// A rough byte cost for accounting.
    fn weight(&self) -> usize {
        self.name.len() + std::mem::size_of::<Self>()
    }
}

/// A cached response.
#[derive(Clone, Debug)]
struct Entry {
    /// The stored message, with TTLs as received.
    msg: Message,
    /// When the entry was stored.
    stored: Instant,
    /// The TTL the entry was stored with.
    ttl: Duration,
    /// The approximate size of the entry in bytes.
    weight: usize,
}

impl Entry {
    /// Reports how much time has passed since the entry was stored.
    fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.stored)
    }

    /// Reports whether the entry is past its TTL.
    fn is_expired(&self, now: Instant) -> bool {
        self.age(now) >= self.ttl
    }
}

/// Cache tuning, mirroring the `cache_*` config keys.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The total budget in bytes.  Zero disables the cache.
    pub size_bytes: usize,
    /// Lower bound applied to a response's TTL, or zero for none.
    pub ttl_min: u32,
    /// Upper bound applied to a response's TTL, or zero for none.
    pub ttl_max: u32,
    /// Whether expired entries may still be served while a refresh runs.
    pub optimistic: bool,
    /// How long an expired entry may still be served.
    pub optimistic_max_age: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            size_bytes: 4 * 1024 * 1024,
            ttl_min: 0,
            ttl_max: 0,
            optimistic: false,
            optimistic_max_age: Duration::from_secs(12 * 3600),
        }
    }
}

/// The number of shards.  A power of two so the index is a mask.
const SHARDS: usize = 16;

/// A sharded, size-bounded DNS cache.
pub struct Cache {
    shards: Vec<Mutex<Shard>>,
    cfg: Config,
}

/// One shard's state.
struct Shard {
    map: HashMap<Key, Entry>,
    /// Keys in rough insertion order, used for eviction.
    order: std::collections::VecDeque<Key>,
    bytes: usize,
    budget: usize,
}

impl Shard {
    /// Evicts oldest entries until the shard fits its budget.
    fn evict_to_fit(&mut self) {
        while self.bytes > self.budget {
            let Some(k) = self.order.pop_front() else {
                break;
            };
            if let Some(e) = self.map.remove(&k) {
                self.bytes = self.bytes.saturating_sub(e.weight);
            }
        }
    }
}

impl Cache {
    /// Builds a cache with the given configuration.
    pub fn new(cfg: Config) -> Self {
        let per_shard = (cfg.size_bytes / SHARDS).max(1);
        let shards = (0..SHARDS)
            .map(|_| {
                Mutex::new(Shard {
                    map: HashMap::new(),
                    order: std::collections::VecDeque::new(),
                    bytes: 0,
                    budget: per_shard,
                })
            })
            .collect();

        Self { shards, cfg }
    }

    /// Reports whether caching is switched off.
    pub fn is_disabled(&self) -> bool {
        self.cfg.size_bytes == 0
    }

    /// Picks the shard for a key.
    fn shard_of(&self, k: &Key) -> &Mutex<Shard> {
        use std::hash::{Hash, Hasher};
        let mut h = ahash::AHasher::default();
        k.hash(&mut h);

        &self.shards[(h.finish() as usize) % SHARDS]
    }

    /// Looks a response up, adjusting its TTLs to the time already elapsed.
    ///
    /// Returns `None` on a miss, or when the entry has expired and optimistic
    /// serving is off.
    pub fn get(&self, k: &Key) -> Option<(Message, Freshness)> {
        if self.is_disabled() {
            return None;
        }

        let now = Instant::now();
        let mut sh = self.shard_of(k).lock();
        let e = sh.map.get(k)?;

        let age = e.age(now);
        let expired = e.is_expired(now);

        // An expired entry is dropped unless optimistic serving is on and it
        // is still inside the stale window.
        if expired && (!self.cfg.optimistic || age > self.cfg.optimistic_max_age) {
            let weight = e.weight;
            sh.map.remove(k);
            sh.bytes = sh.bytes.saturating_sub(weight);

            return None;
        }

        let mut msg = e.msg.clone();
        let elapsed = age.as_secs() as u32;
        decrement_ttls(&mut msg, elapsed);

        Some((
            msg,
            if expired {
                Freshness::Stale
            } else {
                Freshness::Fresh
            },
        ))
    }

    /// Stores a response, if it is cacheable.
    ///
    /// Returns whether the response was stored.
    pub fn put(&self, k: Key, msg: &Message) -> bool {
        if self.is_disabled() {
            return false;
        }

        let Some(ttl) = self.cache_ttl_for(msg) else {
            return false;
        };

        let weight = estimate_weight(msg) + k.weight();
        let mut sh = self.shard_of(&k).lock();

        // Oversized single entries are simply not cached.
        if weight > sh.budget {
            return false;
        }

        if let Some(old) = sh.map.insert(
            k.clone(),
            Entry {
                msg: msg.clone(),
                stored: Instant::now(),
                ttl,
                weight,
            },
        ) {
            sh.bytes = sh.bytes.saturating_sub(old.weight);
        } else {
            sh.order.push_back(k);
        }
        sh.bytes += weight;
        sh.evict_to_fit();

        true
    }

    /// Decides the TTL to cache a response for, or `None` if it must not be
    /// cached.
    fn cache_ttl_for(&self, msg: &Message) -> Option<Duration> {
        // Only successful and negative answers are worth caching.
        match msg.metadata.response_code {
            ResponseCode::NoError | ResponseCode::NXDomain => {}
            _ => return None,
        }

        // A response with no records at all carries no TTL to honour.
        let base = crate::msg::min_ttl(msg)?;

        let mut ttl = base;
        if self.cfg.ttl_min > 0 {
            ttl = ttl.max(self.cfg.ttl_min);
        }
        if self.cfg.ttl_max > 0 {
            ttl = ttl.min(self.cfg.ttl_max);
        }

        if ttl == 0 {
            return None;
        }

        Some(Duration::from_secs(u64::from(ttl)))
    }

    /// Removes every entry.
    pub fn clear(&self) {
        for s in &self.shards {
            let mut sh = s.lock();
            sh.map.clear();
            sh.order.clear();
            sh.bytes = 0;
        }
    }

    /// The number of cached entries.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().map.len()).sum()
    }

    /// Reports whether the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The approximate number of bytes held.
    pub fn bytes(&self) -> usize {
        self.shards.iter().map(|s| s.lock().bytes).sum()
    }
}

/// Reduces every record's TTL by `secs`, flooring at one second so a cached
/// answer never claims to be already expired.
fn decrement_ttls(msg: &mut Message, secs: u32) {
    for r in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        r.ttl = r.ttl.saturating_sub(secs).max(1);
    }
}

/// A rough byte cost for a message.
fn estimate_weight(msg: &Message) -> usize {
    const PER_RECORD: usize = 64;
    let records = msg.answers.len() + msg.authorities.len() + msg.additionals.len();
    let names: usize = msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
        .map(|r| r.name.len())
        .sum();

    std::mem::size_of::<Entry>() + records * PER_RECORD + names
}

/// Reports whether a query type may be cached at all.
pub fn is_cacheable_type(qt: RecordType) -> bool {
    !matches!(qt, RecordType::AXFR | RecordType::IXFR | RecordType::ANY)
}

/// Convenience for building a cache with a non-zero size.
pub fn with_size(bytes: NonZeroUsize) -> Cache {
    Cache::new(Config {
        size_bytes: bytes.get(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RData, Record, rdata::A};

    fn req(name: &str) -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), RecordType::A));

        m
    }

    fn resp(name: &str, ttl: u32) -> Message {
        let mut m = crate::msg::reply(&req(name), ResponseCode::NoError);
        m.answers = vec![Record::from_rdata(
            Name::from_utf8(name).unwrap(),
            ttl,
            RData::A(A(std::net::Ipv4Addr::new(1, 2, 3, 4))),
        )];

        m
    }

    #[test]
    fn stores_and_retrieves() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(c.put(k.clone(), &resp("example.com.", 300)));

        let (got, fresh) = c.get(&k).expect("should hit");
        assert_eq!(fresh, Freshness::Fresh);
        assert_eq!(got.answers.len(), 1);
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn keys_distinguish_name_type_and_dnssec() {
        let a = Key::from_request(&req("example.com.")).unwrap();
        let b = Key::from_request(&req("other.com.")).unwrap();
        assert_ne!(a, b);

        let mut r = req("example.com.");
        r.metadata.authentic_data = true;
        assert_ne!(a, Key::from_request(&r).unwrap());
    }

    #[test]
    fn keys_are_case_insensitive_and_ignore_the_trailing_dot() {
        let a = Key::from_request(&req("Example.COM.")).unwrap();
        let b = Key::from_request(&req("example.com.")).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.name, "example.com");
    }

    #[test]
    fn a_miss_returns_nothing() {
        let c = Cache::new(Config::default());
        assert!(
            c.get(&Key::from_request(&req("absent.com.")).unwrap())
                .is_none()
        );
    }

    #[test]
    fn refuses_to_cache_failures() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        let mut m = resp("example.com.", 300);
        m.metadata.response_code = ResponseCode::ServFail;
        assert!(!c.put(k.clone(), &m));
        assert!(c.get(&k).is_none());
    }

    #[test]
    fn refuses_to_cache_a_zero_ttl() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(!c.put(k.clone(), &resp("example.com.", 0)));
    }

    #[test]
    fn applies_the_configured_ttl_bounds() {
        let c = Cache::new(Config {
            ttl_min: 60,
            ..Default::default()
        });
        assert_eq!(
            c.cache_ttl_for(&resp("a.com.", 5)),
            Some(Duration::from_secs(60))
        );

        let c = Cache::new(Config {
            ttl_max: 30,
            ..Default::default()
        });
        assert_eq!(
            c.cache_ttl_for(&resp("a.com.", 300)),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn a_disabled_cache_stores_nothing() {
        let c = Cache::new(Config {
            size_bytes: 0,
            ..Default::default()
        });
        assert!(c.is_disabled());
        let k = Key::from_request(&req("example.com.")).unwrap();
        assert!(!c.put(k.clone(), &resp("example.com.", 300)));
        assert!(c.get(&k).is_none());
    }

    #[test]
    fn evicts_when_over_budget() {
        // A tiny budget so a handful of entries forces eviction.
        let c = Cache::new(Config {
            size_bytes: SHARDS * 400,
            ..Default::default()
        });
        for i in 0..500 {
            let name = format!("host{i}.example.com.");
            let k = Key::from_request(&req(&name)).unwrap();
            c.put(k, &resp(&name, 300));
        }

        assert!(
            c.len() < 500,
            "eviction should have dropped entries, got {}",
            c.len()
        );
        assert!(
            c.bytes() <= SHARDS * 400 + 4096,
            "bytes should stay near budget"
        );
    }

    #[test]
    fn clearing_empties_the_cache() {
        let c = Cache::new(Config::default());
        let k = Key::from_request(&req("example.com.")).unwrap();
        c.put(k, &resp("example.com.", 300));
        assert!(!c.is_empty());
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.bytes(), 0);
    }

    #[test]
    fn zone_transfer_and_any_are_not_cacheable() {
        assert!(!is_cacheable_type(RecordType::AXFR));
        assert!(!is_cacheable_type(RecordType::ANY));
        assert!(is_cacheable_type(RecordType::A));
    }
}
