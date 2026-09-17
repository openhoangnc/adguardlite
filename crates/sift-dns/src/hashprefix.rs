//! Safe browsing and parental control, over the hash-prefix protocol.
//!
//! A port of `internal/filtering/hashprefix`.  The hostname is never sent:
//! each of its parent names is hashed with SHA-256, the first two bytes of
//! each hash become labels of a `TXT` query, and the server answers with the
//! full hashes it knows in those buckets.  A hash that comes back matching one
//! that was asked about means the host is on the list.
//!
//! The queries go to AdGuard's own family resolver over DNS-over-HTTPS, with
//! its addresses hard-coded so the lookup cannot depend on this very server.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use parking_lot::Mutex;

use crate::addr;
use crate::client::Client;

/// How many leading bytes of the hash are sent.
const PREFIX_LEN: usize = 2;

/// The length of a SHA-256 hash.
const HASH_LEN: usize = 32;

/// The number of hex characters a full hash is written with.
const HEX_LEN: usize = HASH_LEN * 2;

/// How many trailing labels of the hostname are considered.
const SUBDOMAIN_LIMIT: usize = 4;

/// The resolver the lookups go to.
pub const SERVER: &str = "https://family.adguard-dns.com/dns-query";

/// The suffix of a safe browsing question.
pub const SAFE_BROWSING_SUFFIX: &str = "sb.dns.adguard.com";

/// The suffix of a parental control question.
pub const PARENTAL_SUFFIX: &str = "pc.dns.adguard.com";

/// The rule text upstream records for a safe browsing match.
pub const SAFE_BROWSING_RULE: &str = "adguard-malware-shavar";

/// The rule text upstream records for a parental control match.
pub const PARENTAL_RULE: &str = "parental CATEGORY_BLACKLISTED";

/// The filter list identifier for parental control matches.
pub const PARENTAL_LIST_ID: i64 = -3;

/// The filter list identifier for safe browsing matches.
pub const SAFE_BROWSING_LIST_ID: i64 = -4;

/// How long a lookup may take.
const TIMEOUT: Duration = Duration::from_secs(3);

/// The addresses the family resolver's own name is looked up through.
///
/// Hard-coded, as upstream does: bootstrapping this through the server's own
/// resolvers would make safe browsing depend on the very filtering it feeds.
///
/// Port 53, not 443.  These are reached by plain DNS over UDP — that is what
/// bootstrapping is — while 443 is where the same hosts serve DoH, and a
/// plain query sent there is answered by nothing.  With the wrong port every
/// lookup of `family.adguard-dns.com` timed out, `Checker::connect` failed,
/// and safe browsing and parental control stayed off while the interface
/// reported them on.
pub fn bootstrap() -> Vec<SocketAddr> {
    [
        "94.140.14.15",
        "94.140.14.16",
        "2a10:50c0::bad1:ff",
        "2a10:50c0::bad2:ff",
    ]
    .iter()
    .filter_map(|s| s.parse::<IpAddr>().ok())
    .map(|ip| SocketAddr::new(ip, 53))
    .collect()
}

/// A SHA-256 hash of one candidate hostname.
type Hash = [u8; HASH_LEN];

/// What a cache bucket holds.
#[derive(Clone)]
struct Bucket {
    /// When the entry stops being usable.
    expiry: Instant,
    /// Every full hash the server reported for this prefix.
    hashes: Vec<Hash>,
}

/// A hash-prefix checker for one list.
pub struct Checker {
    /// The upstream to ask.
    upstream: Arc<Client>,
    /// The suffix appended to the prefix labels.
    suffix: String,
    /// The bucket cache, keyed by hash prefix.
    cache: Mutex<HashMap<[u8; PREFIX_LEN], Bucket>>,
    /// How long a bucket stays usable.
    cache_time: Duration,
    /// The largest number of buckets kept.
    cache_size: usize,
}

impl Checker {
    /// Builds a checker around an already-resolved upstream.
    pub fn new(
        upstream: Arc<Client>,
        suffix: impl Into<String>,
        cache_time: Duration,
        cache_size: usize,
    ) -> Self {
        Self {
            upstream,
            suffix: suffix.into(),
            cache: Mutex::new(HashMap::new()),
            cache_time,
            cache_size,
        }
    }

    /// Resolves the family resolver and builds a checker for it.
    pub async fn connect(
        suffix: impl Into<String>,
        cache_time: Duration,
        cache_size: usize,
    ) -> Result<Self, crate::client::Error> {
        let up = addr::parse(SERVER)
            .ok()
            .and_then(|e| e.upstream)
            .ok_or_else(|| crate::client::Error::Unsupported(SERVER.into()))?;

        let client = Client::connect(
            up,
            &bootstrap(),
            TIMEOUT,
            false,
            crate::client::tls_config(),
        )
        .await?;

        Ok(Self::new(Arc::new(client), suffix, cache_time, cache_size))
    }

    /// Reports whether `host` is on the list.
    ///
    /// A lookup failure is reported as "not listed": a resolver outage must
    /// not start blocking the whole internet.
    pub async fn check(&self, host: &str) -> bool {
        let hashes = hostname_hashes(host);
        if hashes.is_empty() {
            return false;
        }

        let (found, blocked, to_request) = self.find_in_cache(&hashes);
        if found {
            return blocked;
        }

        let Some(received) = self.lookup(&to_request).await else {
            return false;
        };

        self.store_in_cache(&to_request, &received);

        to_request.iter().any(|h| received.contains(h))
    }

    /// Builds and sends the `TXT` question, returning the hashes it reported.
    async fn lookup(&self, hashes: &[Hash]) -> Option<Vec<Hash>> {
        let mut question = String::new();
        for h in hashes {
            question.push_str(&hex(&h[..PREFIX_LEN]));
            question.push('.');
        }
        question.push_str(&self.suffix);
        question.push('.');

        let name = Name::from_utf8(&question).ok()?;
        let mut req = Message::query();
        req.metadata.id = rand::random::<u16>();
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(name, RecordType::TXT));

        let resp = self.upstream.exchange(&req, TIMEOUT).await.ok()?;

        let mut out = Vec::new();
        for rec in &resp.answers {
            let RData::TXT(txt) = &rec.data else {
                continue;
            };
            for part in &txt.txt_data {
                let Ok(s) = std::str::from_utf8(part) else {
                    continue;
                };
                if s.len() != HEX_LEN {
                    continue;
                }
                if let Some(h) = unhex(s) {
                    out.push(h);
                }
            }
        }

        Some(out)
    }

    /// Looks the candidate hashes up in the bucket cache.
    ///
    /// Returns whether the answer is already known, what it is, and which
    /// hashes still need asking about.
    fn find_in_cache(&self, hashes: &[Hash]) -> (bool, bool, Vec<Hash>) {
        let now = Instant::now();
        let cache = self.cache.lock();

        let mut to_request = Vec::new();
        for h in hashes {
            let mut pref = [0u8; PREFIX_LEN];
            pref.copy_from_slice(&h[..PREFIX_LEN]);

            match cache.get(&pref) {
                Some(b) if now < b.expiry => {
                    if hashes.iter().any(|c| b.hashes.contains(c)) {
                        return (true, true, Vec::new());
                    }
                }
                _ => to_request.push(*h),
            }
        }

        if to_request.is_empty() {
            // Every bucket was cached and none matched.
            return (true, false, Vec::new());
        }

        (false, false, to_request)
    }

    /// Records what the server reported, including the empty buckets.
    ///
    /// Caching an empty bucket is the point: it is what stops a name that is
    /// *not* on the list from being looked up again on every query.
    fn store_in_cache(&self, requested: &[Hash], received: &[Hash]) {
        let expiry = Instant::now() + self.cache_time;
        let mut cache = self.cache.lock();

        let mut by_prefix: HashMap<[u8; PREFIX_LEN], Vec<Hash>> = HashMap::new();
        for h in received {
            let mut pref = [0u8; PREFIX_LEN];
            pref.copy_from_slice(&h[..PREFIX_LEN]);
            by_prefix.entry(pref).or_default().push(*h);
        }

        for (pref, hashes) in by_prefix {
            cache.insert(pref, Bucket { expiry, hashes });
        }

        for h in requested {
            let mut pref = [0u8; PREFIX_LEN];
            pref.copy_from_slice(&h[..PREFIX_LEN]);
            cache.entry(pref).or_insert_with(|| Bucket {
                expiry,
                hashes: Vec::new(),
            });
        }

        // A crude bound rather than an LRU: the cache holds tiny entries and
        // exists to stop a flood of lookups, not to be precise.
        if self.cache_size > 0 && cache.len() > self.cache_size {
            let now = Instant::now();
            cache.retain(|_, b| now < b.expiry);
            if cache.len() > self.cache_size {
                cache.clear();
            }
        }
    }
}

/// Hashes the names that should be checked for `host`.
///
/// Only the last few labels are considered, and the public suffix itself is
/// not checked.  This build stops before the final label rather than
/// consulting a public suffix list, so a name under a multi-label suffix such
/// as `co.uk` contributes one extra prefix to the question — harmless, since
/// no such entry exists in the database.
pub fn hostname_hashes(host: &str) -> Vec<Hash> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Vec::new();
    }

    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return Vec::new();
    }

    let start = labels.len().saturating_sub(SUBDOMAIN_LIMIT);
    let considered = &labels[start..];

    let mut out = Vec::new();
    for i in 0..considered.len().saturating_sub(1) {
        out.push(sha256(considered[i..].join(".").as_bytes()));
    }

    out
}

/// The SHA-256 of a byte string.
fn sha256(data: &[u8]) -> Hash {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(d.as_ref());

    out
}

/// Lowercase hexadecimal, as the question labels are written.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }

    s
}

/// Parses a full hash written in hexadecimal.
fn unhex(s: &str) -> Option<Hash> {
    if s.len() != HEX_LEN {
        return None;
    }

    let mut out = [0u8; HASH_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_suffix_is_not_checked() {
        // Hashing the bare TLD would ask about a bucket that cannot match and
        // would leak one more prefix than necessary.
        assert_eq!(hostname_hashes("example.com").len(), 1);
        assert_eq!(hostname_hashes("www.example.com").len(), 2);
        assert_eq!(hostname_hashes("com").len(), 0);
        assert_eq!(hostname_hashes("").len(), 0);
    }

    #[test]
    fn only_the_last_four_labels_are_considered() {
        // a.b.c.d.example.com -> c.d.example.com and its parents.
        assert_eq!(hostname_hashes("a.b.c.d.example.com").len(), 3);
    }

    #[test]
    fn hashing_matches_the_reference_vectors() {
        // SHA-256 of "example.com", from any implementation.
        let h = sha256(b"example.com");
        assert_eq!(
            hex(&h),
            "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947"
        );
    }

    #[test]
    fn hex_round_trips() {
        let h = sha256(b"anything");
        assert_eq!(unhex(&hex(&h)).unwrap(), h);
        assert_eq!(unhex("short"), None);
        assert_eq!(unhex(&"z".repeat(HEX_LEN)), None);
    }

    #[test]
    fn the_trailing_dot_and_case_do_not_matter() {
        assert_eq!(
            hostname_hashes("Example.COM."),
            hostname_hashes("example.com")
        );
    }

    #[test]
    fn the_bootstrap_addresses_are_the_family_resolvers() {
        let b = bootstrap();
        assert_eq!(b.len(), 4);
        assert!(
            b.iter().all(|a| a.port() == 53),
            "bootstrap speaks plain DNS, which lives on 53; 443 is where the \
             same hosts serve DoH and answers no plain query"
        );
        assert!(b.iter().any(|a| a.ip().is_ipv6()));
    }

    #[test]
    fn a_cached_empty_bucket_answers_without_a_lookup() {
        let up = addr::parse(SERVER).unwrap().upstream.unwrap();
        let checker = Checker::new(
            Arc::new(Client::offline(up)),
            SAFE_BROWSING_SUFFIX,
            Duration::from_secs(60),
            1024,
        );

        let hashes = hostname_hashes("example.com");
        assert!(!checker.find_in_cache(&hashes).0, "nothing cached yet");

        checker.store_in_cache(&hashes, &[]);
        let (found, blocked, rest) = checker.find_in_cache(&hashes);
        assert!(found, "the empty bucket is an answer");
        assert!(!blocked);
        assert!(rest.is_empty());
    }

    #[test]
    fn a_matching_hash_in_the_cache_blocks() {
        let up = addr::parse(SERVER).unwrap().upstream.unwrap();
        let checker = Checker::new(
            Arc::new(Client::offline(up)),
            SAFE_BROWSING_SUFFIX,
            Duration::from_secs(60),
            1024,
        );

        let hashes = hostname_hashes("example.com");
        checker.store_in_cache(&hashes, &hashes);

        let (found, blocked, _) = checker.find_in_cache(&hashes);
        assert!(found);
        assert!(blocked);
    }
}
