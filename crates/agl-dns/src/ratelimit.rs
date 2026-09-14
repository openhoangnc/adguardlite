//! Per-client rate limiting.
//!
//! Clients are grouped by subnet — `/24` for IPv4 and `/56` for IPv6 by
//! default — so a single host cannot evade the limit by rotating addresses
//! within its prefix, matching `ratelimit_subnet_len_ipv4` and
//! `ratelimit_subnet_len_ipv6`.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use parking_lot::Mutex;

/// Rate-limiter settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Queries per second allowed per subnet.  Zero disables limiting.
    pub per_second: u32,
    /// IPv4 prefix length used for grouping.
    pub subnet_len_v4: u8,
    /// IPv6 prefix length used for grouping.
    pub subnet_len_v6: u8,
    /// Addresses exempt from limiting.
    pub allowlist: Vec<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            per_second: 20,
            subnet_len_v4: 24,
            subnet_len_v6: 56,
            allowlist: Vec::new(),
        }
    }
}

/// One subnet's token bucket.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// A token-bucket rate limiter keyed by client subnet.
pub struct Limiter {
    cfg: Config,
    buckets: Mutex<AHashMap<IpAddr, Bucket>>,
}

/// How long an idle bucket is kept before being swept.
const IDLE_TTL: Duration = Duration::from_secs(300);

/// How many buckets may accumulate before a sweep is forced.
const SWEEP_AT: usize = 16_384;

impl Limiter {
    /// Builds a limiter.
    pub fn new(cfg: Config) -> Self {
        Self { cfg, buckets: Mutex::new(AHashMap::new()) }
    }

    /// Reports whether limiting is switched off.
    pub fn is_disabled(&self) -> bool {
        self.cfg.per_second == 0
    }

    /// Reports whether a query from `ip` should be allowed.
    pub fn allow(&self, ip: IpAddr) -> bool {
        if self.is_disabled() || self.cfg.allowlist.contains(&ip) {
            return true;
        }

        let key = subnet_key(ip, self.cfg.subnet_len_v4, self.cfg.subnet_len_v6);
        let cap = f64::from(self.cfg.per_second);
        let now = Instant::now();

        let mut map = self.buckets.lock();
        if map.len() >= SWEEP_AT {
            map.retain(|_, b| now.duration_since(b.last) < IDLE_TTL);
        }

        let b = map.entry(key).or_insert(Bucket { tokens: cap, last: now });

        // Refill for the time that has passed, then spend one token.
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = (b.tokens + elapsed * cap).min(cap);
        b.last = now;

        if b.tokens >= 1.0 {
            b.tokens -= 1.0;

            true
        } else {
            false
        }
    }

    /// The number of tracked subnets.
    pub fn tracked(&self) -> usize {
        self.buckets.lock().len()
    }

    /// Drops every bucket.
    pub fn clear(&self) {
        self.buckets.lock().clear();
    }
}

/// Masks `ip` to its rate-limiting subnet.
fn subnet_key(ip: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let bits = v4.min(32);
            let masked = mask_bytes(&a.octets(), bits);

            IpAddr::V4(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&masked[..]).unwrap_or([0; 4])))
        }
        IpAddr::V6(a) => {
            let bits = v6.min(128);
            let masked = mask_bytes(&a.octets(), bits);

            IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&masked[..]).unwrap_or([0; 16]),
            ))
        }
    }
}

/// Zeroes every bit of `b` past the first `bits`.
fn mask_bytes(b: &[u8], bits: u8) -> Vec<u8> {
    let mut out = b.to_vec();
    let full = (bits / 8) as usize;
    let rem = bits % 8;

    if rem > 0 && full < out.len() {
        out[full] &= 0xFFu8 << (8 - rem);
        for x in out.iter_mut().skip(full + 1) {
            *x = 0;
        }
    } else {
        for x in out.iter_mut().skip(full) {
            *x = 0;
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_blocks() {
        let l = Limiter::new(Config { per_second: 5, ..Default::default() });
        let ip: IpAddr = "192.168.1.10".parse().unwrap();

        for i in 0..5 {
            assert!(l.allow(ip), "query {i} should be allowed");
        }
        assert!(!l.allow(ip), "the sixth query in the same instant should be limited");
    }

    #[test]
    fn a_zero_limit_disables_limiting() {
        let l = Limiter::new(Config { per_second: 0, ..Default::default() });
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        for _ in 0..1000 {
            assert!(l.allow(ip));
        }
    }

    #[test]
    fn clients_in_the_same_subnet_share_a_bucket() {
        let l = Limiter::new(Config { per_second: 2, subnet_len_v4: 24, ..Default::default() });
        assert!(l.allow("192.168.1.1".parse().unwrap()));
        assert!(l.allow("192.168.1.2".parse().unwrap()));
        assert!(!l.allow("192.168.1.3".parse().unwrap()), "same /24 shares the budget");

        // A different /24 has its own budget.
        assert!(l.allow("192.168.2.1".parse().unwrap()));
        assert_eq!(l.tracked(), 2);
    }

    #[test]
    fn ipv6_clients_are_grouped_by_prefix() {
        let l = Limiter::new(Config { per_second: 1, subnet_len_v6: 56, ..Default::default() });
        assert!(l.allow("2001:db8:0:0::1".parse().unwrap()));
        assert!(!l.allow("2001:db8:0:0::2".parse().unwrap()), "same /56");
        assert!(l.allow("2001:db8:0:ff00::1".parse().unwrap()), "different /56");
    }

    #[test]
    fn the_allowlist_is_exempt() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let l = Limiter::new(Config { per_second: 1, allowlist: vec![ip], ..Default::default() });
        for _ in 0..100 {
            assert!(l.allow(ip));
        }
    }

    #[test]
    fn tokens_refill_over_time() {
        let l = Limiter::new(Config { per_second: 10, ..Default::default() });
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        for _ in 0..10 {
            assert!(l.allow(ip));
        }
        assert!(!l.allow(ip));

        // Rewind the bucket's clock to simulate a second passing.
        {
            let mut m = l.buckets.lock();
            let key = subnet_key(ip, 24, 56);
            if let Some(b) = m.get_mut(&key) {
                b.last = Instant::now() - Duration::from_secs(1);
            }
        }
        assert!(l.allow(ip), "a second later the bucket should have refilled");
    }

    #[test]
    fn subnet_masking() {
        assert_eq!(
            subnet_key("192.168.1.77".parse().unwrap(), 24, 56),
            "192.168.1.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            subnet_key("192.168.1.77".parse().unwrap(), 16, 56),
            "192.168.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            subnet_key("192.168.1.77".parse().unwrap(), 32, 56),
            "192.168.1.77".parse::<IpAddr>().unwrap()
        );
        // A non-byte-aligned prefix.
        assert_eq!(
            subnet_key("10.1.255.1".parse().unwrap(), 12, 56),
            "10.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn clearing_drops_state() {
        let l = Limiter::new(Config { per_second: 1, ..Default::default() });
        l.allow("1.2.3.4".parse().unwrap());
        assert_eq!(l.tracked(), 1);
        l.clear();
        assert_eq!(l.tracked(), 0);
    }
}
