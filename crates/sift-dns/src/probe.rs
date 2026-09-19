//! Shutting out a source that connects and never asks anything.
//!
//! An encrypted listener reachable from the internet is scanned, and every
//! visit costs a TLS handshake -- the most expensive thing an unauthenticated
//! stranger can make this process do.  They arrive as fast as whatever is
//! doing it reconnects: one source dialling the DoT port by address was enough
//! to fill the log twice a second with rustls' complaint about the IP address
//! it had put in the SNI extension, and to pay for a signature each time.
//!
//! The rate limiter next door cannot help, and must not be made to.  It is a
//! defence against *datagram* amplification and deliberately leaves a
//! connection alone: a client that completed a handshake cannot have spoofed
//! its address, and limiting streams by rate cut off every client behind one
//! busy address -- a NAT, an office, a phone hotspot -- which is the bug
//! `ratelimit_diff.py` now guards against.
//!
//! What separates a scanner from a busy client is not the rate, it is that a
//! real client *asks something*.  A DoT client opens a connection in order to
//! send a query; a scanner handshakes, learns what it came for, and leaves.
//! So only connections that asked nothing at all are counted here, a single
//! answered query clears an address's record, and the count decays: a monitor
//! that opens a connection a minute to see whether the port is up never
//! reaches the threshold, while a scanner reaches it in seconds.  A busy NAT
//! is answering queries by definition, so it cannot be shut out.
//!
//! Two deliberate limits on what this counts:
//!
//! - **A local address is never shut out.**  The threat is the public
//!   internet, and a liveness check from the LAN that connects and closes is
//!   the shape this looks for without being the thing it is for.
//! - **An unvalidated QUIC address is never counted.**  A QUIC initial packet
//!   can carry a forged source, so counting one would let a spoofer lock a
//!   victim out of DoQ.  The caller records a wasted connection only once the
//!   handshake has proved the address, which is also why nothing here is
//!   reachable from the UDP path at all.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use parking_lot::{Mutex, RwLock};

/// How the guard decides, and for how long.
#[derive(Clone, Debug)]
pub struct Config {
    /// Connections that ask nothing, within `window`, before a source is shut
    /// out.  Zero switches the guard off.
    pub strikes: u32,
    /// The span the strikes are counted over.
    pub window: Duration,
    /// How long a source is refused once it has run out of strikes.
    pub penalty: Duration,
    /// Whether an address on this network is left alone.
    ///
    /// The threat is the public internet, and a liveness check from the LAN
    /// that connects and closes is the shape this looks for without being the
    /// thing it is for.  Only the tests turn it off, so the refusal can be
    /// driven over loopback.
    pub exempt_local: bool,
    /// Addresses that are never shut out.
    ///
    /// This is `ratelimit_whitelist`: an operator who has already said an
    /// address is exempt from one defence means it, and reusing the setting
    /// keeps the config file exactly what the Go build writes.
    pub allowlist: Vec<IpAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            // Six in a minute is far more than a client or a monitor makes,
            // and a scanner at two a second reaches it in three seconds.
            strikes: 6,
            window: Duration::from_secs(60),
            penalty: Duration::from_secs(600),
            exempt_local: true,
            allowlist: Vec::new(),
        }
    }
}

/// What is known about one source address.
#[derive(Clone, Copy, Debug)]
struct Mark {
    /// Connections that asked nothing since `first`.
    strikes: u32,
    /// When the current window started.
    first: Instant,
    /// When the source may connect again, once it has been shut out.
    until: Option<Instant>,
}

/// How many addresses may accumulate before a sweep is forced.
const SWEEP_AT: usize = 16_384;

/// Refuses connections from a source that has proved it never asks anything.
///
/// The configuration sits behind its own lock because `/control/dns_config`
/// can change the allowlist on a running server.
pub struct Guard {
    cfg: RwLock<Config>,
    marks: Mutex<AHashMap<IpAddr, Mark>>,
}

impl Guard {
    /// Builds a guard.
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: RwLock::new(cfg),
            marks: Mutex::new(AHashMap::new()),
        }
    }

    /// Replaces the configuration on a running guard.
    ///
    /// The marks are kept, unlike the rate limiter's buckets: a reconfigure
    /// happens whenever an operator saves the DNS settings, and dropping them
    /// would hand every scanner a fresh start each time.  An address added to
    /// the allowlist is exempt at once regardless, because `admits` consults
    /// the list before the marks.
    pub fn set_config(&self, cfg: Config) {
        *self.cfg.write() = cfg;
    }

    /// Reports whether a connection from `ip` should be accepted.
    ///
    /// Called before the TLS handshake, which is the whole point: the
    /// handshake is the cost being avoided.
    pub fn admits(&self, ip: IpAddr) -> bool {
        if self.exempt(ip) {
            return true;
        }

        let now = Instant::now();
        let mut marks = self.marks.lock();
        let Some(m) = marks.get(&ip) else {
            return true;
        };

        match m.until {
            Some(t) if now < t => false,
            // The penalty is served.  Forget the address rather than hold the
            // strikes against it, so a client that was misconfigured and has
            // been fixed is simply a client again.
            Some(_) => {
                marks.remove(&ip);

                true
            }
            None => true,
        }
    }

    /// Records how one finished connection from `ip` behaved.
    ///
    /// `served` is the number of queries it was answered, so the two cases a
    /// caller has are one call.
    pub fn record(&self, ip: IpAddr, served: u32) {
        if served == 0 {
            self.wasted(ip);
        } else {
            self.served(ip);
        }
    }

    /// Records that a connection from `ip` answered at least one query.
    pub fn served(&self, ip: IpAddr) {
        if self.exempt(ip) {
            return;
        }

        self.marks.lock().remove(&ip);
    }

    /// Records that a connection from `ip` closed without asking anything.
    ///
    /// The caller must only report an address the transport has proved --
    /// anything accepted over TCP, or a QUIC connection whose handshake
    /// completed.
    pub fn wasted(&self, ip: IpAddr) {
        let (strikes, window, penalty) = {
            let cfg = self.cfg.read();
            if cfg.strikes == 0 || cfg.allowlist.contains(&ip) || (cfg.exempt_local && is_local(ip))
            {
                return;
            }

            (cfg.strikes, cfg.window, cfg.penalty)
        };

        let now = Instant::now();
        let mut marks = self.marks.lock();
        if marks.len() >= SWEEP_AT {
            marks.retain(|_, m| {
                m.until.is_some_and(|t| now < t) || now.duration_since(m.first) < window
            });
        }

        let m = marks.entry(ip).or_insert(Mark {
            strikes: 0,
            first: now,
            until: None,
        });

        // Already shut out: nothing it does while refused counts again.
        if m.until.is_some_and(|t| now < t) {
            return;
        }

        if now.duration_since(m.first) > window {
            m.strikes = 0;
            m.first = now;
            m.until = None;
        }

        m.strikes += 1;
        if m.strikes >= strikes {
            m.until = Some(now + penalty);

            // The one line worth logging, and the one rustls could not give:
            // its warning names the address the client *dialled*, never the
            // client.  Bounded by the penalty, so it cannot itself flood.
            tracing::info!(
                client = %ip,
                connections = m.strikes,
                seconds = penalty.as_secs(),
                "refusing a source that keeps connecting without asking anything"
            );
        }
    }

    /// Reports whether `ip` is outside the guard's remit altogether.
    fn exempt(&self, ip: IpAddr) -> bool {
        let cfg = self.cfg.read();

        cfg.strikes == 0 || cfg.allowlist.contains(&ip) || (cfg.exempt_local && is_local(ip))
    }

    /// The number of tracked addresses.
    pub fn tracked(&self) -> usize {
        self.marks.lock().len()
    }

    /// Forgets every address.
    pub fn clear(&self) {
        self.marks.lock().clear();
    }
}

impl Default for Guard {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

/// Reports whether an address belongs to this network rather than the
/// internet.
///
/// `Ipv6Addr::is_unique_local` and `is_unicast_link_local` are still
/// unstable, so `fc00::/7` and `fe80::/10` are spelled out.
fn is_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_loopback() || a.is_private() || a.is_link_local() || a.is_unspecified()
        }
        IpAddr::V6(a) => {
            let o = a.octets();

            a.is_loopback()
                || a.is_unspecified()
                || o[0] & 0xfe == 0xfc
                || (o[0] == 0xfe && o[1] & 0xc0 == 0x80)
                // An address mapped from IPv4 is judged as that address.
                || a.to_ipv4_mapped().is_some_and(|v4| {
                    v4.is_loopback() || v4.is_private() || v4.is_link_local()
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A public address, so nothing is exempt by locality.
    fn scanner() -> IpAddr {
        "198.51.100.7".parse().unwrap()
    }

    /// Rewinds an address's window so the test does not have to wait.
    fn rewind_window(g: &Guard, ip: IpAddr, by: Duration) {
        let mut marks = g.marks.lock();
        if let Some(m) = marks.get_mut(&ip) {
            m.first -= by;
        }
    }

    /// Rewinds an address's penalty so the test does not have to wait.
    fn rewind_penalty(g: &Guard, ip: IpAddr, by: Duration) {
        let mut marks = g.marks.lock();
        if let Some(m) = marks.get_mut(&ip) {
            m.until = m.until.map(|t| t - by);
        }
    }

    fn guard(strikes: u32) -> Guard {
        Guard::new(Config {
            strikes,
            ..Default::default()
        })
    }

    #[test]
    fn a_source_that_never_asks_anything_is_refused() {
        let g = guard(3);
        let ip = scanner();

        for i in 0..2 {
            assert!(g.admits(ip), "strike {i} is not yet the last one");
            g.wasted(ip);
        }

        assert!(g.admits(ip), "two of three strikes is still a welcome");
        g.wasted(ip);
        assert!(!g.admits(ip), "the third strike shuts it out");
    }

    #[test]
    fn a_source_that_asks_something_is_never_refused() {
        // The whole point: a busy client -- or a NAT full of them -- opens
        // connections at any rate it likes.  Only silence counts, and one
        // answered query clears the record, so the alternation below can run
        // forever without the guard ever noticing it.
        let g = guard(3);
        let ip = scanner();

        for _ in 0..100 {
            assert!(g.admits(ip));
            g.wasted(ip);
            g.wasted(ip);
            g.served(ip);
        }

        assert!(g.admits(ip));
        assert_eq!(g.tracked(), 0, "an answered query leaves nothing behind");
    }

    #[test]
    fn connections_spread_out_do_not_accumulate() {
        // A liveness monitor connects to see whether the port answers and
        // closes without asking anything.  At one a minute it must never be
        // shut out, however long it runs -- which is why the strikes are
        // counted over a window rather than for ever.
        let g = guard(3);
        let ip = scanner();

        for _ in 0..50 {
            g.wasted(ip);
            rewind_window(&g, ip, Duration::from_secs(61));
            assert!(g.admits(ip), "one connection a minute is not a scan");
        }
    }

    #[test]
    fn the_penalty_runs_out() {
        let g = guard(2);
        let ip = scanner();

        g.wasted(ip);
        g.wasted(ip);
        assert!(!g.admits(ip));

        rewind_penalty(&g, ip, Duration::from_secs(601));
        assert!(g.admits(ip), "the penalty is served");
        assert_eq!(
            g.tracked(),
            0,
            "and the address is forgotten rather than kept on one strike"
        );
    }

    #[test]
    fn a_local_address_is_never_refused() {
        let g = guard(1);

        for ip in [
            "127.0.0.1",
            "192.168.1.10",
            "10.4.4.4",
            "172.16.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.10",
        ] {
            let ip: IpAddr = ip.parse().unwrap();
            for _ in 0..10 {
                g.wasted(ip);
            }

            assert!(g.admits(ip), "{ip} is on this network, not the internet");
        }

        assert_eq!(g.tracked(), 0);
    }

    #[test]
    fn zero_strikes_switches_the_guard_off() {
        let g = guard(0);
        let ip = scanner();

        for _ in 0..1000 {
            g.wasted(ip);
        }

        assert!(g.admits(ip));
        assert_eq!(g.tracked(), 0);
    }

    #[test]
    fn an_allowlisted_address_is_exempt_at_once() {
        let g = guard(1);
        let ip = scanner();

        g.wasted(ip);
        assert!(!g.admits(ip));

        // `ratelimit_whitelist` is the operator's escape hatch, and saving it
        // has to take effect on the running server rather than at the next
        // restart.
        g.set_config(Config {
            strikes: 1,
            allowlist: vec![ip],
            ..Default::default()
        });
        assert!(g.admits(ip), "the allowlist is consulted before the marks");
    }

    #[test]
    fn a_public_address_is_not_local() {
        for ip in ["198.51.100.7", "8.8.8.8", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!is_local(ip.parse().unwrap()), "{ip} is on the internet");
        }
    }
}
