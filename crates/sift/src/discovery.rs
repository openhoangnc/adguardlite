//! Working out who a client is.
//!
//! A DNS query carries only an address.  Upstream gives that address a name
//! from whatever source it can — the hosts file, the ARP table, a reverse
//! lookup — and a WHOIS record for addresses from outside the network.  The
//! result is what the web interface shows next to a query and what
//! `/control/clients` reports as an automatic client.
//!
//! Every source is best-effort: a failure leaves the address nameless rather
//! than failing a query.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use sift_dns::clients::{Runtime, Source};
use sift_dns::resolver::{ClientInfo, Proto, Resolver};
use tokio::sync::mpsc;

/// How long a WHOIS exchange may take.
const WHOIS_TIMEOUT: Duration = Duration::from_secs(5);

/// The WHOIS server asked first.
const WHOIS_ROOT: &str = "whois.arin.net:43";

/// How many addresses may queue for discovery before new ones are dropped.
///
/// Dropping is the right failure: the address will be seen again on the next
/// query from that client.
const QUEUE: usize = 256;

/// The fields the API reports from a WHOIS record.
///
/// Upstream keeps only these three, so a record's other fields are read only
/// to fill in an organisation name that was not given directly.
const WHOIS_KEYS: &[&str] = &["orgname", "city", "country"];

/// Discovers client names in the background.
pub struct Discoverer {
    /// The resolver, used for reverse lookups.
    pub resolver: Arc<Resolver>,
    /// Where discovered names are recorded.
    pub runtime: Arc<Runtime>,
}

/// The handle a caller uses to submit addresses for discovery.
#[derive(Clone)]
pub struct Queue(mpsc::Sender<IpAddr>);

impl Queue {
    /// Submits an address, dropping it if the queue is full.
    pub fn submit(&self, addr: IpAddr) {
        let _ = self.0.try_send(addr);
    }
}

impl Discoverer {
    /// Reads the sources that need no network: the hosts file and the ARP
    /// table.
    pub fn prime(&self) {
        let sources = self.runtime.sources();

        if sources.hosts {
            for (addr, name) in parse_hosts(&crate::app::read_system_hosts()) {
                self.runtime.set_name(addr, name, Source::Hosts);
            }
        }

        if sources.arp {
            for (addr, mac) in read_arp_table() {
                self.runtime.set_mac(addr, mac);
            }
        }
    }

    /// Starts the discovery task and returns the queue that feeds it.
    pub fn start(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> (Queue, tokio::task::JoinHandle<()>) {
        let (tx, mut rx) = mpsc::channel(QUEUE);

        let handle = tokio::spawn(async move {
            // The local sources are cheap and worth having before the first
            // query arrives.
            self.prime();

            let mut refresh = tokio::time::interval(Duration::from_secs(300));
            refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // The first tick fires immediately; the priming above covers it.
            refresh.tick().await;

            loop {
                tokio::select! {
                    _ = shutdown.changed() => return,
                    _ = refresh.tick() => self.prime(),
                    addr = rx.recv() => match addr {
                        Some(a) => self.discover(a).await,
                        None => return,
                    },
                }
            }
        });

        (Queue(tx), handle)
    }

    /// Looks one address up through every enabled source.
    async fn discover(&self, addr: IpAddr) {
        let sources = self.runtime.sources();

        if sources.rdns
            && self.runtime.name_of(addr).is_empty()
            && let Some(name) = self.reverse_lookup(addr).await
        {
            self.runtime.set_name(addr, name, Source::Rdns);
        }

        if sources.whois && !is_local(addr) {
            let fields = whois(addr).await;
            if !fields.is_empty() {
                self.runtime.set_whois(addr, fields);
            }
        }
    }

    /// Resolves an address back to a name through this server's own resolver.
    ///
    /// Going through the resolver rather than a separate client means the
    /// lookup honours the private-network routing: a `PTR` for a local address
    /// is answered by the local resolvers, not a public one.
    async fn reverse_lookup(&self, addr: IpAddr) -> Option<String> {
        let name = Name::from_utf8(reverse_name(addr)).ok()?;
        let mut req = Message::query();
        req.metadata.id = rand::random::<u16>();
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(name, RecordType::PTR));

        let out = self
            .resolver
            .resolve(&req, Proto::Udp, &ClientInfo::default())
            .await;

        out.response()?.answers.iter().find_map(|r| match &r.data {
            RData::PTR(p) => {
                let n = p.0.to_ascii().trim_end_matches('.').to_string();
                (!n.is_empty()).then_some(n)
            }
            _ => None,
        })
    }
}

/// The `in-addr.arpa` or `ip6.arpa` name for an address.
pub fn reverse_name(addr: IpAddr) -> String {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();

            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(74);
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0x0f, b >> 4));
            }
            s.push_str("ip6.arpa.");

            s
        }
    }
}

/// Reports whether an address is on a local network.
pub fn is_local(addr: IpAddr) -> bool {
    sift_dns::resolver::default_private_networks()
        .iter()
        .any(|&(n, b)| sift_dns::clients::in_subnet(addr, n, b))
}

/// Parses a hosts file into address-to-name pairs.
///
/// Only the first name on a line is taken, which is the canonical one.
pub fn parse_hosts(text: &str) -> Vec<(IpAddr, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(addr) = parts.next().and_then(|a| a.parse::<IpAddr>().ok()) else {
            continue;
        };
        let Some(name) = parts.next() else {
            continue;
        };

        out.push((addr, name.to_string()));
    }

    out
}

/// Reads the system ARP table, returning address-to-MAC pairs.
///
/// On Linux this is `/proc/net/arp`; elsewhere `arp -an` is parsed, which is
/// the BSD and macOS form.  Anything unrecognised yields nothing.
pub fn read_arp_table() -> Vec<(IpAddr, String)> {
    if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
        return parse_proc_arp(&text);
    }

    let Ok(out) = std::process::Command::new("arp").arg("-an").output() else {
        return Vec::new();
    };

    parse_arp_command(&String::from_utf8_lossy(&out.stdout))
}

/// Parses Linux's `/proc/net/arp`.
pub fn parse_proc_arp(text: &str) -> Vec<(IpAddr, String)> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                return None;
            }

            let addr = f[0].parse::<IpAddr>().ok()?;
            let mac = f[3];
            if mac == "00:00:00:00:00:00" {
                return None;
            }

            Some((addr, mac.to_ascii_lowercase()))
        })
        .collect()
}

/// Parses the BSD and macOS `arp -an` output.
///
/// Lines look like `? (192.168.1.1) at 0:11:22:aa:bb:cc on en0 ifscope`, and
/// the octets are written without leading zeroes.
pub fn parse_arp_command(text: &str) -> Vec<(IpAddr, String)> {
    text.lines()
        .filter_map(|line| {
            let start = line.find('(')? + 1;
            let end = line[start..].find(')')? + start;
            let addr = line[start..end].parse::<IpAddr>().ok()?;

            let rest = line[end + 1..].trim_start();
            let mac = rest.strip_prefix("at ")?.split_whitespace().next()?;
            if mac.eq_ignore_ascii_case("(incomplete)") {
                return None;
            }

            let parts: Vec<&str> = mac.split(':').collect();
            if parts.len() != 6
                || !parts
                    .iter()
                    .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return None;
            }

            let normalised = parts
                .iter()
                .map(|p| format!("{:0>2}", p.to_ascii_lowercase()))
                .collect::<Vec<_>>()
                .join(":");

            Some((addr, normalised))
        })
        .collect()
}

/// Looks an address up over WHOIS, following one referral.
pub async fn whois(addr: IpAddr) -> Vec<(String, String)> {
    let Some(text) = whois_query(WHOIS_ROOT, &addr.to_string()).await else {
        return Vec::new();
    };

    let mut fields = parse_whois(&text);

    // The regional registry usually points at the one that actually holds the
    // record; one hop is enough and stops a redirect loop.
    if let Some(referral) = referral_of(&text)
        && let Some(more) = whois_query(&referral, &addr.to_string()).await
    {
        let deeper = parse_whois(&more);
        if !deeper.is_empty() {
            fields = deeper;
        }
    }

    fields
}

/// Sends one WHOIS query and reads the reply.
async fn whois_query(server: &str, query: &str) -> Option<String> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let fut = async {
        let mut s = tokio::net::TcpStream::connect(server).await.ok()?;
        s.write_all(format!("{query}\r\n").as_bytes()).await.ok()?;
        s.flush().await.ok()?;

        let mut buf = Vec::new();
        // A WHOIS record is small; a server that streams forever is a fault.
        s.take(256 * 1024).read_to_end(&mut buf).await.ok()?;

        Some(String::from_utf8_lossy(&buf).into_owned())
    };

    tokio::time::timeout(WHOIS_TIMEOUT, fut).await.ok()?
}

/// The referral server a WHOIS record names, if any.
fn referral_of(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        let Some(rest) = lower
            .strip_prefix("referralserver:")
            .or_else(|| lower.strip_prefix("refer:"))
        else {
            continue;
        };

        let host = rest
            .trim()
            .trim_start_matches("whois://")
            .trim_end_matches('/');
        if host.is_empty() {
            continue;
        }

        return Some(if host.contains(':') {
            host.to_string()
        } else {
            format!("{host}:43")
        });
    }

    None
}

/// Extracts the fields the API reports from a WHOIS record.
///
/// `descr` and `netname` stand in for a missing `orgname`, which is what
/// upstream does: the registries that omit `OrgName` put the operator's name
/// in one of those instead.
pub fn parse_whois(text: &str) -> Vec<(String, String)> {
    let mut found: BTreeMap<&str, String> = BTreeMap::new();

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };

        let value = v.trim();
        if value.is_empty() {
            continue;
        }

        let key = match k.trim().to_ascii_lowercase().as_str() {
            "orgname" | "org-name" | "descr" | "netname" => "orgname",
            "city" => "city",
            "country" => "country",
            _ => continue,
        };

        // The first value wins: later blocks describe wider allocations.
        found.entry(key).or_insert_with(|| value.to_string());
    }

    // Report them in upstream's order rather than alphabetically.
    WHOIS_KEYS
        .iter()
        .filter_map(|k| found.get(k).map(|v| ((*k).to_string(), v.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_names_are_built_the_way_dns_expects() {
        assert_eq!(
            reverse_name("1.2.3.4".parse().unwrap()),
            "4.3.2.1.in-addr.arpa."
        );
        assert_eq!(
            reverse_name("2001:db8::1".parse().unwrap()),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }

    #[test]
    fn hosts_files_yield_the_canonical_name() {
        let text = "\
# a comment
127.0.0.1   localhost localhost.localdomain
192.168.1.7 printer.lan printer

not-an-address foo
192.168.1.8
";
        let got = parse_hosts(text);
        assert_eq!(
            got,
            vec![
                ("127.0.0.1".parse().unwrap(), "localhost".to_string()),
                ("192.168.1.7".parse().unwrap(), "printer.lan".to_string()),
            ]
        );
    }

    #[test]
    fn a_trailing_comment_is_stripped() {
        let got = parse_hosts("10.0.0.1 gateway # the router\n");
        assert_eq!(got, vec![("10.0.0.1".parse().unwrap(), "gateway".into())]);
    }

    #[test]
    fn the_linux_arp_table_parses() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0
";
        let got = parse_proc_arp(text);
        assert_eq!(
            got,
            vec![(
                "192.168.1.1".parse().unwrap(),
                "aa:bb:cc:dd:ee:ff".to_string()
            )],
            "an incomplete entry is skipped"
        );
    }

    #[test]
    fn the_bsd_arp_output_parses_and_pads_octets() {
        let text = "\
? (192.168.1.1) at 0:11:22:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.5) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.6) at aa:bb:cc:dd:ee:ff on en0 [ethernet]
";
        let got = parse_arp_command(text);
        assert_eq!(
            got,
            vec![
                (
                    "192.168.1.1".parse().unwrap(),
                    "00:11:22:aa:bb:cc".to_string()
                ),
                (
                    "192.168.1.6".parse().unwrap(),
                    "aa:bb:cc:dd:ee:ff".to_string()
                ),
            ]
        );
    }

    #[test]
    fn whois_records_yield_the_reported_fields() {
        let text = "\
% this is a comment
NetRange:       93.184.216.0 - 93.184.216.255
OrgName:        MCI Communications Services, Inc.
OrgId:          MCICS
City:           Ashburn
Country:        US
OrgName:        A later, wider block
";
        let got = parse_whois(text);
        assert_eq!(
            got,
            vec![
                (
                    "orgname".to_string(),
                    "MCI Communications Services, Inc.".to_string()
                ),
                ("city".to_string(), "Ashburn".to_string()),
                ("country".to_string(), "US".to_string()),
            ],
            "the first value of each field wins, in upstream's order"
        );
    }

    #[test]
    fn a_registry_without_orgname_falls_back_to_netname() {
        // RIPE and APNIC records name the operator in netname or descr.
        let got = parse_whois("netname: EXAMPLE-NET\ncountry: NL\n");
        assert_eq!(
            got,
            vec![
                ("orgname".to_string(), "EXAMPLE-NET".to_string()),
                ("country".to_string(), "NL".to_string()),
            ]
        );
    }

    #[test]
    fn a_referral_is_recognised_in_either_spelling() {
        assert_eq!(
            referral_of("ReferralServer:  whois://whois.ripe.net\n").as_deref(),
            Some("whois.ripe.net:43")
        );
        assert_eq!(
            referral_of("refer:        whois.apnic.net\n").as_deref(),
            Some("whois.apnic.net:43")
        );
        assert_eq!(referral_of("OrgName: nothing here\n"), None);
    }

    #[test]
    fn local_addresses_are_recognised() {
        assert!(is_local("192.168.1.1".parse().unwrap()));
        assert!(is_local("10.1.2.3".parse().unwrap()));
        assert!(!is_local("93.184.216.34".parse().unwrap()));
    }
}
