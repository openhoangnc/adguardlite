//! Parsing of upstream resolver specifications.
//!
//! AdGuard Home accepts a small language here, and the details matter for
//! config compatibility:
//!
//! ```text
//! 1.1.1.1                         plain DNS on port 53
//! 1.1.1.1:5353                    plain DNS on an explicit port
//! udp://dns.example               plain DNS, explicit scheme
//! tcp://dns.example               DNS over TCP
//! tls://dns.adguard.com           DNS-over-TLS
//! https://dns.quad9.net/dns-query DNS-over-HTTPS
//! quic://dns.adguard.com          DNS-over-QUIC
//! sdns://...                      a DNSCrypt/DoH stamp
//! [/example.com/]1.1.1.1          only for example.com and its subdomains
//! [/example.com/]#                use the default resolvers for this domain
//! [//]1.1.1.1                     only for unqualified names
//! ```

use std::fmt;

/// The transport an upstream speaks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Transport {
    /// Plain DNS over UDP, falling back to TCP on truncation.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS-over-TLS.
    Tls,
    /// DNS-over-HTTPS.
    Https,
    /// DNS-over-QUIC.
    Quic,
    /// A DNSCrypt or DoH server described by a `sdns://` stamp.
    Stamp,
}

impl Transport {
    /// The port used when the specification omits one.
    pub const fn default_port(self) -> u16 {
        match self {
            Transport::Udp | Transport::Tcp => 53,
            Transport::Tls | Transport::Quic => 853,
            Transport::Https => 443,
            Transport::Stamp => 443,
        }
    }

    /// The scheme this transport is written with.
    pub const fn scheme(self) -> &'static str {
        match self {
            Transport::Udp => "udp",
            Transport::Tcp => "tcp",
            Transport::Tls => "tls",
            Transport::Https => "https",
            Transport::Quic => "quic",
            Transport::Stamp => "sdns",
        }
    }
}

/// One upstream resolver.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Upstream {
    /// The transport to use.
    pub transport: Transport,
    /// The host, as written: a literal address or a hostname.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The URL path, for DNS-over-HTTPS.
    pub path: String,
    /// The specification this was parsed from, used in the query log.
    pub original: String,
}

impl Upstream {
    /// The `host:port` authority, bracketing IPv6 literals.
    pub fn authority(&self) -> String {
        if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The address string used in the query log.
    ///
    /// Upstream logs the normalised form with an explicit port, e.g.
    /// `https://dns10.quad9.net:443/dns-query` for a DoH upstream written
    /// without one, and `9.9.9.10:53` for plain DNS.
    pub fn label(&self) -> String {
        match self.transport {
            Transport::Udp | Transport::Tcp => self.authority(),
            Transport::Stamp => self.original.clone(),
            t => format!("{}://{}{}", t.scheme(), self.authority(), self.path),
        }
    }

    /// Reports whether this upstream is implemented by this build.
    pub const fn is_supported(&self) -> bool {
        matches!(
            self.transport,
            Transport::Udp | Transport::Tcp | Transport::Tls | Transport::Https
        )
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

/// A configured upstream, together with the domains it is restricted to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UpstreamEntry {
    /// The domains this upstream serves.  Empty means "all domains".
    ///
    /// An empty string in this list is the `[//]` form, meaning unqualified
    /// names only.
    pub domains: Vec<String>,
    /// The resolver, or `None` for the `#` form, which defers to the defaults.
    pub upstream: Option<Upstream>,
}

impl UpstreamEntry {
    /// Reports whether this entry applies to every domain.
    pub fn is_default(&self) -> bool {
        self.domains.is_empty()
    }
}

/// Why an upstream specification could not be parsed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    /// The line held no upstream.
    #[error("blank or comment line")]
    Empty,
    /// The `[/domain/]` prefix was malformed.
    #[error("unterminated domain list in {0:?}")]
    UnterminatedDomains(String),
    /// The address itself was malformed.
    #[error("invalid upstream {0:?}: {1}")]
    Invalid(String, String),
}

/// Parses one upstream specification line.
pub fn parse(line: &str) -> Result<UpstreamEntry, ParseError> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return Err(ParseError::Empty);
    }

    let (domains, rest) = split_domains(t)?;

    // A bare `#` means "use the default upstreams for these domains".
    if rest == "#" {
        return Ok(UpstreamEntry { domains, upstream: None });
    }

    let upstream = parse_address(rest)?;

    Ok(UpstreamEntry { domains, upstream: Some(upstream) })
}

/// Splits an optional `[/a.com/b.com/]` prefix from the address.
fn split_domains(t: &str) -> Result<(Vec<String>, &str), ParseError> {
    let Some(after_open) = t.strip_prefix("[/") else {
        // `[//]addr` restricts to unqualified names.
        if let Some(rest) = t.strip_prefix("[//]") {
            return Ok((vec![String::new()], rest.trim()));
        }

        return Ok((Vec::new(), t));
    };

    let close = after_open
        .find("/]")
        .ok_or_else(|| ParseError::UnterminatedDomains(t.to_string()))?;

    let domains: Vec<String> = after_open[..close]
        .split('/')
        .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();

    Ok((domains, after_open[close + 2..].trim()))
}

/// Parses the address portion of a specification.
fn parse_address(s: &str) -> Result<Upstream, ParseError> {
    let invalid = |m: &str| ParseError::Invalid(s.to_string(), m.to_string());

    let (transport, rest) = match s.split_once("://") {
        Some(("udp", r)) => (Transport::Udp, r),
        Some(("tcp", r)) => (Transport::Tcp, r),
        Some(("tls", r)) => (Transport::Tls, r),
        Some(("https", r)) => (Transport::Https, r),
        Some(("h3", r)) => (Transport::Https, r),
        Some(("quic", r)) => (Transport::Quic, r),
        Some(("sdns", r)) => {
            // A stamp is opaque: keep it verbatim rather than trying to
            // decode it here.
            return Ok(Upstream {
                transport: Transport::Stamp,
                host: r.to_string(),
                port: Transport::Stamp.default_port(),
                path: String::new(),
                original: s.to_string(),
            });
        }
        Some((scheme, _)) => return Err(invalid(&format!("unknown scheme {scheme:?}"))),
        None => (Transport::Udp, s),
    };

    // Split off the URL path, which only DNS-over-HTTPS uses.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, String::new()),
    };

    let (host, port) = split_host_port(authority, transport.default_port())
        .ok_or_else(|| invalid("malformed host:port"))?;

    if host.is_empty() {
        return Err(invalid("empty host"));
    }

    let path = if transport == Transport::Https && path.is_empty() {
        "/dns-query".to_string()
    } else {
        path
    };

    Ok(Upstream { transport, host, port, path, original: s.to_string() })
}

/// Splits `host:port`, handling bracketed IPv6 literals and bare IPv6
/// addresses.
fn split_host_port(a: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = a.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = rest[..close].to_string();
        let after = &rest[close + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };

        return Some((host, port));
    }

    // A bare IPv6 literal has more than one colon and carries no port.
    if a.matches(':').count() > 1 {
        return a.parse::<std::net::Ipv6Addr>().ok().map(|_| (a.to_string(), default_port));
    }

    match a.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((a.to_string(), default_port)),
    }
}

/// Parses a list of upstream specification lines, skipping blanks and
/// comments.  Returns the entries and the lines that failed, so callers can
/// log them without aborting startup — which is what upstream does.
pub fn parse_list<'a>(
    lines: impl IntoIterator<Item = &'a str>,
) -> (Vec<UpstreamEntry>, Vec<(String, ParseError)>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for l in lines {
        match parse(l) {
            Ok(e) => ok.push(e),
            Err(ParseError::Empty) => {}
            Err(e) => bad.push((l.to_string(), e)),
        }
    }

    (ok, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up(s: &str) -> Upstream {
        parse(s).unwrap().upstream.unwrap()
    }

    #[test]
    fn plain_addresses_default_to_udp_port_53() {
        let u = up("1.1.1.1");
        assert_eq!(u.transport, Transport::Udp);
        assert_eq!(u.host, "1.1.1.1");
        assert_eq!(u.port, 53);
        assert_eq!(u.authority(), "1.1.1.1:53");
    }

    #[test]
    fn explicit_ports_are_honoured() {
        assert_eq!(up("1.1.1.1:5353").port, 5353);
        assert_eq!(up("dns.example:5353").host, "dns.example");
    }

    #[test]
    fn ipv6_literals_parse_bare_and_bracketed() {
        let u = up("2620:fe::10");
        assert_eq!(u.host, "2620:fe::10");
        assert_eq!(u.port, 53);
        assert_eq!(u.authority(), "[2620:fe::10]:53");

        let u = up("[2620:fe::10]:5353");
        assert_eq!(u.host, "2620:fe::10");
        assert_eq!(u.port, 5353);
    }

    #[test]
    fn schemes_select_transport_and_default_port() {
        assert_eq!(up("tcp://1.1.1.1").transport, Transport::Tcp);
        assert_eq!(up("tls://dns.adguard.com").transport, Transport::Tls);
        assert_eq!(up("tls://dns.adguard.com").port, 853);
        assert_eq!(up("quic://dns.adguard.com").port, 853);
        assert_eq!(up("https://dns.quad9.net/dns-query").port, 443);
    }

    #[test]
    fn doh_keeps_its_path_and_defaults_it() {
        let u = up("https://dns.quad9.net/dns-query");
        assert_eq!(u.host, "dns.quad9.net");
        assert_eq!(u.path, "/dns-query");

        // A DoH URL with no path gets the conventional one.
        assert_eq!(up("https://dns.quad9.net").path, "/dns-query");
    }

    #[test]
    fn parses_the_default_config_upstreams() {
        // Exactly what a fresh AdGuard Home writes.
        for s in [
            "https://dns10.quad9.net/dns-query",
            "9.9.9.10",
            "149.112.112.10",
            "2620:fe::10",
            "2620:fe::fe:10",
        ] {
            assert!(parse(s).is_ok(), "{s} should parse");
        }
    }

    #[test]
    fn domain_specific_upstreams() {
        let e = parse("[/example.com/]1.1.1.1").unwrap();
        assert_eq!(e.domains, ["example.com"]);
        assert_eq!(e.upstream.unwrap().host, "1.1.1.1");
        assert!(!parse("[/example.com/]1.1.1.1").unwrap().is_default());

        let e = parse("[/a.com/b.com/]tls://dns.example").unwrap();
        assert_eq!(e.domains, ["a.com", "b.com"]);

        // The `#` form defers to the default upstreams.
        let e = parse("[/example.com/]#").unwrap();
        assert_eq!(e.domains, ["example.com"]);
        assert!(e.upstream.is_none());

        // `[//]` restricts to unqualified names.
        let e = parse("[//]1.1.1.1").unwrap();
        assert_eq!(e.domains, [""]);
    }

    #[test]
    fn plain_entries_are_defaults() {
        assert!(parse("1.1.1.1").unwrap().is_default());
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(parse("").unwrap_err(), ParseError::Empty);
        assert_eq!(parse("  # a comment").unwrap_err(), ParseError::Empty);
        assert!(matches!(
            parse("[/example.com 1.1.1.1"),
            Err(ParseError::UnterminatedDomains(_))
        ));
        assert!(matches!(parse("ftp://example.com"), Err(ParseError::Invalid(..))));
    }

    #[test]
    fn the_log_label_carries_an_explicit_port() {
        // This is the exact form a real AdGuard Home writes to querylog.json.
        assert_eq!(
            up("https://dns10.quad9.net/dns-query").label(),
            "https://dns10.quad9.net:443/dns-query"
        );
        assert_eq!(up("9.9.9.10").label(), "9.9.9.10:53");
        assert_eq!(up("tls://dns.adguard.com").label(), "tls://dns.adguard.com:853");
        assert_eq!(up("2620:fe::10").label(), "[2620:fe::10]:53");
    }

    #[test]
    fn reports_which_transports_are_implemented() {
        assert!(up("1.1.1.1").is_supported());
        assert!(up("tls://dns.example").is_supported());
        assert!(up("https://dns.example/dns-query").is_supported());
        assert!(!up("quic://dns.example").is_supported());
        assert!(!up("sdns://AQIAAAA").is_supported());
    }

    #[test]
    fn parse_list_skips_blanks_and_collects_failures() {
        let (ok, bad) = parse_list(["1.1.1.1", "", "# c", "ftp://x", "tls://dns.example"]);
        assert_eq!(ok.len(), 2);
        assert_eq!(bad.len(), 1);
    }
}
