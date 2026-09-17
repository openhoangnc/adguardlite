//! DNS64 synthesis, as RFC 6147 describes it.
//!
//! When a client can only reach IPv4 hosts through a NAT64 gateway, an `AAAA`
//! query that comes back empty is retried as `A` and the answers are rewritten
//! into IPv6 addresses inside the NAT64 prefix.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::AAAA;
use hickory_proto::rr::{RData, Record, RecordType};

/// The Well-Known Prefix, used when none is configured.
///
/// See [RFC 6052 section 2.1](https://datatracker.ietf.org/doc/html/rfc6052#section-2.1).
pub const WELL_KNOWN: (Ipv6Addr, u8) = (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96);

/// The longest NAT64 prefix RFC 6147 allows.
pub const MAX_PREFIX_BITS: u8 = 96;

/// The TTL cap for a synthesised answer when the negative response carried no
/// SOA to take one from.
const MAX_SYNTH_TTL: u32 = 600;

/// The configured NAT64 prefixes.
#[derive(Clone, Debug, Default)]
pub struct Prefixes(Vec<(Ipv6Addr, u8)>);

impl Prefixes {
    /// Builds a prefix set, falling back to the Well-Known Prefix when the
    /// feature is on but nothing is configured, as RFC 6147 section 5.2 says.
    ///
    /// A prefix that is not IPv6, or longer than 96 bits, is skipped: it could
    /// not address a synthesised host anyway.
    pub fn new(enabled: bool, configured: impl IntoIterator<Item = (IpAddr, u8)>) -> Self {
        if !enabled {
            return Self(Vec::new());
        }

        let mut out = Vec::new();
        for (addr, bits) in configured {
            let IpAddr::V6(a) = addr else {
                continue;
            };
            if bits > MAX_PREFIX_BITS {
                continue;
            }
            out.push((mask_v6(a, bits), bits));
        }

        if out.is_empty() {
            out.push(WELL_KNOWN);
        }

        Self(out)
    }

    /// Reports whether DNS64 is in use at all.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Reports whether an address falls inside one of the prefixes.
    pub fn contains(&self, addr: IpAddr) -> bool {
        let IpAddr::V6(a) = addr else {
            return false;
        };

        self.0.iter().any(|&(p, bits)| mask_v6(a, bits) == p)
    }

    /// Maps an IPv4 address into the first configured prefix.
    pub fn map(&self, addr: Ipv4Addr) -> Option<Ipv6Addr> {
        let &(prefix, _) = self.0.first()?;
        let mut octets = prefix.octets();
        octets[12..].copy_from_slice(&addr.octets());

        Some(Ipv6Addr::from(octets))
    }
}

/// Zeroes the bits of an IPv6 address below `bits`.
fn mask_v6(addr: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let v = u128::from(addr);
    let keep = if bits >= 128 {
        u128::MAX
    } else {
        u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0)
    };

    Ipv6Addr::from(v & keep)
}

/// Reports whether an `AAAA` response should be retried as `A`.
///
/// The answer section is filtered first: an address already inside a NAT64
/// prefix is not a real IPv6 host, so a response that holds only those counts
/// as empty.
pub fn needs_synthesis(prefixes: &Prefixes, req: &Message, resp: &mut Message) -> bool {
    if prefixes.is_empty() {
        return false;
    }

    let Some(q) = req.queries.first() else {
        return false;
    };
    if q.query_type() != RecordType::AAAA || q.query_class() != hickory_proto::rr::DNSClass::IN {
        return false;
    }

    match resp.metadata.response_code {
        // A name error is a real answer and is passed through.
        ResponseCode::NXDomain => false,
        ResponseCode::NoError => !filter_excluded(prefixes, &mut resp.answers),
        // Anything else is treated as an empty NOERROR.
        _ => true,
    }
}

/// Drops `AAAA` answers inside a NAT64 prefix, reporting whether any real one
/// remains.
fn filter_excluded(prefixes: &Prefixes, answers: &mut Vec<Record>) -> bool {
    let mut kept_real = false;
    answers.retain(|r| match &r.data {
        RData::AAAA(a) => {
            if prefixes.contains(IpAddr::V6(a.0)) {
                false
            } else {
                kept_real = true;

                true
            }
        }
        _ => true,
    });

    kept_real
}

/// Rewrites `resp` in place using the `A` answers from `a_resp`.
///
/// Returns whether anything was synthesised; an empty `A` answer leaves the
/// original response untouched, as RFC 6147 requires.
pub fn synthesize(
    prefixes: &Prefixes,
    req: &Message,
    resp: &mut Message,
    a_resp: &Message,
) -> bool {
    if a_resp.answers.is_empty() {
        return false;
    }

    // The synthesised TTL is the smaller of the A record's own TTL and the
    // negative answer's SOA TTL, or 600 seconds when there was no SOA.
    let soa_ttl = req
        .queries
        .first()
        .and_then(|q| {
            resp.authorities
                .iter()
                .find(|r| r.record_type() == RecordType::SOA && &r.name == q.name())
        })
        .map_or(MAX_SYNTH_TTL, |r| r.ttl);

    let mut answers = Vec::with_capacity(a_resp.answers.len());
    for rec in &a_resp.answers {
        let RData::A(a) = &rec.data else {
            // Non-address records, such as the CNAME chain, are carried over.
            answers.push(rec.clone());

            continue;
        };
        let Some(mapped) = prefixes.map(a.0) else {
            return false;
        };

        let mut out = Record::from_rdata(
            rec.name.clone(),
            rec.ttl.min(soa_ttl),
            RData::AAAA(AAAA(mapped)),
        );
        out.dns_class = rec.dns_class;
        answers.push(out);
    }

    resp.metadata.response_code = ResponseCode::NoError;
    resp.answers = answers;
    resp.authorities = a_resp.authorities.clone();

    true
}

/// Reports whether a `PTR` query names an address inside a NAT64 prefix.
///
/// Such a name has no real owner, so upstream answers it locally rather than
/// asking a resolver that would return nonsense.
pub fn is_nat64_ptr(prefixes: &Prefixes, req: &Message) -> bool {
    if prefixes.is_empty() {
        return false;
    }

    let Some(q) = req.queries.first() else {
        return false;
    };
    if q.query_type() != RecordType::PTR {
        return false;
    }

    let Some(addr) = addr_from_reverse(&q.name().to_ascii()) else {
        return false;
    };

    // The requirement is to match any prefix in use at the site, not only the
    // configured one, so the Well-Known Prefix always counts.
    prefixes.contains(addr) || Prefixes(vec![WELL_KNOWN]).contains(addr)
}

/// Parses an `ip6.arpa` or `in-addr.arpa` name back into an address.
pub fn addr_from_reverse(name: &str) -> Option<IpAddr> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();

    if let Some(rest) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() != 32 {
            return None;
        }

        let mut v: u128 = 0;
        // The name is written least-significant nibble first.
        for n in nibbles.iter().rev() {
            let d = u128::from(u8::from_str_radix(n, 16).ok()?);
            v = (v << 4) | d;
        }

        return Some(IpAddr::V6(Ipv6Addr::from(v)));
    }

    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = rest.split('.').collect();
        if octets.len() != 4 {
            return None;
        }

        let mut o = [0u8; 4];
        for (i, part) in octets.iter().rev().enumerate() {
            o[i] = part.parse().ok()?;
        }

        return Some(IpAddr::V4(Ipv4Addr::from(o)));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::{A, SOA};

    fn request(qt: RecordType) -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8("example.com.").unwrap(), qt));

        m
    }

    #[test]
    fn disabled_means_no_prefixes() {
        let p = Prefixes::new(false, [("64:ff9b::".parse().unwrap(), 96)]);
        assert!(p.is_empty());
    }

    #[test]
    fn enabling_without_a_prefix_uses_the_well_known_one() {
        let p = Prefixes::new(true, []);
        assert!(!p.is_empty());
        assert!(p.contains("64:ff9b::1.2.3.4".parse().unwrap()));
        assert!(!p.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn an_ipv4_prefix_is_rejected_rather_than_used() {
        let p = Prefixes::new(true, [("192.0.2.0".parse().unwrap(), 24)]);
        // Falls back to the Well-Known Prefix rather than producing nonsense.
        assert!(p.contains("64:ff9b::1".parse().unwrap()));
    }

    #[test]
    fn a_too_long_prefix_is_rejected() {
        let p = Prefixes::new(true, [("2001:db8::".parse().unwrap(), 112)]);
        assert!(!p.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn mapping_embeds_the_ipv4_address() {
        let p = Prefixes::new(true, []);
        assert_eq!(
            p.map("192.0.2.33".parse().unwrap()).unwrap(),
            "64:ff9b::c000:221".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn an_empty_aaaa_answer_asks_for_synthesis() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::AAAA);
        let mut resp = crate::msg::reply(&req, ResponseCode::NoError);
        assert!(needs_synthesis(&p, &req, &mut resp));
    }

    #[test]
    fn a_real_aaaa_answer_does_not() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::AAAA);
        let mut resp = crate::msg::reply(&req, ResponseCode::NoError);
        resp.answers = vec![Record::from_rdata(
            Name::from_utf8("example.com.").unwrap(),
            60,
            RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
        )];

        assert!(!needs_synthesis(&p, &req, &mut resp));
        assert_eq!(resp.answers.len(), 1);
    }

    #[test]
    fn an_answer_only_inside_the_prefix_counts_as_empty() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::AAAA);
        let mut resp = crate::msg::reply(&req, ResponseCode::NoError);
        resp.answers = vec![Record::from_rdata(
            Name::from_utf8("example.com.").unwrap(),
            60,
            RData::AAAA(AAAA("64:ff9b::1.2.3.4".parse().unwrap())),
        )];

        assert!(needs_synthesis(&p, &req, &mut resp));
        assert!(resp.answers.is_empty(), "the excluded answer is dropped");
    }

    #[test]
    fn nxdomain_is_passed_through_untouched() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::AAAA);
        let mut resp = crate::msg::reply(&req, ResponseCode::NXDomain);
        assert!(!needs_synthesis(&p, &req, &mut resp));
    }

    #[test]
    fn an_a_query_is_never_synthesised() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::A);
        let mut resp = crate::msg::reply(&req, ResponseCode::NoError);
        assert!(!needs_synthesis(&p, &req, &mut resp));
    }

    #[test]
    fn synthesis_rewrites_a_records_into_the_prefix() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::AAAA);
        let mut resp = crate::msg::reply(&req, ResponseCode::NoError);
        resp.authorities = vec![Record::from_rdata(
            Name::from_utf8("example.com.").unwrap(),
            30,
            RData::SOA(SOA::new(
                Name::from_utf8("ns.example.com.").unwrap(),
                Name::from_utf8("hostmaster.example.com.").unwrap(),
                1,
                2,
                3,
                4,
                5,
            )),
        )];

        let mut a_resp = crate::msg::reply(&req, ResponseCode::NoError);
        a_resp.answers = vec![Record::from_rdata(
            Name::from_utf8("example.com.").unwrap(),
            900,
            RData::A(A("192.0.2.33".parse().unwrap())),
        )];

        assert!(synthesize(&p, &req, &mut resp, &a_resp));
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].record_type(), RecordType::AAAA);
        assert_eq!(
            resp.answers[0].ttl, 30,
            "the SOA's TTL bounds the synthesised one"
        );
    }

    #[test]
    fn an_empty_a_answer_leaves_the_response_alone() {
        let p = Prefixes::new(true, []);
        let req = request(RecordType::AAAA);
        let mut resp = crate::msg::reply(&req, ResponseCode::NoError);
        let a_resp = crate::msg::reply(&req, ResponseCode::NoError);

        assert!(!synthesize(&p, &req, &mut resp, &a_resp));
    }

    #[test]
    fn reverse_names_parse_back_into_addresses() {
        assert_eq!(
            addr_from_reverse("4.3.2.1.in-addr.arpa."),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            addr_from_reverse(
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
            ),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(addr_from_reverse("example.com."), None);
        assert_eq!(addr_from_reverse("1.2.in-addr.arpa."), None);
    }

    #[test]
    fn a_nat64_ptr_is_recognised() {
        let p = Prefixes::new(true, []);
        let mut req = Message::query();
        req.add_query(Query::query(
            Name::from_utf8(
                "4.0.3.0.0.2.0.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.9.f.f.4.6.0.0.ip6.arpa.",
            )
            .unwrap(),
            RecordType::PTR,
        ));
        assert!(is_nat64_ptr(&p, &req));
    }
}
