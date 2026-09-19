//! Construction of DNS responses, matching `internal/dnsforward/msg.go`.
//!
//! And their shaping on the way out, by [`shape_to_request`]: a response is
//! the answer to one client's question, not a copy of what an upstream said.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::edns;

/// The TTL used for blocked responses when none is configured.
pub const DEFAULT_BLOCKED_TTL: u32 = 3600;

/// The authority name upstream puts in negative-caching SOA records.
const NEG_CACHE_NS: &str = "fake-for-negative-caching.adguard.com.";

/// How a blocked query is answered.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BlockingMode {
    /// The rule's own address if it has one, otherwise a null address.
    #[default]
    Default,
    /// The configured custom addresses.
    CustomIp,
    /// `NXDOMAIN`.
    Nxdomain,
    /// A null address, even when the rule carries one.
    NullIp,
    /// `REFUSED`.
    Refused,
}

/// The settings needed to synthesise a blocked response.
#[derive(Clone, Copy, Debug)]
pub struct BlockingConfig {
    /// How to answer.
    pub mode: BlockingMode,
    /// The address used for `A` in custom-IP mode.
    pub custom_v4: Option<Ipv4Addr>,
    /// The address used for `AAAA` in custom-IP mode.
    pub custom_v6: Option<Ipv6Addr>,
    /// The TTL of blocked responses.
    pub ttl: u32,
}

impl Default for BlockingConfig {
    fn default() -> Self {
        Self {
            mode: BlockingMode::Default,
            custom_v4: None,
            custom_v6: None,
            ttl: 10,
        }
    }
}

/// Starts a response to `req`, copying the header fields upstream copies.
pub fn reply(req: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::query();
    resp.metadata.id = req.metadata.id;
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.op_code = req.metadata.op_code;
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.checking_disabled = req.metadata.checking_disabled;
    resp.metadata.response_code = rcode;
    resp.queries = req.queries.clone();

    resp
}

/// The question's name, or the root when there is no question.
fn qname(req: &Message) -> Name {
    req.queries
        .first()
        .map(|q| q.name().clone())
        .unwrap_or_else(Name::root)
}

/// The question's type, or `A` when there is no question.
fn qtype(req: &Message) -> RecordType {
    req.queries
        .first()
        .map(|q| q.query_type())
        .unwrap_or(RecordType::A)
}

/// Builds the negative-caching SOA record upstream attaches to NODATA and
/// NXDOMAIN responses.
pub fn soa_record(req: &Message, ttl: u32) -> Record {
    let zone = qname(req);
    let ttl = if ttl == 0 { DEFAULT_BLOCKED_TTL } else { ttl };

    // Upstream builds the mailbox as `hostmaster.` plus the zone, unless the
    // zone is the root.
    let mbox = if zone.is_root() {
        "hostmaster.".to_string()
    } else {
        format!("hostmaster.{zone}")
    };

    let soa = SOA::new(
        Name::from_ascii(NEG_CACHE_NS).unwrap_or_else(|_| Name::root()),
        Name::from_ascii(&mbox).unwrap_or_else(|_| Name::root()),
        100_500,
        1800,
        900,
        604_800,
        86_400,
    );

    Record::from_rdata(zone, ttl, RData::SOA(soa))
}

/// A `NOERROR` response with no answers and a negative-caching SOA.
pub fn nodata(req: &Message, ttl: u32) -> Message {
    let mut resp = reply(req, ResponseCode::NoError);
    resp.authorities = vec![soa_record(req, ttl)];

    resp
}

/// An `NXDOMAIN` response with a negative-caching SOA.
pub fn nxdomain(req: &Message, ttl: u32) -> Message {
    let mut resp = reply(req, ResponseCode::NXDomain);
    resp.authorities = vec![soa_record(req, ttl)];

    resp
}

/// A `REFUSED` response.
pub fn refused(req: &Message) -> Message {
    reply(req, ResponseCode::Refused)
}

/// A `SERVFAIL` response.
pub fn servfail(req: &Message) -> Message {
    reply(req, ResponseCode::ServFail)
}

/// The record types DNSSEC adds to a response.
///
/// RFC 4035 3.2.1 and RFC 5155 name exactly these, and they are what a client
/// that did not set the `DO` bit must not be sent.  Deliberately not hickory's
/// `RecordType::is_dnssec`, which also counts `TSIG` and `SIG` -- transaction
/// security rather than DNSSEC data -- and the `CDS`/`CDNSKEY` a zone
/// publishes for its parent to read like any other record.
const fn is_dnssec_record(t: RecordType) -> bool {
    matches!(
        t,
        RecordType::RRSIG
            | RecordType::DNSKEY
            | RecordType::DS
            | RecordType::NSEC
            | RecordType::NSEC3
    )
}

/// Removes a response's DNSSEC records, except the ones `qtype` asked for.
///
/// A `DNSKEY` question is answered with its keys whatever the `DO` bit says --
/// they are the answer -- while the `RRSIG` that came with them is not.  A
/// running AdGuard Home was measured doing that for `DNSKEY`, `DS` and `NSEC`
/// questions, and stripping the `NSEC` and `RRSIG` records out of the
/// authority section of a negative answer while leaving the `SOA`.
pub fn strip_dnssec(resp: &mut Message, qtype: RecordType) {
    let keep = |r: &Record| r.record_type() == qtype || !is_dnssec_record(r.record_type());

    resp.answers.retain(keep);
    resp.authorities.retain(keep);
    resp.additionals.retain(keep);
}

/// Shapes a response to what the request asked for, just before it is sent.
///
/// Upstream splits this between `processDNSSECAfterResponse` in
/// `internal/dnsforward` and dnsproxy's `scrub`; here it is one step, run at
/// the single point every answer leaves the resolver through, so a path added
/// later cannot forget it.  What it corrects is that the question this server
/// asked an upstream is not the question the client asked this server.
pub fn shape_to_request(req: &Message, resp: &mut Message) {
    // `forward` sets the `DO` bit on every upstream query while
    // `enable_dnssec` is on, so signatures arrive whether or not anyone below
    // asked for them, and passing them on is what RFC 4035 3.2.1 forbids.
    // macOS enforces it: `mDNSResponder` discards a response carrying records
    // it did not ask for, so `getaddrinfo` fails for every signed name --
    // every Cloudflare-hosted one, since Cloudflare signs by default -- while
    // an unsigned name resolves and `dig`, which prints whatever arrives
    // rather than judging its shape, shows nothing wrong.
    if !edns::dnssec_ok(req) {
        strip_dnssec(resp, qtype(req));
    }

    // `AD` claims the answer was validated, which RFC 6840 5.7 leaves
    // meaningless to a client that set neither `DO` nor `AD`.  Upstream
    // clears it for exactly those clients, and keeps the upstream's own
    // verdict for the rest.
    if !edns::wants_dnssec(req) {
        resp.metadata.authentic_data = false;
    }

    edns::mirror_request(req, resp);
}

/// A `NOERROR` response carrying the given addresses, filtered to the question's
/// address family.
pub fn with_addrs(req: &Message, addrs: &[IpAddr], ttl: u32) -> Message {
    let mut resp = reply(req, ResponseCode::NoError);
    let name = qname(req);

    resp.answers = match qtype(req) {
        RecordType::A => addrs
            .iter()
            .filter_map(|a| match a {
                IpAddr::V4(v4) => Some(Record::from_rdata(name.clone(), ttl, RData::A(A(*v4)))),
                IpAddr::V6(_) => None,
            })
            .collect(),
        RecordType::AAAA => addrs
            .iter()
            .filter_map(|a| match a {
                IpAddr::V6(v6) => Some(Record::from_rdata(
                    name.clone(),
                    ttl,
                    RData::AAAA(AAAA(*v6)),
                )),
                IpAddr::V4(_) => None,
            })
            .collect(),
        _ => Vec::new(),
    };

    resp
}

/// A response with a `CNAME` answer, optionally followed by addresses that the
/// canonical name resolves to.
pub fn with_cname(req: &Message, cname: &str, addrs: &[IpAddr], ttl: u32) -> Message {
    let mut resp = reply(req, ResponseCode::NoError);
    let name = qname(req);

    let Ok(target) = Name::from_utf8(cname) else {
        return resp;
    };
    let target = target.to_lowercase();

    let mut answers = vec![Record::from_rdata(
        name,
        ttl,
        RData::CNAME(CNAME(target.clone())),
    )];

    let qt = qtype(req);
    for a in addrs {
        match (qt, a) {
            (RecordType::A, IpAddr::V4(v4)) => {
                answers.push(Record::from_rdata(target.clone(), ttl, RData::A(A(*v4))));
            }
            (RecordType::AAAA, IpAddr::V6(v6)) => {
                answers.push(Record::from_rdata(
                    target.clone(),
                    ttl,
                    RData::AAAA(AAAA(*v6)),
                ));
            }
            _ => {}
        }
    }

    resp.answers = answers;

    resp
}

/// Builds the response for a blocked query.
///
/// `rule_addrs` are the addresses carried by the matching rules, which
/// hosts-style rules supply.
pub fn blocked(req: &Message, cfg: &BlockingConfig, rule_addrs: &[IpAddr]) -> Message {
    let qt = qtype(req);

    // Only address-shaped questions get a synthesised answer; everything else
    // gets NODATA, or a bare NOERROR in null-IP mode.
    if !matches!(qt, RecordType::A | RecordType::AAAA | RecordType::HTTPS) {
        if cfg.mode == BlockingMode::NullIp {
            return reply(req, ResponseCode::NoError);
        }

        return nodata(req, cfg.ttl);
    }

    match cfg.mode {
        BlockingMode::Refused => refused(req),
        BlockingMode::Nxdomain => nxdomain(req, cfg.ttl),
        BlockingMode::CustomIp => {
            let addrs: Vec<IpAddr> = match qt {
                RecordType::A => cfg.custom_v4.map(IpAddr::V4).into_iter().collect(),
                RecordType::AAAA => cfg.custom_v6.map(IpAddr::V6).into_iter().collect(),
                _ => Vec::new(),
            };

            with_addrs(req, &addrs, cfg.ttl)
        }
        BlockingMode::NullIp => with_addrs(req, &null_addr(qt), cfg.ttl),
        BlockingMode::Default => {
            // A hosts-style rule's own address wins; otherwise a null address.
            let usable: Vec<IpAddr> = rule_addrs
                .iter()
                .copied()
                .filter(|a| {
                    matches!(
                        (qt, a),
                        (RecordType::A, IpAddr::V4(_)) | (RecordType::AAAA, IpAddr::V6(_))
                    )
                })
                .collect();

            if usable.is_empty() {
                with_addrs(req, &null_addr(qt), cfg.ttl)
            } else {
                with_addrs(req, &usable, cfg.ttl)
            }
        }
    }
}

/// The unspecified address matching the question type.
fn null_addr(qt: RecordType) -> Vec<IpAddr> {
    match qt {
        RecordType::A => vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        RecordType::AAAA => vec![IpAddr::V6(Ipv6Addr::UNSPECIFIED)],
        _ => Vec::new(),
    }
}

/// Rewrites every answer's TTL, clamping to the configured bounds.
///
/// `min` of 0 and `max` of 0 mean "no bound", matching `cache_ttl_min` and
/// `cache_ttl_max`.
pub fn clamp_ttls(msg: &mut Message, min: u32, max: u32) {
    let clamp = |t: u32| {
        let mut t = t;
        if min > 0 && t < min {
            t = min;
        }
        if max > 0 && t > max {
            t = max;
        }

        t
    };

    for r in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        r.ttl = clamp(r.ttl);
    }
}

/// The smallest TTL across a message's records, or `None` when it has none.
pub fn min_ttl(msg: &Message) -> Option<u32> {
    msg.answers
        .iter()
        .chain(&msg.authorities)
        .map(|r| r.ttl)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn query(name: &str, qt: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.id = 0x1234;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), qt));

        m
    }

    fn first_addr(m: &Message) -> Option<IpAddr> {
        m.answers.first().and_then(|r| match r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
    }

    #[test]
    fn reply_copies_the_request_identity() {
        let q = query("example.com.", RecordType::A);
        let r = reply(&q, ResponseCode::NoError);
        assert_eq!(r.metadata.id, 0x1234);
        assert_eq!(r.metadata.message_type, MessageType::Response);
        assert!(r.metadata.recursion_available);
        assert!(r.metadata.recursion_desired);
        assert_eq!(r.queries.len(), 1);
    }

    #[test]
    fn default_mode_uses_a_null_address_without_a_rule_address() {
        let cfg = BlockingConfig::default();
        let r = blocked(&query("ads.example.com.", RecordType::A), &cfg, &[]);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(first_addr(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

        let r = blocked(&query("ads.example.com.", RecordType::AAAA), &cfg, &[]);
        assert_eq!(first_addr(&r), Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn default_mode_prefers_the_rules_own_address() {
        let cfg = BlockingConfig::default();
        let addr: IpAddr = "192.168.1.5".parse().unwrap();
        let r = blocked(&query("nas.lan.", RecordType::A), &cfg, &[addr]);
        assert_eq!(first_addr(&r), Some(addr));
    }

    #[test]
    fn default_mode_ignores_a_rule_address_of_the_wrong_family() {
        let cfg = BlockingConfig::default();
        let v6: IpAddr = "::1".parse().unwrap();
        let r = blocked(&query("nas.lan.", RecordType::A), &cfg, &[v6]);
        assert_eq!(first_addr(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn null_ip_mode_ignores_the_rules_address() {
        let cfg = BlockingConfig {
            mode: BlockingMode::NullIp,
            ..Default::default()
        };
        let addr: IpAddr = "192.168.1.5".parse().unwrap();
        let r = blocked(&query("nas.lan.", RecordType::A), &cfg, &[addr]);
        assert_eq!(first_addr(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn custom_ip_mode_uses_the_configured_addresses() {
        let cfg = BlockingConfig {
            mode: BlockingMode::CustomIp,
            custom_v4: Some(Ipv4Addr::new(10, 0, 0, 1)),
            custom_v6: Some(Ipv6Addr::LOCALHOST),
            ..Default::default()
        };
        let r = blocked(&query("ads.example.com.", RecordType::A), &cfg, &[]);
        assert_eq!(first_addr(&r), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        let r = blocked(&query("ads.example.com.", RecordType::AAAA), &cfg, &[]);
        assert_eq!(first_addr(&r), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn nxdomain_and_refused_modes() {
        let cfg = BlockingConfig {
            mode: BlockingMode::Nxdomain,
            ..Default::default()
        };
        let r = blocked(&query("ads.example.com.", RecordType::A), &cfg, &[]);
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(
            r.authorities.len(),
            1,
            "NXDOMAIN carries a negative-caching SOA"
        );

        let cfg = BlockingConfig {
            mode: BlockingMode::Refused,
            ..Default::default()
        };
        let r = blocked(&query("ads.example.com.", RecordType::A), &cfg, &[]);
        assert_eq!(r.metadata.response_code, ResponseCode::Refused);
    }

    #[test]
    fn non_address_questions_get_nodata() {
        let cfg = BlockingConfig::default();
        let r = blocked(&query("ads.example.com.", RecordType::TXT), &cfg, &[]);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
        assert_eq!(r.authorities.len(), 1);

        // In null-IP mode upstream returns a bare NOERROR with no SOA.
        let cfg = BlockingConfig {
            mode: BlockingMode::NullIp,
            ..Default::default()
        };
        let r = blocked(&query("ads.example.com.", RecordType::TXT), &cfg, &[]);
        assert!(r.authorities.is_empty());
    }

    #[test]
    fn soa_matches_upstreams_shape() {
        let q = query("ads.example.com.", RecordType::A);
        let rec = soa_record(&q, 10);
        assert_eq!(rec.ttl, 10);
        let RData::SOA(soa) = rec.data else {
            panic!("expected SOA")
        };
        assert_eq!(soa.mname.to_ascii(), NEG_CACHE_NS);
        assert_eq!(soa.rname.to_ascii(), "hostmaster.ads.example.com.");
        assert_eq!(soa.serial, 100_500);
        assert_eq!(soa.refresh, 1800);
        assert_eq!(soa.retry, 900);
        assert_eq!(soa.expire, 604_800);
        assert_eq!(soa.minimum, 86_400);
    }

    #[test]
    fn a_zero_ttl_falls_back_to_the_default() {
        let q = query("ads.example.com.", RecordType::A);
        assert_eq!(soa_record(&q, 0).ttl, DEFAULT_BLOCKED_TTL);
    }

    #[test]
    fn cname_responses_carry_the_target_and_its_addresses() {
        let q = query("www.example.com.", RecordType::A);
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        let r = with_cname(&q, "target.example.net", &[addr], 300);
        assert_eq!(r.answers.len(), 2);
        assert!(matches!(r.answers[0].data, RData::CNAME(_)));
        assert!(matches!(r.answers[1].data, RData::A(_)));
    }

    #[test]
    fn ttl_clamping_respects_zero_as_unbounded() {
        let mut m = with_addrs(
            &query("a.com.", RecordType::A),
            &["1.2.3.4".parse().unwrap()],
            5,
        );
        clamp_ttls(&mut m, 60, 0);
        assert_eq!(m.answers[0].ttl, 60);

        let mut m = with_addrs(
            &query("a.com.", RecordType::A),
            &["1.2.3.4".parse().unwrap()],
            9999,
        );
        clamp_ttls(&mut m, 0, 300);
        assert_eq!(m.answers[0].ttl, 300);

        let mut m = with_addrs(
            &query("a.com.", RecordType::A),
            &["1.2.3.4".parse().unwrap()],
            100,
        );
        clamp_ttls(&mut m, 0, 0);
        assert_eq!(m.answers[0].ttl, 100);
    }

    /// A record of `rtype` with opaque rdata, which is how a DNSSEC record
    /// arrives here: hickory is built without its `dnssec` feature, so an
    /// `RRSIG` parses as `Unknown` and keeps `RecordType::RRSIG`.
    fn dnssec_record(name: &str, rtype: RecordType) -> Record {
        Record::from_rdata(
            Name::from_utf8(name).unwrap(),
            300,
            RData::Unknown {
                code: rtype,
                rdata: hickory_proto::rr::rdata::NULL::with(vec![0x01, 0x02, 0x03]),
            },
        )
    }

    /// The answer an upstream gives a query it was asked with `DO` set: the
    /// records, their signature, a denial in the authority section, and `AD`.
    fn signed_answer(req: &Message) -> Message {
        let mut m = with_addrs(req, &["1.2.3.4".parse().unwrap()], 300);
        m.metadata.authentic_data = true;
        m.answers
            .push(dnssec_record("example.com.", RecordType::RRSIG));
        m.authorities = vec![
            soa_record(req, 300),
            dnssec_record("example.com.", RecordType::NSEC),
            dnssec_record("example.com.", RecordType::RRSIG),
        ];

        m
    }

    fn types(rs: &[Record]) -> Vec<RecordType> {
        rs.iter().map(Record::record_type).collect()
    }

    #[test]
    fn a_plain_query_is_answered_without_signatures() {
        let q = query("example.com.", RecordType::A);
        let mut resp = signed_answer(&q);
        shape_to_request(&q, &mut resp);

        assert_eq!(types(&resp.answers), vec![RecordType::A]);
        assert_eq!(
            types(&resp.authorities),
            vec![RecordType::SOA],
            "the denial of existence goes with the signatures; the SOA stays"
        );
        assert!(!resp.metadata.authentic_data);
        assert!(resp.edns.is_none());
    }

    #[test]
    fn a_validating_client_is_answered_with_everything() {
        let mut q = query("example.com.", RecordType::A);
        edns::set_dnssec_ok(&mut q, true);

        let mut resp = signed_answer(&q);
        shape_to_request(&q, &mut resp);

        assert_eq!(
            types(&resp.answers),
            vec![RecordType::A, RecordType::RRSIG],
            "asking for DNSSEC is how signatures are asked for"
        );
        assert_eq!(resp.authorities.len(), 3);
        assert!(resp.metadata.authentic_data);
    }

    #[test]
    fn the_question_type_survives_even_unasked_for() {
        // The keys are the answer to a `DNSKEY` question; the signature over
        // them is not.  Measured against a running AdGuard Home.
        let q = query("example.com.", RecordType::DNSKEY);
        let mut resp = reply(&q, ResponseCode::NoError);
        resp.answers = vec![
            dnssec_record("example.com.", RecordType::DNSKEY),
            dnssec_record("example.com.", RecordType::DNSKEY),
            dnssec_record("example.com.", RecordType::RRSIG),
        ];

        shape_to_request(&q, &mut resp);
        assert_eq!(
            types(&resp.answers),
            vec![RecordType::DNSKEY, RecordType::DNSKEY]
        );
    }

    #[test]
    fn a_client_that_asked_only_for_the_verdict_keeps_it() {
        // `AD` without `DO`: tell me whether it validated, not with what.
        let mut q = query("example.com.", RecordType::A);
        q.metadata.authentic_data = true;

        let mut resp = signed_answer(&q);
        shape_to_request(&q, &mut resp);

        assert_eq!(types(&resp.answers), vec![RecordType::A]);
        assert!(resp.metadata.authentic_data);
    }

    #[test]
    fn an_unsigned_answer_is_left_alone() {
        let q = query("example.com.", RecordType::A);
        let mut resp = with_addrs(&q, &["1.2.3.4".parse().unwrap()], 300);
        let before = resp.clone();

        shape_to_request(&q, &mut resp);
        assert_eq!(types(&resp.answers), types(&before.answers));
        assert_eq!(first_addr(&resp), first_addr(&before));
    }
}
