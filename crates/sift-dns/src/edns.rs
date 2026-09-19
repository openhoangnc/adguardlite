//! EDNS(0) handling: Client Subnet and the DNSSEC OK bit.
//!
//! Both are per-request edits to the OPT pseudo-record, and both are visible
//! to the client: the subnet is recorded in the query log's `ECS` field, and
//! the DO bit decides whether an upstream returns signatures at all.
//!
//! The OPT record on the way back is shaped here too, by [`mirror_request`]:
//! what this server asked an upstream for is not what the client asked for,
//! and the client is owed an answer to its own question.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

/// The prefix length ECS uses for IPv4 clients.
pub const DEFAULT_PREFIX_V4: u8 = 24;

/// The prefix length ECS uses for IPv6 clients.
///
/// Seven octets is upstream's choice: at least Google's public resolver
/// refuses requests carrying longer masks.
pub const DEFAULT_PREFIX_V6: u8 = 56;

/// The EDNS UDP payload size advertised when an OPT record has to be created.
const UDP_PAYLOAD: u16 = 4096;

/// A client subnet as it appears on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Subnet {
    /// The masked address.
    pub addr: IpAddr,
    /// The source prefix length.
    pub prefix: u8,
}

impl Subnet {
    /// Renders the subnet the way the query log's `ECS` field spells it.
    pub fn to_cidr(self) -> String {
        format!("{}/{}", self.addr, self.prefix)
    }
}

/// Masks `addr` to `prefix` bits, zeroing everything below.
pub fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let keep = if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
            };

            IpAddr::V4(Ipv4Addr::from(bits & keep))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let keep = if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
            };

            IpAddr::V6(Ipv6Addr::from(bits & keep))
        }
    }
}

/// The prefix length used for a client address, as upstream chooses it.
pub const fn default_prefix(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => DEFAULT_PREFIX_V4,
        IpAddr::V6(_) => DEFAULT_PREFIX_V6,
    }
}

/// Reads the Client Subnet option a message carries, if any.
pub fn subnet_of(msg: &Message) -> Option<Subnet> {
    let edns = msg.edns.as_ref()?;
    let EdnsOption::Subnet(cs) = edns.option(EdnsCode::Subnet)? else {
        return None;
    };

    Some(Subnet {
        addr: cs.addr(),
        prefix: cs.source_prefix(),
    })
}

/// Adds a Client Subnet option for `addr`, replacing any the request carried.
///
/// Returns the subnet actually written, which is the masked address: sending
/// the client's full address would defeat the point of the prefix.
pub fn set_subnet(msg: &mut Message, addr: IpAddr, prefix: u8) -> Subnet {
    let addr = mask(addr, prefix);
    let cs = ClientSubnet::new(addr, prefix, 0);

    let edns = msg.edns.get_or_insert_with(|| {
        let mut e = Edns::new();
        e.set_max_payload(UDP_PAYLOAD);

        e
    });
    edns.options_mut().remove(EdnsCode::Subnet);
    edns.options_mut().insert(EdnsOption::Subnet(cs));

    Subnet { addr, prefix }
}

/// Removes any Client Subnet option, leaving the rest of the OPT record alone.
pub fn strip_subnet(msg: &mut Message) {
    if let Some(edns) = msg.edns.as_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
}

/// Sets the DNSSEC OK bit on a request, creating an OPT record if needed.
///
/// Without DO an upstream strips signatures, so a validating client below this
/// server would never see them.
pub fn set_dnssec_ok(msg: &mut Message, ok: bool) {
    if !ok && msg.edns.is_none() {
        return;
    }

    let edns = msg.edns.get_or_insert_with(|| {
        let mut e = Edns::new();
        e.set_max_payload(UDP_PAYLOAD);

        e
    });
    edns.set_dnssec_ok(ok);
}

/// Reports whether a message asked for DNSSEC records.
pub fn dnssec_ok(msg: &Message) -> bool {
    msg.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
}

/// Reports whether a message asked to be told about DNSSEC at all.
///
/// `DO` asks for the records themselves and `AD` only for the verdict, and
/// either changes what the answer may say: the cache keys on this, and a
/// response's `AD` bit is only left standing for a client that set one of the
/// two.
pub fn wants_dnssec(msg: &Message) -> bool {
    dnssec_ok(msg) || msg.metadata.authentic_data
}

/// Shapes a response's OPT record to match the request's.
///
/// RFC 6891 makes OPT part of one question-and-answer exchange rather than
/// something a server volunteers, and a running AdGuard Home answers that way:
/// a request that carried no OPT record is answered without one, and a request
/// that carried one is answered with *its* `DO` bit and *its* advertised
/// payload size.  Neither is the upstream's, and the upstream's is what
/// arrives: [`crate::resolver::Resolver::forward`] asks with `DO` set whenever
/// `enable_dnssec` is on, and the answer comes back advertising whatever size
/// that server liked -- 512 from one, 1232 from another.
pub fn mirror_request(req: &Message, resp: &mut Message) {
    let Some(asked) = req.edns.as_ref() else {
        resp.edns = None;

        return;
    };

    // A response built here carries no OPT record of its own, and a client
    // that sent one still expects one back -- upstream answers even a
    // locally-built `NOTIMP` that way.
    let edns = resp.edns.get_or_insert_with(Edns::new);
    edns.set_dnssec_ok(asked.flags().dnssec_ok);
    edns.set_max_payload(asked.max_payload());
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    fn query() -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(
            Name::from_utf8("example.com.").unwrap(),
            RecordType::A,
        ));

        m
    }

    #[test]
    fn masking_zeroes_the_host_part() {
        assert_eq!(
            mask("192.0.2.77".parse().unwrap(), 24),
            "192.0.2.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("192.0.2.77".parse().unwrap(), 32),
            "192.0.2.77".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("192.0.2.77".parse().unwrap(), 0),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            mask("2001:db8::dead:beef".parse().unwrap(), 56),
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn the_default_prefix_follows_the_family() {
        assert_eq!(default_prefix("1.2.3.4".parse().unwrap()), 24);
        assert_eq!(default_prefix("2001:db8::1".parse().unwrap()), 56);
    }

    #[test]
    fn a_subnet_round_trips_through_the_opt_record() {
        let mut m = query();
        assert_eq!(subnet_of(&m), None);

        let written = set_subnet(&mut m, "192.0.2.77".parse().unwrap(), 24);
        assert_eq!(written.addr, "192.0.2.0".parse::<IpAddr>().unwrap());
        assert_eq!(written.to_cidr(), "192.0.2.0/24");

        let got = subnet_of(&m).expect("the option should be readable back");
        assert_eq!(got, written);

        strip_subnet(&mut m);
        assert_eq!(subnet_of(&m), None);
    }

    #[test]
    fn setting_a_subnet_twice_leaves_one_option() {
        let mut m = query();
        set_subnet(&mut m, "192.0.2.1".parse().unwrap(), 24);
        set_subnet(&mut m, "198.51.100.1".parse().unwrap(), 24);

        let got = subnet_of(&m).unwrap();
        assert_eq!(got.addr, "198.51.100.0".parse::<IpAddr>().unwrap());
        assert_eq!(
            m.edns.as_ref().unwrap().options().as_ref().len(),
            1,
            "a second OPT subnet option would be a FORMERR for some servers"
        );
    }

    #[test]
    fn the_dnssec_bit_is_settable_and_readable() {
        let mut m = query();
        assert!(!dnssec_ok(&m));

        set_dnssec_ok(&mut m, true);
        assert!(dnssec_ok(&m));

        set_dnssec_ok(&mut m, false);
        assert!(!dnssec_ok(&m));
    }

    #[test]
    fn clearing_the_bit_does_not_invent_an_opt_record() {
        // A request with no OPT must stay that way: adding one changes what
        // the upstream sees for no reason.
        let mut m = query();
        set_dnssec_ok(&mut m, false);
        assert!(m.edns.is_none());
    }

    #[test]
    fn wanting_dnssec_covers_both_bits() {
        let mut m = query();
        assert!(!wants_dnssec(&m));

        m.metadata.authentic_data = true;
        assert!(wants_dnssec(&m), "`AD` alone asks for the verdict");

        let mut m = query();
        set_dnssec_ok(&mut m, true);
        assert!(wants_dnssec(&m), "and `DO` alone asks for the records");
    }

    /// A response as an upstream hands one back: its own OPT record, with `DO`
    /// set because that is what it was asked, and its own payload size.
    fn answer() -> Message {
        let mut m = Message::query();
        m.metadata.message_type = hickory_proto::op::MessageType::Response;

        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_dnssec_ok(true);
        m.edns = Some(e);

        m
    }

    #[test]
    fn a_request_without_an_opt_record_is_answered_without_one() {
        let mut resp = answer();
        mirror_request(&query(), &mut resp);

        assert!(
            resp.edns.is_none(),
            "an OPT record the client never sent is one macOS discards the answer over"
        );
    }

    #[test]
    fn the_answers_opt_record_carries_the_requests_own_terms() {
        let mut req = query();
        let mut e = Edns::new();
        e.set_max_payload(1400);
        req.edns = Some(e);

        let mut resp = answer();
        mirror_request(&req, &mut resp);

        let got = resp
            .edns
            .expect("the client sent an OPT record, so it gets one back");
        assert!(!got.flags().dnssec_ok, "the client did not ask for DNSSEC");
        assert_eq!(
            got.max_payload(),
            1400,
            "and advertised its own size, not 1232"
        );
    }

    #[test]
    fn a_locally_built_answer_gains_the_opt_record_the_client_expects() {
        // Nothing this server synthesises -- a block, a rewrite, `NOTIMP` --
        // carries an OPT record, and a running AdGuard Home answers all three
        // with one when the request had one.
        let mut req = query();
        req.edns = Some(Edns::new());

        let mut resp = Message::query();
        mirror_request(&req, &mut resp);

        assert!(resp.edns.is_some());
    }

    #[test]
    fn a_validating_client_keeps_its_dnssec_bit() {
        let mut req = query();
        set_dnssec_ok(&mut req, true);

        let mut resp = answer();
        mirror_request(&req, &mut resp);

        assert!(resp.edns.expect("an OPT record").flags().dnssec_ok);
    }
}
