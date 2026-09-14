//! EDNS(0) handling: Client Subnet and the DNSSEC OK bit.
//!
//! Both are per-request edits to the OPT pseudo-record, and both are visible
//! to the client: the subnet is recorded in the query log's `ECS` field, and
//! the DO bit decides whether an upstream returns signatures at all.

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
}
