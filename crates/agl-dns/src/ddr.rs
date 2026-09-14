//! Discovery of Designated Resolvers.
//!
//! A client asks `_dns.resolver.arpa` for `SVCB` records and learns which
//! encrypted transports this server offers.  Answering it is what lets a
//! stock client upgrade from plain DNS to DoH, DoT or DoQ on its own.
//!
//! See [draft-ietf-add-ddr-10](https://www.ietf.org/archive/id/draft-ietf-add-ddr-10.html).

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::SVCB;
use hickory_proto::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue, Unknown};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

/// The name a DDR query asks for.
pub const HOST: &str = "_dns.resolver.arpa";

/// The SVCB parameter key for the DoH URI template.
///
/// RFC 9461 assigns key 7; hickory has no named variant for it, so the value is
/// written as an opaque parameter with the right code.
const DOHPATH_KEY: u16 = 7;

/// The DoH URI template upstream advertises.
const DOHPATH: &str = "/dns-query{?dns}";

/// The TTL of a DDR answer.
const TTL: u32 = 3600;

/// The encrypted endpoints this server offers.
#[derive(Clone, Debug, Default)]
pub struct Endpoints {
    /// The name the certificate is issued for.
    pub server_name: String,
    /// The DNS-over-HTTPS port, if served.
    pub https: Option<u16>,
    /// The DNS-over-TLS port, if served *and* the certificate names an IP.
    ///
    /// Upstream only advertises DoT when the certificate carries IP addresses,
    /// because a client that discovered this resolver by address has no name
    /// to validate against.
    pub tls: Option<u16>,
    /// The DNS-over-QUIC port, if served.
    pub quic: Option<u16>,
}

impl Endpoints {
    /// Reports whether there is anything worth advertising.
    pub fn is_empty(&self) -> bool {
        self.server_name.is_empty()
            || (self.https.is_none() && self.tls.is_none() && self.quic.is_none())
    }
}

/// Reports whether a request is a DDR query.
pub fn is_query(req: &Message) -> bool {
    req.queries.first().is_some_and(|q| {
        q.name()
            .to_ascii()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(HOST)
    })
}

/// Builds the answer to a DDR query.
///
/// A query for anything but `SVCB` gets an empty `NOERROR`, which is what
/// upstream returns: the name exists, but has no record of that type.
pub fn respond(req: &Message, ep: &Endpoints) -> Message {
    let mut resp = crate::msg::reply(req, ResponseCode::NoError);

    let Some(q) = req.queries.first() else {
        return resp;
    };
    if q.query_type() != RecordType::SVCB || ep.is_empty() {
        return resp;
    }

    let Ok(target) = Name::from_utf8(format!("{}.", ep.server_name.trim_end_matches('.'))) else {
        return resp;
    };

    let name = q.name().clone();
    let mut push = |alpn: &str, port: u16, dohpath: bool| {
        let mut params = vec![
            (
                SvcParamKey::Alpn,
                SvcParamValue::Alpn(Alpn(vec![alpn.to_string()])),
            ),
            (SvcParamKey::Port, SvcParamValue::Port(port)),
        ];
        if dohpath {
            params.push((
                SvcParamKey::Unknown(DOHPATH_KEY),
                SvcParamValue::Unknown(Unknown(DOHPATH.as_bytes().to_vec())),
            ));
        }

        let mut rec = Record::from_rdata(
            name.clone(),
            TTL,
            RData::SVCB(SVCB::new(1, target.clone(), params)),
        );
        rec.dns_class = DNSClass::IN;
        resp.answers.push(rec);
    };

    // The order matches upstream's: HTTPS, then TLS, then QUIC.
    if let Some(p) = ep.https {
        push("h2", p, true);
    }
    if let Some(p) = ep.tls {
        push("dot", p, false);
    }
    if let Some(p) = ep.quic {
        push("doq", p, false);
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;

    fn request(name: &str, qt: RecordType) -> Message {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_utf8(name).unwrap(), qt));

        m
    }

    fn endpoints() -> Endpoints {
        Endpoints {
            server_name: "dns.example".into(),
            https: Some(443),
            tls: Some(853),
            quic: Some(853),
        }
    }

    #[test]
    fn only_the_ddr_name_is_a_ddr_query() {
        assert!(is_query(&request("_dns.resolver.arpa.", RecordType::SVCB)));
        assert!(is_query(&request("_DNS.Resolver.ARPA.", RecordType::SVCB)));
        assert!(!is_query(&request("example.com.", RecordType::SVCB)));
    }

    #[test]
    fn an_svcb_query_lists_every_configured_transport() {
        let resp = respond(
            &request("_dns.resolver.arpa.", RecordType::SVCB),
            &endpoints(),
        );

        assert_eq!(resp.answers.len(), 3);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);

        let alpns: Vec<String> = resp
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::SVCB(s) => s.svc_params.iter().find_map(|(k, v)| match (k, v) {
                    (SvcParamKey::Alpn, SvcParamValue::Alpn(a)) => a.0.first().cloned(),
                    _ => None,
                }),
                _ => None,
            })
            .collect();
        assert_eq!(alpns, vec!["h2", "dot", "doq"]);
    }

    #[test]
    fn the_https_entry_carries_the_uri_template() {
        let resp = respond(
            &request("_dns.resolver.arpa.", RecordType::SVCB),
            &endpoints(),
        );

        let RData::SVCB(s) = &resp.answers[0].data else {
            panic!("expected an SVCB record");
        };
        let path = s.svc_params.iter().find_map(|(k, v)| match (k, v) {
            (SvcParamKey::Unknown(7), SvcParamValue::Unknown(u)) => Some(u.0.clone()),
            _ => None,
        });
        assert_eq!(path.as_deref(), Some(DOHPATH.as_bytes()));
    }

    #[test]
    fn a_non_svcb_query_gets_an_empty_noerror() {
        let resp = respond(&request("_dns.resolver.arpa.", RecordType::A), &endpoints());
        assert!(resp.answers.is_empty());
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    }

    #[test]
    fn nothing_is_advertised_without_a_server_name() {
        let ep = Endpoints {
            server_name: String::new(),
            https: Some(443),
            ..Default::default()
        };
        let resp = respond(&request("_dns.resolver.arpa.", RecordType::SVCB), &ep);
        assert!(resp.answers.is_empty());
    }

    #[test]
    fn a_certificate_without_ip_names_suppresses_dot() {
        // Upstream leaves DoT out unless the certificate names IP addresses,
        // because a client that found this resolver by address cannot
        // validate a hostname.
        let ep = Endpoints {
            tls: None,
            ..endpoints()
        };
        let resp = respond(&request("_dns.resolver.arpa.", RecordType::SVCB), &ep);
        assert_eq!(resp.answers.len(), 2);
    }
}
