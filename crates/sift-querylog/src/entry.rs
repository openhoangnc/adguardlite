//! The query log entry, wire-compatible with `internal/querylog`.
//!
//! The JSON field names and their order are part of the file format: an
//! existing `querylog.json` must stay readable by the Go implementation and
//! vice versa.  Fields marked `omitempty` upstream are skipped here too, so a
//! round trip does not change a file's size or shape.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use sift_core::Reason;

/// The transport a query arrived on, as written to the `CP` field.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum ClientProto {
    /// Plain DNS, written as an empty string.
    #[default]
    #[serde(rename = "")]
    Plain,
    /// DNS-over-HTTPS.
    #[serde(rename = "doh")]
    Doh,
    /// DNS-over-QUIC.
    #[serde(rename = "doq")]
    Doq,
    /// DNS-over-TLS.
    #[serde(rename = "dot")]
    Dot,
    /// DNSCrypt.
    #[serde(rename = "dnscrypt")]
    DnsCrypt,
}

impl ClientProto {
    /// The string written to the log.
    pub const fn as_str(self) -> &'static str {
        match self {
            ClientProto::Plain => "",
            ClientProto::Doh => "doh",
            ClientProto::Doq => "doq",
            ClientProto::Dot => "dot",
            ClientProto::DnsCrypt => "dnscrypt",
        }
    }
}

/// One applied filtering rule.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ResultRule {
    /// The rule's text.
    #[serde(rename = "Text", default, skip_serializing_if = "String::is_empty")]
    pub text: String,

    /// The address a hosts-style rule resolves to.
    #[serde(rename = "IP", default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,

    /// The list the rule came from.
    #[serde(rename = "FilterListID", default, skip_serializing_if = "is_zero_i64")]
    pub filter_list_id: i64,
}

/// Reports whether a list identifier is the zero value, which upstream omits.
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

/// Reports whether a reason is the zero value, which upstream omits.
fn is_zero_reason(r: &Reason) -> bool {
    *r == Reason::NotFilteredNotFound
}

/// Reports whether a boolean is false, which upstream omits.
fn is_false(b: &bool) -> bool {
    !*b
}

/// The `$dnsrewrite` outcome recorded alongside a result.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsRewriteResult {
    /// The response code to answer with.
    #[serde(rename = "RCode", default, skip_serializing_if = "is_zero_u16")]
    pub rcode: u16,

    /// The synthesised records, keyed by record type.
    #[serde(rename = "Response", default, skip_serializing_if = "Option::is_none")]
    pub response: Option<serde_json::Value>,
}

/// Reports whether a response code is zero.
fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

/// The filtering outcome recorded for a query.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Result {
    /// The `$dnsrewrite` outcome, if any.
    #[serde(
        rename = "DNSRewriteResult",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dns_rewrite_result: Option<DnsRewriteResult>,

    /// The canonical name a rewrite produced.
    #[serde(
        rename = "CanonName",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub canon_name: String,

    /// The blocked service's name.
    #[serde(
        rename = "ServiceName",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub service_name: String,

    /// Addresses produced by a rewrite.
    #[serde(rename = "IPList", default, skip_serializing_if = "Vec::is_empty")]
    pub ip_list: Vec<IpAddr>,

    /// The rules that matched.
    #[serde(rename = "Rules", default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ResultRule>,

    /// Why the query was filtered, allowed or rewritten.
    #[serde(rename = "Reason", default, skip_serializing_if = "is_zero_reason")]
    pub reason: Reason,

    /// Whether the query was blocked.
    #[serde(rename = "IsFiltered", default, skip_serializing_if = "is_false")]
    pub is_filtered: bool,
}

/// One line of the query log.
///
/// Field order matches upstream's struct, because that is the order Go's JSON
/// encoder emits and a byte-identical file is the goal.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// When the query was handled, in RFC 3339 with the local offset.
    #[serde(rename = "T")]
    pub time: String,

    /// The queried host, without a trailing dot.
    #[serde(rename = "QH")]
    pub question_host: String,

    /// The query type, e.g. `A`.
    #[serde(rename = "QT")]
    pub question_type: String,

    /// The query class, normally `IN`.
    #[serde(rename = "QC")]
    pub question_class: String,

    /// The EDNS Client Subnet the request carried.
    #[serde(rename = "ECS", default, skip_serializing_if = "String::is_empty")]
    pub req_ecs: String,

    /// The ClientID the request was tagged with.
    #[serde(rename = "CID", default, skip_serializing_if = "String::is_empty")]
    pub client_id: String,

    /// The transport the query arrived on.
    #[serde(rename = "CP")]
    pub client_proto: ClientProto,

    /// The upstream that answered.
    #[serde(rename = "Upstream", default, skip_serializing_if = "String::is_empty")]
    pub upstream: String,

    /// The answer, as a base64-encoded DNS message.
    #[serde(rename = "Answer", default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,

    /// The upstream's original answer, when filtering replaced it.
    #[serde(
        rename = "OrigAnswer",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub orig_answer: Option<String>,

    /// The client's address.
    #[serde(rename = "IP")]
    pub ip: String,

    /// The filtering outcome.
    #[serde(rename = "Result")]
    pub result: Result,

    /// How long handling took, in nanoseconds.
    #[serde(rename = "Elapsed")]
    pub elapsed: u64,

    /// Whether the answer came from the cache.
    #[serde(rename = "Cached", default, skip_serializing_if = "is_false")]
    pub cached: bool,

    /// Whether the answer was DNSSEC-authenticated.
    #[serde(rename = "AD", default, skip_serializing_if = "is_false")]
    pub authenticated_data: bool,
}

impl Entry {
    /// Encodes the entry as one line of the log, including the newline.
    pub fn to_line(&self) -> std::result::Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');

        Ok(s)
    }

    /// Decodes one line of the log.
    pub fn from_line(line: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(line)
    }

    /// Encodes a packed DNS message the way the `Answer` field stores it.
    pub fn encode_answer(wire: &[u8]) -> String {
        use base64::Engine as _;

        base64::engine::general_purpose::STANDARD.encode(wire)
    }

    /// Decodes an `Answer` field back to a packed DNS message.
    pub fn decode_answer(s: &str) -> Option<Vec<u8>> {
        use base64::Engine as _;

        base64::engine::general_purpose::STANDARD.decode(s).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line captured verbatim from a running AdGuard Home v0.107.79.
    const REAL_LINE: &str = r#"{"T":"2026-09-14T17:41:53.850502+07:00","QH":"doubleclick.net","QT":"A","QC":"IN","CP":"","Answer":"EyOBgAABAAEAAAABC2RvdWJsZWNsaWNrA25ldAAAAQABwAwAAQABAAAACgAEAAAAAAAAKRAAAAAAAAAA","IP":"127.0.0.1","Result":{"Rules":[{"Text":"||doubleclick.net^","FilterListID":1}],"Reason":3,"IsFiltered":true},"Elapsed":267375}"#;

    #[test]
    fn parses_a_real_log_line() {
        let e = Entry::from_line(REAL_LINE).expect("must parse");
        assert_eq!(e.question_host, "doubleclick.net");
        assert_eq!(e.question_type, "A");
        assert_eq!(e.question_class, "IN");
        assert_eq!(e.client_proto, ClientProto::Plain);
        assert_eq!(e.ip, "127.0.0.1");
        assert_eq!(e.elapsed, 267_375);
        assert_eq!(e.result.reason, Reason::FilteredBlockList);
        assert!(e.result.is_filtered);
        assert_eq!(e.result.rules.len(), 1);
        assert_eq!(e.result.rules[0].text, "||doubleclick.net^");
        assert_eq!(e.result.rules[0].filter_list_id, 1);
    }

    #[test]
    fn re_encodes_a_real_line_byte_for_byte() {
        let e = Entry::from_line(REAL_LINE).unwrap();
        let out = e.to_line().unwrap();
        assert_eq!(
            out.trim_end(),
            REAL_LINE,
            "the log format must round-trip exactly"
        );
    }

    #[test]
    fn omits_the_fields_upstream_omits() {
        let e = Entry {
            time: "2026-09-14T17:41:53.85+07:00".into(),
            question_host: "example.com".into(),
            question_type: "A".into(),
            question_class: "IN".into(),
            ip: "127.0.0.1".into(),
            elapsed: 1000,
            ..Default::default()
        };

        let line = e.to_line().unwrap();
        for absent in [
            "ECS",
            "CID",
            "Upstream",
            "Answer",
            "OrigAnswer",
            "Cached",
            "AD",
        ] {
            assert!(
                !line.contains(absent),
                "{absent} should be omitted, got {line}"
            );
        }
        // A zero reason and a false IsFiltered are omitted inside Result too.
        assert!(line.contains(r#""Result":{}"#), "got {line}");
    }

    #[test]
    fn answers_round_trip_through_base64() {
        let wire = b"\x13\x23\x81\x80\x00\x01";
        let encoded = Entry::encode_answer(wire);
        assert_eq!(Entry::decode_answer(&encoded).as_deref(), Some(&wire[..]));
    }

    #[test]
    fn client_proto_strings_match_upstream() {
        assert_eq!(ClientProto::Plain.as_str(), "");
        assert_eq!(ClientProto::Doh.as_str(), "doh");
        assert_eq!(ClientProto::Doq.as_str(), "doq");
        assert_eq!(ClientProto::Dot.as_str(), "dot");
        assert_eq!(ClientProto::DnsCrypt.as_str(), "dnscrypt");

        // And they round-trip through the log's JSON.
        for p in [ClientProto::Plain, ClientProto::Doh, ClientProto::Dot] {
            let j = serde_json::to_string(&p).unwrap();
            assert_eq!(serde_json::from_str::<ClientProto>(&j).unwrap(), p);
        }
    }

    #[test]
    fn hosts_rule_addresses_are_recorded() {
        let line = r#"{"T":"2026-09-14T17:41:53.85+07:00","QH":"nas.lan","QT":"A","QC":"IN","CP":"","IP":"127.0.0.1","Result":{"Rules":[{"Text":"192.168.1.5 nas.lan","IP":"192.168.1.5","FilterListID":1}],"Reason":3,"IsFiltered":true},"Elapsed":100}"#;
        let e = Entry::from_line(line).unwrap();
        assert_eq!(e.result.rules[0].ip, Some("192.168.1.5".parse().unwrap()));
        assert_eq!(e.to_line().unwrap().trim_end(), line);
    }

    #[test]
    fn cached_and_authenticated_flags_round_trip() {
        let line = r#"{"T":"2026-09-14T17:41:53.85+07:00","QH":"example.com","QT":"A","QC":"IN","CP":"","IP":"127.0.0.1","Result":{},"Elapsed":100,"Cached":true,"AD":true}"#;
        let e = Entry::from_line(line).unwrap();
        assert!(e.cached);
        assert!(e.authenticated_data);
        assert_eq!(e.to_line().unwrap().trim_end(), line);
    }
}
