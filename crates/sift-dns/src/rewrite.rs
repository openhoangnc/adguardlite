//! Legacy DNS rewrites — the `filtering.rewrites` list in the config.
//!
//! Each entry maps a domain pattern to an answer.  The answer is an address,
//! a canonical name, or one of the two special values `A` and `AAAA`, which
//! mean "answer this type with nothing" rather than naming a record.

use std::net::IpAddr;

use hickory_proto::rr::RecordType;

/// What a rewrite answers with.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Answer {
    /// Answer with this address.
    Addr(IpAddr),
    /// Answer with this canonical name.
    CName(String),
    /// Answer the given type with an empty answer.
    Exclude(RecordType),
}

/// One rewrite rule.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Rewrite {
    /// The domain pattern, possibly a `*.` wildcard.
    pub domain: String,
    /// What to answer with.
    pub answer: Answer,
    /// The answer exactly as written, for reporting.
    pub answer_text: String,
}

impl Rewrite {
    /// Parses a configured rewrite entry.
    pub fn parse(domain: &str, answer: &str) -> Option<Self> {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return None;
        }

        let a = match answer.trim() {
            "A" => Answer::Exclude(RecordType::A),
            "AAAA" => Answer::Exclude(RecordType::AAAA),
            "" => return None,
            other => match other.parse::<IpAddr>() {
                Ok(ip) => Answer::Addr(ip),
                Err(_) if sift_core::name::is_valid(other) => {
                    Answer::CName(other.to_ascii_lowercase())
                }
                Err(_) => return None,
            },
        };

        Some(Rewrite {
            domain,
            answer: a,
            answer_text: answer.trim().to_string(),
        })
    }

    /// Reports whether this rewrite applies to `host`.
    pub fn matches(&self, host: &str) -> bool {
        sift_core::name::wildcard_match(&self.domain, host)
    }

    /// How specific the pattern is; an exact domain beats a wildcard.
    fn specificity(&self) -> (u8, usize) {
        let exact = u8::from(!sift_core::name::is_wildcard(&self.domain));

        (exact, self.domain.len())
    }
}

/// The result of applying the rewrite table to a query.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Answer with these addresses.
    Addrs(Vec<IpAddr>),
    /// Answer with this canonical name, then resolve it.
    CName(String),
    /// Answer with nothing.
    Empty,
}

/// A compiled set of rewrites.
#[derive(Default, Debug)]
pub struct Table {
    rules: Vec<Rewrite>,
}

impl Table {
    /// Builds a table from configured `(domain, answer, enabled)` triples.
    pub fn build<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str, bool)>) -> Self {
        let rules = entries
            .into_iter()
            .filter(|(_, _, enabled)| *enabled)
            .filter_map(|(d, a, _)| Rewrite::parse(d, a))
            .collect();

        Self { rules }
    }

    /// The number of active rewrites.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Reports whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Applies the table to a query.
    ///
    /// Returns `None` when no rewrite matches.  Among matching rules, the most
    /// specific pattern wins, and exact domains beat wildcards.
    pub fn apply(&self, host: &str, qtype: RecordType) -> Option<(Outcome, Vec<&Rewrite>)> {
        let mut matched: Vec<&Rewrite> = self.rules.iter().filter(|r| r.matches(host)).collect();
        if matched.is_empty() {
            return None;
        }

        // Keep only the most specific patterns.
        let best = matched.iter().map(|r| r.specificity()).max()?;
        matched.retain(|r| r.specificity() == best);

        // A CNAME that points at the queried name itself would loop; upstream
        // treats that as "no rewrite".
        if let Some(r) = matched
            .iter()
            .find(|r| matches!(&r.answer, Answer::CName(c) if c == host))
        {
            let _ = r;

            return None;
        }

        // An explicit exclusion for this type wins over addresses.
        if matched
            .iter()
            .any(|r| matches!(r.answer, Answer::Exclude(t) if t == qtype))
        {
            return Some((Outcome::Empty, matched));
        }

        if let Some(r) = matched
            .iter()
            .find(|r| matches!(r.answer, Answer::CName(_)))
        {
            let Answer::CName(c) = &r.answer else {
                unreachable!("checked above")
            };

            return Some((Outcome::CName(c.clone()), matched));
        }

        let addrs: Vec<IpAddr> = matched
            .iter()
            .filter_map(|r| match &r.answer {
                Answer::Addr(ip) => Some(*ip),
                _ => None,
            })
            .filter(|ip| match qtype {
                RecordType::A => ip.is_ipv4(),
                RecordType::AAAA => ip.is_ipv6(),
                _ => false,
            })
            .collect();

        if addrs.is_empty() {
            // The domain is covered but has no answer of this type.
            return Some((Outcome::Empty, matched));
        }

        Some((Outcome::Addrs(addrs), matched))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(&str, &str)]) -> Table {
        Table::build(entries.iter().map(|(d, a)| (*d, *a, true)))
    }

    #[test]
    fn parses_the_answer_forms() {
        assert_eq!(
            Rewrite::parse("a.com", "1.2.3.4").unwrap().answer,
            Answer::Addr("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            Rewrite::parse("a.com", "::1").unwrap().answer,
            Answer::Addr("::1".parse().unwrap())
        );
        assert_eq!(
            Rewrite::parse("a.com", "target.example").unwrap().answer,
            Answer::CName("target.example".into())
        );
        assert_eq!(
            Rewrite::parse("a.com", "A").unwrap().answer,
            Answer::Exclude(RecordType::A)
        );
        assert_eq!(
            Rewrite::parse("a.com", "AAAA").unwrap().answer,
            Answer::Exclude(RecordType::AAAA)
        );
        assert!(Rewrite::parse("", "1.2.3.4").is_none());
        assert!(Rewrite::parse("a.com", "").is_none());
    }

    #[test]
    fn rewrites_an_exact_domain() {
        let t = table(&[("nas.lan", "192.168.1.5")]);
        let (out, _) = t.apply("nas.lan", RecordType::A).unwrap();
        assert_eq!(out, Outcome::Addrs(vec!["192.168.1.5".parse().unwrap()]));
        assert!(t.apply("other.lan", RecordType::A).is_none());
    }

    #[test]
    fn wildcards_cover_subdomains_and_the_bare_domain() {
        let t = table(&[("*.example.com", "10.0.0.1")]);
        assert!(t.apply("a.example.com", RecordType::A).is_some());
        assert!(t.apply("example.com", RecordType::A).is_some());
        assert!(t.apply("example.org", RecordType::A).is_none());
    }

    #[test]
    fn exact_domains_beat_wildcards() {
        let t = table(&[("*.example.com", "10.0.0.1"), ("a.example.com", "10.0.0.2")]);
        let (out, rules) = t.apply("a.example.com", RecordType::A).unwrap();
        assert_eq!(out, Outcome::Addrs(vec!["10.0.0.2".parse().unwrap()]));
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn answers_are_filtered_to_the_query_type() {
        let t = table(&[("dual.lan", "1.2.3.4"), ("dual.lan", "::1")]);
        let (v4, _) = t.apply("dual.lan", RecordType::A).unwrap();
        assert_eq!(v4, Outcome::Addrs(vec!["1.2.3.4".parse().unwrap()]));

        let (v6, _) = t.apply("dual.lan", RecordType::AAAA).unwrap();
        assert_eq!(v6, Outcome::Addrs(vec!["::1".parse().unwrap()]));
    }

    #[test]
    fn a_domain_with_no_answer_of_this_type_gets_an_empty_answer() {
        let t = table(&[("v4only.lan", "1.2.3.4")]);
        assert_eq!(
            t.apply("v4only.lan", RecordType::AAAA).unwrap().0,
            Outcome::Empty
        );
    }

    #[test]
    fn the_special_values_suppress_a_type() {
        let t = table(&[("noa.lan", "AAAA")]);
        assert_eq!(
            t.apply("noa.lan", RecordType::AAAA).unwrap().0,
            Outcome::Empty
        );
    }

    #[test]
    fn cname_answers_are_returned_for_resolution() {
        let t = table(&[("alias.lan", "target.example")]);
        let (out, _) = t.apply("alias.lan", RecordType::A).unwrap();
        assert_eq!(out, Outcome::CName("target.example".into()));
    }

    #[test]
    fn a_self_referential_cname_is_ignored() {
        let t = table(&[("loop.lan", "loop.lan")]);
        assert!(t.apply("loop.lan", RecordType::A).is_none());
    }

    #[test]
    fn disabled_entries_are_skipped() {
        let t = Table::build([("nas.lan", "192.168.1.5", false)]);
        assert!(t.is_empty());
        assert!(t.apply("nas.lan", RecordType::A).is_none());
    }

    #[test]
    fn domains_are_matched_case_insensitively() {
        let t = table(&[("NAS.Lan", "192.168.1.5")]);
        assert!(t.apply("nas.lan", RecordType::A).is_some());
    }
}
