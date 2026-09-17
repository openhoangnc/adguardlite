//! The hosts refused outright by the access settings.
//!
//! `dns.blocked_hosts` — "Disallowed domains" in the interface — is a list of
//! *rules*, not of names.  Upstream's `newAccessCtx` lowercases each entry,
//! hands the whole list to `urlfilter.NewDNSEngine`, and asks it whether
//! anything matched, so the three forms the interface documents are simply
//! three rule syntaxes.  Matching them by name and suffix, which this build
//! did, both over-blocked the plain form and ignored the other two.
//!
//! Every claim below was measured against a running AdGuard Home v0.107.79,
//! not read off its source.

use std::sync::Arc;

use sift_filter::engine::{Engine, Request};

/// The access blocklist, compiled.
pub struct BlockedHosts {
    /// The rules, in the engine the filter lists already use -- which is what
    /// upstream does, so `$dnstype` and the rest come along for free.
    engine: Engine,
    /// How many entries were configured, for `Debug` and for emptiness.
    entries: usize,
}

impl Default for BlockedHosts {
    fn default() -> Self {
        Self::build(&[])
    }
}

impl std::fmt::Debug for BlockedHosts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockedHosts")
            .field("entries", &self.entries)
            .finish()
    }
}

impl BlockedHosts {
    /// Compiles the configured entries.
    pub fn build(entries: &[String]) -> Self {
        let text: String = entries.iter().map(|e| rule_for(e) + "\n").collect();

        Self {
            engine: Engine::build([(0i64, text)], sift_filter::engine::NO_LISTS),
            entries: entries.len(),
        }
    }

    /// Compiles the entries into a shared handle, as [`Settings`] holds one.
    ///
    /// [`Settings`]: crate::resolver::Settings
    pub fn shared(entries: &[String]) -> Arc<Self> {
        Arc::new(Self::build(entries))
    }

    /// Reports whether nothing is configured.
    pub fn is_empty(&self) -> bool {
        self.entries == 0
    }

    /// Reports whether a query is refused by the access blocklist.
    ///
    /// `host` must already be lowercased and free of a trailing dot.
    ///
    /// Any match at all refuses the query, including a match on an `@@`
    /// exception rule.  That looks wrong and it is upstream's behaviour:
    /// `isBlockedHost` throws the match away and keeps only the "something
    /// matched" flag (`_, ok = ...MatchRequest(...)`), so an exception in this
    /// field blocks rather than permits.  Measured: with
    /// `@@||allow.example.org^` listed, `allow.example.org` answers REFUSED.
    pub fn blocks(&self, host: &str, qtype: u16) -> bool {
        if self.is_empty() || host.is_empty() {
            return false;
        }

        !self
            .engine
            .match_request(&Request {
                hostname: host,
                qtype,
                client_ip: None,
                client_name: None,
                client_tags: &[],
            })
            .rules
            .is_empty()
    }
}

/// Turns one configured entry into the rule upstream's parser makes of it.
///
/// A bare host name becomes a *host* rule, which the engine matches by
/// equality; everything else is passed through as written.  That split is
/// upstream's, where `rules.NewRule` tries `NewHostRule` first and a line
/// holding a single valid host name becomes one.  It is also the whole reason
/// the plain form does not match subdomains: measured against the Go build,
/// `exact.example.org` refuses `exact.example.org` and answers
/// `sub.exact.example.org` normally, while `||rule.example.org^` refuses both.
fn rule_for(entry: &str) -> String {
    let e = entry.trim().to_ascii_lowercase();

    if is_plain_host(&e) {
        format!("0.0.0.0 {e}")
    } else {
        e
    }
}

/// Reports whether an entry is a bare host name rather than a rule.
///
/// Letters, digits, hyphens and dots only.  An underscore is deliberately not
/// a host name here even though DNS carries plenty of them: upstream's host
/// parser rejects it, so the line falls through to a pattern rule instead.
/// Measured, with `_test.example.org` listed: the Go build refuses
/// `sub._test.example.org` too, which only a pattern rule does.
fn is_plain_host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The list the oracle run was configured with.
    fn sample() -> BlockedHosts {
        BlockedHosts::build(&[
            "exact.example.org".into(),
            "*.wild.example.org".into(),
            "||rule.example.org^".into(),
            "_test.example.org".into(),
            "0.0.0.0 hosts.example.org".into(),
            "@@||allow.example.org^".into(),
            "||both.example.org^".into(),
            "@@||sub.both.example.org^".into(),
            "||typed.example.org^$dnstype=AAAA".into(),
        ])
    }

    /// `A`, which most of these cases use.
    const A: u16 = 1;
    /// `AAAA`.
    const AAAA: u16 = 28;

    #[test]
    fn a_plain_entry_matches_that_name_and_nothing_else() {
        // Measured against AdGuard Home v0.107.79: a plain entry is a host
        // rule, so it does *not* cover subdomains. Treating it as a suffix,
        // which this build did, refused traffic the Go build answers.
        let b = sample();
        assert!(b.blocks("exact.example.org", A));
        assert!(b.blocks("exact.example.org", AAAA));

        for host in [
            "sub.exact.example.org",
            "deep.sub.exact.example.org",
            "notexact.example.org",
            "myexact.example.org",
            "exact.example.org.evil.net",
            "example.org",
        ] {
            assert!(!b.blocks(host, A), "{host} must not be refused");
        }
    }

    #[test]
    fn a_wildcard_entry_is_an_unanchored_pattern() {
        // `*.wild.example.org` is the pattern ".wild.example.org" appearing
        // anywhere, which is why it covers a subdomain but not the domain
        // itself -- and why it reaches past the end of the name.
        let b = sample();
        for host in [
            "a.wild.example.org",
            "a.b.wild.example.org",
            "b.a.wild.example.org",
            "a.wild.example.org.evil.net",
        ] {
            assert!(b.blocks(host, A), "{host} must be refused");
        }

        for host in ["wild.example.org", "notwild.example.org"] {
            assert!(!b.blocks(host, A), "{host} must not be refused");
        }
    }

    #[test]
    fn a_rule_entry_covers_the_domain_and_its_subdomains() {
        let b = sample();
        for host in [
            "rule.example.org",
            "sub.rule.example.org",
            "x.sub.rule.example.org",
        ] {
            assert!(b.blocks(host, A), "{host} must be refused");
        }

        // `^` anchors the end, so a longer name is not covered, and neither
        // is one that merely ends with the same letters.
        for host in [
            "notrule.example.org",
            "arule.example.org",
            "rule.example.org.evil.net",
        ] {
            assert!(!b.blocks(host, A), "{host} must not be refused");
        }
    }

    #[test]
    fn an_underscore_makes_the_entry_a_pattern_rather_than_a_name() {
        let b = sample();
        assert!(b.blocks("_test.example.org", A));
        assert!(
            b.blocks("sub._test.example.org", A),
            "upstream's host parser rejects the underscore, so this is a \
             pattern and patterns are unanchored"
        );
    }

    #[test]
    fn hosts_file_syntax_is_accepted_and_exact() {
        let b = sample();
        assert!(b.blocks("hosts.example.org", A));
        assert!(!b.blocks("sub.hosts.example.org", A));
    }

    #[test]
    fn an_exception_rule_refuses_rather_than_permits() {
        // Upstream keeps only "something matched" from its engine, so `@@` in
        // this field blocks. Surprising, measured, and load-bearing.
        let b = sample();
        assert!(b.blocks("allow.example.org", A));
        assert!(b.blocks("both.example.org", A));
        assert!(b.blocks("sub.both.example.org", A));
        assert!(b.blocks("other.both.example.org", A));
    }

    #[test]
    fn the_query_type_takes_part_in_the_match() {
        // `$dnstype` works because the request carries the type, which is why
        // the matcher takes one at all.
        let b = sample();
        assert!(b.blocks("typed.example.org", AAAA));
        assert!(!b.blocks("typed.example.org", A));
        assert!(!b.blocks("typed.example.org", 16), "TXT");
    }

    #[test]
    fn a_plain_entry_matches_whatever_the_type() {
        let b = BlockedHosts::build(&["exact.example.org".into()]);
        for qtype in [1u16, 28, 16, 65, 2] {
            assert!(b.blocks("exact.example.org", qtype), "type {qtype}");
        }
    }

    #[test]
    fn entries_are_matched_case_insensitively() {
        let b = BlockedHosts::build(&[
            "EXACT.example.org".into(),
            "*.WILD.example.org".into(),
            "||RULE.example.org^".into(),
        ]);

        // The caller lowercases the question, as the resolver does.
        assert!(b.blocks("exact.example.org", A));
        assert!(b.blocks("a.wild.example.org", A));
        assert!(b.blocks("rule.example.org", A));
    }

    #[test]
    fn an_empty_list_refuses_nothing() {
        let b = BlockedHosts::default();
        assert!(b.is_empty());
        assert!(!b.blocks("anything.example.org", A));
    }

    #[test]
    fn the_defaults_are_names_and_match_only_themselves() {
        // `version.bind` and friends are the shipped defaults, and they are
        // plain names, so they must not take their subdomains with them.
        let b = BlockedHosts::build(&[
            "version.bind".into(),
            "id.server".into(),
            "hostname.bind".into(),
        ]);

        assert!(b.blocks("version.bind", 16));
        assert!(b.blocks("id.server", 16));
        assert!(b.blocks("hostname.bind", 16));
        assert!(!b.blocks("sub.version.bind", 16));
        assert!(!b.blocks("notversion.bind", 16));
    }

    #[test]
    fn entries_are_sorted_into_names_and_rules() {
        assert_eq!(rule_for("Example.ORG"), "0.0.0.0 example.org");
        assert_eq!(rule_for("  example.org  "), "0.0.0.0 example.org");
        assert_eq!(rule_for("*.example.org"), "*.example.org");
        assert_eq!(rule_for("||example.org^"), "||example.org^");
        assert_eq!(rule_for("_x.example.org"), "_x.example.org");
        assert_eq!(rule_for("0.0.0.0 example.org"), "0.0.0.0 example.org");

        assert!(is_plain_host("example.org"));
        assert!(is_plain_host("a-b.example.org"));
        assert!(!is_plain_host(""));
        assert!(
            !is_plain_host("-x.example.org"),
            "a label may not lead with -"
        );
        assert!(!is_plain_host("x-.example.org"), "nor end with one");
        assert!(
            !is_plain_host("example.org."),
            "a trailing dot is an empty label"
        );
        assert!(!is_plain_host("a_b.example.org"));
        assert!(!is_plain_host("||example.org^"));
    }
}
