//! The indexed rule store and the matching engine.
//!
//! Lookup strategy, in the order candidates are gathered:
//!
//!   1. **Domain index** — `||domain^` rules, by far the bulk of DNS
//!      blocklists, live in a hash map keyed by domain.  A query walks its own
//!      parent domains, so matching costs one hash lookup per label.
//!   2. **Shortcut index** — other literal patterns are prefiltered with an
//!      Aho–Corasick automaton over their longest literal substring.
//!   3. **Scan list** — regexes and patterns too short to index are checked
//!      one by one.  This list is kept small.

use std::net::IpAddr;

use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use agl_core::Reason;

use crate::pattern::Target;
use crate::rule::{DnsRewrite, HostRule, MIN_SHORTCUT_LEN, NetworkRule, Pattern, Rule, parse};

/// The rule indices stored under one index key.
///
/// Almost every domain is named by exactly one rule, so the common case is
/// kept inline: a `Vec` here would cost a 24-byte header plus a heap
/// allocation apiece, tens of megabytes across a real blocklist.
#[derive(Clone, Debug)]
enum Refs {
    /// A single rule.
    One(u32),
    /// Several rules, in load order.
    Many(Vec<u32>),
}

impl Refs {
    /// Adds an index, promoting to the heap only when a second one arrives.
    fn push(&mut self, idx: u32) {
        match self {
            Refs::One(first) => *self = Refs::Many(vec![*first, idx]),
            Refs::Many(v) => v.push(idx),
        }
    }

    /// Iterates the stored indices.
    fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        match self {
            Refs::One(i) => std::slice::from_ref(i).iter().copied(),
            Refs::Many(v) => v.iter().copied(),
        }
    }
}

/// A DNS filtering request.
#[derive(Clone, Debug, Default)]
pub struct Request<'a> {
    /// The queried hostname, already lowercased and without a trailing dot.
    pub hostname: &'a str,
    /// The query type, e.g. 1 for `A`.
    pub qtype: u16,
    /// The client's address, if known.
    pub client_ip: Option<IpAddr>,
    /// The client's name or ClientID, if known.
    pub client_name: Option<&'a str>,
    /// The client's tags.
    pub client_tags: &'a [String],
}

/// A rule that contributed to a match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatchedRule {
    /// The rule's original text.
    pub text: String,
    /// The list the rule came from.
    pub list_id: i64,
    /// The address a host rule resolves to, if this was a host rule.
    pub ip: Option<IpAddr>,
}

/// The outcome of matching a request.
#[derive(Clone, Debug, Default)]
pub struct MatchResult {
    /// Why the request was filtered, allowed or rewritten.
    pub reason: Reason,
    /// The rules that matched.
    pub rules: Vec<MatchedRule>,
    /// The response to synthesise, for `$dnsrewrite` matches.
    pub rewrites: Vec<DnsRewrite>,
}

impl MatchResult {
    /// Reports whether anything matched.
    pub fn matched(&self) -> bool {
        self.reason.matched()
    }
}

/// An indexed set of rules from one group of lists.
#[derive(Default)]
pub struct RuleSet {
    net: Vec<NetworkRule>,
    hosts: Vec<HostRule>,
    domain_index: AHashMap<Box<str>, Refs>,
    host_index: AHashMap<Box<str>, Refs>,
    ac: Option<AhoCorasick>,
    ac_rules: Vec<Vec<u32>>,
    scan: Vec<u32>,
    badfilter: AHashSet<Box<str>>,
    rules_count: usize,
}

impl RuleSet {
    /// Builds a rule set from the lines of one or more lists.
    ///
    /// `lists` pairs a list identifier with its text.  Unparseable lines are
    /// skipped, as upstream does, rather than failing the whole list.
    pub fn build<'a>(lists: impl IntoIterator<Item = (i64, &'a str)>) -> Self {
        let mut b = Builder::default();
        for (id, text) in lists {
            b.add_list(id, text);
        }

        b.finish()
    }

    /// The number of rules that were loaded.
    pub fn len(&self) -> usize {
        self.rules_count
    }

    /// Reports whether the set holds no rules.
    pub fn is_empty(&self) -> bool {
        self.rules_count == 0
    }

    /// Finds the applicable network rules for `req` and returns the winner,
    /// plus every `$dnsrewrite` rule that applies.
    fn match_network(&self, req: &Request<'_>) -> (Option<&NetworkRule>, Vec<&NetworkRule>) {
        let url = format!("http://{}", req.hostname);

        let mut best: Option<(u32, &NetworkRule)> = None;
        let mut rewrites: Vec<&NetworkRule> = Vec::new();
        let mut seen = AHashSet::new();

        // 1. Domain index: walk the query's parent domains.
        for suffix in agl_core::name::suffixes(req.hostname) {
            if let Some(ids) = self.domain_index.get(suffix) {
                for i in ids.iter() {
                    self.consider(i, req, &url, &mut best, &mut rewrites, &mut seen);
                }
            }
        }

        // 2. Shortcut index.
        if let Some(ac) = &self.ac {
            for m in ac.find_overlapping_iter(&url) {
                for &i in &self.ac_rules[m.pattern().as_usize()] {
                    self.consider(i, req, &url, &mut best, &mut rewrites, &mut seen);
                }
            }
        }

        // 3. Everything that could not be indexed.
        for &i in &self.scan {
            self.consider(i, req, &url, &mut best, &mut rewrites, &mut seen);
        }

        (best.map(|(_, r)| r), rewrites)
    }

    /// Folds candidate rule `idx` into the running best rule and rewrite list.
    #[allow(clippy::too_many_arguments)]
    fn consider<'r>(
        &'r self,
        idx: u32,
        req: &Request<'_>,
        url: &str,
        best: &mut Option<(u32, &'r NetworkRule)>,
        rewrites: &mut Vec<&'r NetworkRule>,
        seen: &mut AHashSet<u32>,
    ) {
        if !seen.insert(idx) {
            return;
        }

        let r = &self.net[idx as usize];
        if !self.applies(r, req, url) {
            return;
        }

        if r.dnsrewrite().is_some() {
            rewrites.push(r);

            return;
        }

        if best.is_none_or(|(bi, b)| higher_priority((idx, r), (bi, b))) {
            *best = Some((idx, r));
        }
    }

    /// Reports whether `r` applies to `req`, checking both the pattern and the
    /// modifiers.
    fn applies(&self, r: &NetworkRule, req: &Request<'_>, url: &str) -> bool {
        if r.badfilter() || self.badfilter.contains(canonical_text(&r.text).as_str()) {
            return false;
        }

        let Some(opts) = r.opts() else {
            // No modifiers: only the pattern decides.
            return self.pattern_matches(r, req, url);
        };

        if let Some(t) = &opts.dnstype
            && !t.matches(req.qtype)
        {
            return false;
        }

        if let Some(c) = &opts.client {
            let ip = req.client_ip.map(|i| i.to_string());
            let name_ok = req.client_name.is_some_and(|n| c.matches(n));
            let ip_ok = ip.as_deref().is_some_and(|i| c.matches(i));
            // An all-negative list applies unless the client is excluded.
            let neg_only = c.included.is_empty();
            if !(name_ok || ip_ok || (neg_only && !excluded(c, req))) {
                return false;
            }
        }

        if let Some(t) = &opts.ctag
            && !t.matches_any(req.client_tags)
        {
            return false;
        }

        if !opts.denyallow.is_empty()
            && opts
                .denyallow
                .iter()
                .any(|d| agl_core::name::is_subdomain_of(req.hostname, d))
        {
            return false;
        }

        self.pattern_matches(r, req, url)
    }

    /// Reports whether the rule's pattern matches the request.
    fn pattern_matches(&self, r: &NetworkRule, req: &Request<'_>, url: &str) -> bool {
        match &r.pattern {
            Pattern::Any => true,
            // Reaching a domain-anchored rule means the domain index already
            // matched one of the hostname's suffixes.
            Pattern::DomainAnchor => true,
            Pattern::Rx { re, target } => match target {
                Target::Url => re.is_match(url),
                Target::Hostname => re.is_match(req.hostname),
            },
        }
    }

    /// Finds host rules for the request's hostname.
    fn match_hosts(&self, req: &Request<'_>) -> Vec<&HostRule> {
        self.host_index
            .get(req.hostname)
            .map(|ids| ids.iter().map(|i| &self.hosts[i as usize]).collect())
            .unwrap_or_default()
    }
}

/// Reports whether the client is explicitly excluded by the rule's list.
fn excluded(c: &crate::rule::StrList, req: &Request<'_>) -> bool {
    let ip = req.client_ip.map(|i| i.to_string());

    c.excluded.iter().any(|e| {
        req.client_name.is_some_and(|n| n.eq_ignore_ascii_case(e))
            || ip.as_deref().is_some_and(|i| i.eq_ignore_ascii_case(e))
    })
}

/// The priority class of a rule.  Upstream's ordering is:
/// whitelist+important, important, whitelist, then basic rules.
fn rank(r: &NetworkRule) -> u8 {
    match (r.allowlist, r.important()) {
        (true, true) => 3,
        (false, true) => 2,
        (true, false) => 1,
        (false, false) => 0,
    }
}

/// Reports whether `a` outranks `b`.
///
/// Upstream compares by priority class, then by the *number of specifiers* a
/// rule carries — not by pattern length — and leaves equal rules in the order
/// the engine happened to visit them.  Here the final tie-break is the rule's
/// load order, which reproduces upstream's observed choice while staying
/// independent of index-traversal order.
fn higher_priority(a: (u32, &NetworkRule), b: (u32, &NetworkRule)) -> bool {
    let (ai, ar) = a;
    let (bi, br) = b;

    let (ra, rb) = (rank(ar), rank(br));
    if ra != rb {
        return ra > rb;
    }

    let (sa, sb) = (ar.specificity(), br.specificity());
    if sa != sb {
        return sa > sb;
    }

    ai < bi
}

/// Strips the `$badfilter` modifier so a badfilter rule can be compared with
/// the rule it cancels.
fn canonical_text(text: &str) -> String {
    let Some(dollar) = text.rfind('$') else {
        return text.to_string();
    };

    let (head, mods) = text.split_at(dollar);
    let kept: Vec<&str> = mods[1..]
        .split(',')
        .filter(|m| m.trim() != "badfilter")
        .collect();

    if kept.is_empty() {
        head.to_string()
    } else {
        format!("{head}${}", kept.join(","))
    }
}

/// Inserts a rule index into a `Refs`-valued map.
fn push_ref(map: &mut AHashMap<Box<str>, Refs>, key: Box<str>, idx: u32) {
    match map.entry(key) {
        std::collections::hash_map::Entry::Occupied(mut e) => e.get_mut().push(idx),
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(Refs::One(idx));
        }
    }
}

/// Accumulates rules and builds the lookup indexes.
#[derive(Default)]
struct Builder {
    net: Vec<NetworkRule>,
    hosts: Vec<HostRule>,
    domain_index: AHashMap<Box<str>, Refs>,
    host_index: AHashMap<Box<str>, Refs>,
    shortcuts: AHashMap<String, Vec<u32>>,
    scan: Vec<u32>,
    badfilter: AHashSet<Box<str>>,
    rules_count: usize,
}

impl Builder {
    /// Parses and indexes every line of one list.
    fn add_list(&mut self, id: i64, text: &str) {
        for line in text.lines() {
            match parse(line, id) {
                Ok(Rule::Network(n)) => self.add_network(n.rule, n.shortcut),
                Ok(Rule::Host(h)) => self.add_host(h),
                Err(_) => {}
            }
        }
    }

    /// Indexes one network rule.
    fn add_network(&mut self, r: NetworkRule, shortcut: Option<String>) {
        self.rules_count += 1;

        if r.badfilter() {
            self.badfilter.insert(canonical_text(&r.text).into_boxed_str());
        }

        let idx = self.net.len() as u32;

        match (&r.pattern, shortcut) {
            (Pattern::DomainAnchor, Some(d)) => {
                push_ref(&mut self.domain_index, d.into_boxed_str(), idx);
            }
            (Pattern::Rx { .. }, Some(sc)) if sc.len() >= MIN_SHORTCUT_LEN => {
                self.shortcuts.entry(sc).or_default().push(idx);
            }
            _ => self.scan.push(idx),
        }

        self.net.push(r);
    }

    /// Indexes one hosts-file rule.
    fn add_host(&mut self, h: HostRule) {
        self.rules_count += 1;
        let idx = self.hosts.len() as u32;
        for name in &h.hostnames {
            push_ref(&mut self.host_index, name.clone().into_boxed_str(), idx);
        }
        self.hosts.push(h);
    }

    /// Finalises the indexes into a queryable rule set.
    fn finish(self) -> RuleSet {
        let Builder {
            net,
            hosts,
            domain_index,
            host_index,
            shortcuts,
            scan,
            badfilter,
            rules_count,
        } = self;

        let (patterns, ac_rules): (Vec<String>, Vec<Vec<u32>>) = shortcuts.into_iter().unzip();
        let ac = if patterns.is_empty() {
            None
        } else {
            AhoCorasickBuilder::new()
                .match_kind(MatchKind::Standard)
                .ascii_case_insensitive(true)
                .build(&patterns)
                .ok()
        };

        RuleSet {
            net,
            hosts,
            domain_index,
            host_index,
            ac,
            ac_rules,
            scan,
            badfilter,
            rules_count,
        }
    }
}

/// The filtering engine: an allowlist set that short-circuits, and a blocklist
/// set consulted when nothing allowed the request.
#[derive(Default)]
pub struct Engine {
    /// Rules from allowlists.  Any match here allows the request outright.
    pub allow: RuleSet,
    /// Rules from blocklists and the user's custom rules.
    pub block: RuleSet,
}

impl Engine {
    /// Builds an engine from blocklist and allowlist sources.
    pub fn build<'a>(
        block: impl IntoIterator<Item = (i64, &'a str)>,
        allow: impl IntoIterator<Item = (i64, &'a str)>,
    ) -> Self {
        Self { allow: RuleSet::build(allow), block: RuleSet::build(block) }
    }

    /// The total number of loaded rules.
    pub fn len(&self) -> usize {
        self.allow.len() + self.block.len()
    }

    /// Reports whether the engine holds no rules.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Matches a request.
    ///
    /// The order mirrors upstream: allowlists win outright, then
    /// `$dnsrewrite` rules, then ordinary blocking and host rules.
    pub fn match_request(&self, req: &Request<'_>) -> MatchResult {
        if req.hostname.is_empty() {
            return MatchResult::default();
        }

        // 1. Allowlists short-circuit.
        if !self.allow.is_empty() {
            let (net, _) = self.allow.match_network(req);
            if let Some(r) = net {
                return MatchResult {
                    reason: Reason::NotFilteredAllowList,
                    rules: vec![to_matched(r)],
                    rewrites: Vec::new(),
                };
            }
            let hosts = self.allow.match_hosts(req);
            if !hosts.is_empty() {
                return MatchResult {
                    reason: Reason::NotFilteredAllowList,
                    rules: hosts.iter().map(|h| host_matched(h)).collect(),
                    rewrites: Vec::new(),
                };
            }
        }

        let (net, rewrites) = self.block.match_network(req);

        // 2. `$dnsrewrite` rules, unless one of them excludes the host.
        if !rewrites.is_empty() {
            let excluded = rewrites
                .iter()
                .any(|r| matches!(r.dnsrewrite(), Some(DnsRewrite::Exclude)));
            if !excluded {
                return MatchResult {
                    reason: Reason::RewrittenRule,
                    rules: rewrites.iter().map(|r| to_matched(r)).collect(),
                    rewrites: rewrites
                        .iter()
                        .filter_map(|r| r.dnsrewrite().cloned())
                        .collect(),
                };
            }
        }

        // 3. The winning basic rule.
        if let Some(r) = net {
            let reason = if r.allowlist {
                Reason::NotFilteredAllowList
            } else {
                Reason::FilteredBlockList
            };

            return MatchResult { reason, rules: vec![to_matched(r)], rewrites: Vec::new() };
        }

        // 4. Host rules.
        let hosts = self.block.match_hosts(req);
        if !hosts.is_empty() {
            // Upstream narrows to the matching address family for A and AAAA
            // queries, and falls back to any rule for other types.
            let want_v4 = req.qtype == 1;
            let want_v6 = req.qtype == 28;
            let selected: Vec<&HostRule> = if want_v4 || want_v6 {
                let f: Vec<&HostRule> = hosts
                    .iter()
                    .copied()
                    .filter(|h| h.ip.is_ipv4() == want_v4)
                    .collect();
                if f.is_empty() { hosts.clone() } else { f }
            } else {
                hosts.clone()
            };

            return MatchResult {
                reason: Reason::FilteredBlockList,
                rules: selected.iter().map(|h| host_matched(h)).collect(),
                rewrites: Vec::new(),
            };
        }

        MatchResult::default()
    }
}

/// Converts a network rule into its reportable form.
fn to_matched(r: &NetworkRule) -> MatchedRule {
    MatchedRule { text: r.text.to_string(), list_id: r.list_id, ip: None }
}

/// Converts a host rule into its reportable form.
fn host_matched(h: &HostRule) -> MatchedRule {
    MatchedRule { text: h.text.clone(), list_id: h.list_id, ip: Some(h.ip) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: u16 = 1;
    const AAAA: u16 = 28;
    const TXT: u16 = 16;

    fn engine(block: &str) -> Engine {
        Engine::build([(1i64, block)], [])
    }

    fn req<'a>(host: &'a str, qtype: u16) -> Request<'a> {
        Request { hostname: host, qtype, ..Default::default() }
    }

    fn matches(e: &Engine, host: &str) -> MatchResult {
        e.match_request(&req(host, A))
    }

    #[test]
    fn blocks_via_the_domain_anchor_fast_path() {
        let e = engine("||ads.example.com^\n");
        assert_eq!(matches(&e, "ads.example.com").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "x.ads.example.com").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "example.com").reason, Reason::NotFilteredNotFound);
        assert_eq!(matches(&e, "notads.example.com").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn hosts_rules_block_and_carry_their_address() {
        let e = engine("0.0.0.0 ads.example.com\n");
        let r = matches(&e, "ads.example.com");
        assert_eq!(r.reason, Reason::FilteredBlockList);
        assert_eq!(r.rules[0].ip, Some("0.0.0.0".parse().unwrap()));

        // Hosts rules are exact: subdomains are not covered.
        assert_eq!(matches(&e, "x.ads.example.com").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn hosts_rules_select_by_address_family() {
        let e = engine("0.0.0.0 a.example.com\n:: a.example.com\n");
        let v4 = e.match_request(&req("a.example.com", A));
        assert_eq!(v4.rules.len(), 1);
        assert!(v4.rules[0].ip.unwrap().is_ipv4());

        let v6 = e.match_request(&req("a.example.com", AAAA));
        assert_eq!(v6.rules.len(), 1);
        assert!(v6.rules[0].ip.unwrap().is_ipv6());
    }

    #[test]
    fn exception_rules_beat_blocking_rules() {
        let e = engine("||example.com^\n@@||good.example.com^\n");
        assert_eq!(matches(&e, "bad.example.com").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "good.example.com").reason, Reason::NotFilteredAllowList);
    }

    #[test]
    fn important_beats_an_exception() {
        let e = engine("||example.com^$important\n@@||example.com^\n");
        assert_eq!(matches(&e, "example.com").reason, Reason::FilteredBlockList);
    }

    #[test]
    fn important_exception_beats_important_block() {
        let e = engine("||example.com^$important\n@@||example.com^$important\n");
        assert_eq!(matches(&e, "example.com").reason, Reason::NotFilteredAllowList);
    }

    #[test]
    fn a_separate_allowlist_short_circuits() {
        let e = Engine::build([(1i64, "||example.com^")], [(2i64, "||example.com^")]);
        let r = matches(&e, "example.com");
        assert_eq!(r.reason, Reason::NotFilteredAllowList);
        assert_eq!(r.rules[0].list_id, 2);
    }

    #[test]
    fn badfilter_cancels_the_matching_rule() {
        let e = engine("||example.com^\n||example.com^$badfilter\n");
        assert_eq!(matches(&e, "example.com").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn dnstype_restricts_the_rule() {
        let e = engine("||example.com^$dnstype=AAAA\n");
        assert_eq!(e.match_request(&req("example.com", AAAA)).reason, Reason::FilteredBlockList);
        assert_eq!(e.match_request(&req("example.com", A)).reason, Reason::NotFilteredNotFound);
        assert_eq!(e.match_request(&req("example.com", TXT)).reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn denyallow_exempts_listed_domains() {
        let e = engine("||example.com^$denyallow=good.example.com\n");
        assert_eq!(matches(&e, "bad.example.com").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "good.example.com").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn client_modifier_restricts_by_name_and_address() {
        let e = engine("||example.com^$client=192.168.1.5\n");

        let mut r = req("example.com", A);
        r.client_ip = Some("192.168.1.5".parse().unwrap());
        assert_eq!(e.match_request(&r).reason, Reason::FilteredBlockList);

        let mut r = req("example.com", A);
        r.client_ip = Some("192.168.1.6".parse().unwrap());
        assert_eq!(e.match_request(&r).reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn ctag_modifier_restricts_by_tag() {
        let e = engine("||example.com^$ctag=device_phone\n");
        let tags = vec!["device_phone".to_string()];
        let r = Request { hostname: "example.com", qtype: A, client_tags: &tags, ..Default::default() };
        assert_eq!(e.match_request(&r).reason, Reason::FilteredBlockList);

        let other = vec!["device_pc".to_string()];
        let r = Request { hostname: "example.com", qtype: A, client_tags: &other, ..Default::default() };
        assert_eq!(e.match_request(&r).reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn dnsrewrite_reports_a_rewrite() {
        let e = engine("||example.com^$dnsrewrite=1.2.3.4\n");
        let r = matches(&e, "example.com");
        assert_eq!(r.reason, Reason::RewrittenRule);
        assert_eq!(r.rewrites, vec![DnsRewrite::Addr("1.2.3.4".parse().unwrap())]);
    }

    #[test]
    fn regex_rules_match_against_the_hostname() {
        // For DNS, a `/regex/` pattern is applied to the bare hostname.
        let e = engine("/^ads[0-9]+\\./\n");
        assert_eq!(matches(&e, "ads123.example.com").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "example.com").reason, Reason::NotFilteredNotFound);
        assert_eq!(matches(&e, "x.ads123.example.com").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn a_left_anchored_bare_pattern_pins_to_the_hostname() {
        // The case the Go differential test caught: `|foo.` anchors to the
        // hostname start, not to `http://`.
        let e = engine("|load.gtm.\n");
        assert_eq!(matches(&e, "load.gtm.example.co.uk").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "x.load.gtm.example.co.uk").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn wildcard_text_rules_match() {
        let e = engine("||ad*.example.com^\n");
        assert_eq!(matches(&e, "ads.example.com").reason, Reason::FilteredBlockList);
        assert_eq!(matches(&e, "news.example.com").reason, Reason::NotFilteredNotFound);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let e = engine("! a comment\n\n||example.com^\n# another\n");
        assert_eq!(e.block.len(), 1);
    }

    #[test]
    fn empty_engine_matches_nothing() {
        let e = Engine::default();
        assert!(e.is_empty());
        assert_eq!(matches(&e, "example.com").reason, Reason::NotFilteredNotFound);
    }
}
