//! Adding resolved addresses to Linux ipsets.
//!
//! The configuration names domains and the sets their addresses belong in:
//!
//! ```text
//! example.com,example.net/allow4,allow6
//! ```
//!
//! Upstream talks to the kernel over netlink.  This build runs the `ipset`
//! command instead, which needs no netlink implementation and no privileges of
//! its own beyond what the operator already grants; a cache of what has
//! already been added keeps the cost to one process per new address rather
//! than one per query.

use std::collections::HashSet;
use std::net::IpAddr;
use std::process::Command;

use parking_lot::Mutex;

/// How many additions are remembered before the cache is emptied.
///
/// A bound is needed: a resolver sees an unbounded number of addresses, and
/// forgetting simply means re-adding, which `ipset -exist` accepts.
const MAX_REMEMBERED: usize = 65_536;

/// One configured line: which domains go into which sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The domains this applies to, lowercased.
    pub domains: Vec<String>,
    /// The sets their addresses are added to.
    pub sets: Vec<String>,
}

/// Parses the configured lines.
///
/// A malformed line is skipped rather than failing startup, as upstream does
/// with an unknown service identifier: one bad line should not stop the
/// server.
pub fn parse(lines: &[String]) -> Vec<Rule> {
    lines
        .iter()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                return None;
            }

            let (domains, sets) = line.split_once('/')?;
            let domains: Vec<String> = domains
                .split(',')
                .map(|d| d.trim().trim_matches('.').to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect();
            let sets: Vec<String> = sets
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            (!domains.is_empty() && !sets.is_empty()).then_some(Rule { domains, sets })
        })
        .collect()
}

/// Reads the configured lines, preferring the file when one is named.
///
/// `ipset_file` replaces the inline list rather than adding to it, which is
/// what upstream's "this field is ignored if the file is set" means.
pub fn lines(inline: &[String], file: &str) -> Vec<String> {
    if file.is_empty() {
        return inline.to_vec();
    }

    match std::fs::read_to_string(file) {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(e) => {
            tracing::warn!(path = file, error = %e, "reading ipset_file");

            Vec::new()
        }
    }
}

/// Adds resolved addresses to the configured sets.
pub struct Manager {
    /// The configured rules.
    rules: Vec<Rule>,
    /// Which set-and-address pairs have already been added.
    seen: Mutex<HashSet<(String, IpAddr)>>,
}

impl Manager {
    /// Builds a manager, or `None` when nothing is configured.
    pub fn new(rules: Vec<Rule>) -> Option<Self> {
        if rules.is_empty() {
            return None;
        }

        Some(Self {
            rules,
            seen: Mutex::new(HashSet::new()),
        })
    }

    /// The sets a hostname's addresses belong in.
    pub fn sets_for(&self, host: &str) -> Vec<&str> {
        let host = host.trim_matches('.').to_ascii_lowercase();

        let mut out = Vec::new();
        for r in &self.rules {
            if r.domains
                .iter()
                .any(|d| sift_core::name::is_subdomain_of(&host, d))
            {
                out.extend(r.sets.iter().map(String::as_str));
            }
        }

        out.sort_unstable();
        out.dedup();

        out
    }

    /// Adds the addresses of one answer to the sets its name belongs in.
    ///
    /// Returns how many additions were attempted, which is what the debug log
    /// reports.
    pub fn add(&self, host: &str, addrs: &[IpAddr]) -> usize {
        if addrs.is_empty() {
            return 0;
        }

        let sets = self.sets_for(host);
        if sets.is_empty() {
            return 0;
        }

        let mut added = 0;
        for set in sets {
            for addr in addrs {
                if !self.remember(set, *addr) {
                    continue;
                }

                match run_ipset(set, *addr) {
                    Ok(()) => added += 1,
                    Err(e) => {
                        tracing::warn!(set, %addr, error = %e, "adding to ipset");
                        // Forget it so a later query retries once the set
                        // exists or the permissions are fixed.
                        self.forget(set, *addr);
                    }
                }
            }
        }

        added
    }

    /// Records an addition, reporting whether it is new.
    fn remember(&self, set: &str, addr: IpAddr) -> bool {
        let mut seen = self.seen.lock();
        if seen.len() >= MAX_REMEMBERED {
            seen.clear();
        }

        seen.insert((set.to_string(), addr))
    }

    /// Forgets an addition that failed.
    fn forget(&self, set: &str, addr: IpAddr) {
        self.seen.lock().remove(&(set.to_string(), addr));
    }
}

/// Runs `ipset add`, tolerating an entry that is already there.
fn run_ipset(set: &str, addr: IpAddr) -> std::io::Result<()> {
    let out = Command::new("ipset")
        .args(["add", set, &addr.to_string(), "-exist"])
        .output()?;

    if out.status.success() {
        return Ok(());
    }

    Err(std::io::Error::other(
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_names_domains_and_sets() {
        let got = parse(&["example.com,example.net/allow4,allow6".to_string()]);
        assert_eq!(
            got,
            vec![Rule {
                domains: vec!["example.com".into(), "example.net".into()],
                sets: vec!["allow4".into(), "allow6".into()],
            }]
        );
    }

    #[test]
    fn blank_and_malformed_lines_are_skipped() {
        let got = parse(&[
            String::new(),
            "# a comment".to_string(),
            "no-slash-here".to_string(),
            "/only-sets".to_string(),
            "only-domains/".to_string(),
            "a.example/set1".to_string(),
        ]);

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sets, vec!["set1".to_string()]);
    }

    #[test]
    fn domains_are_matched_including_subdomains() {
        let m = Manager::new(parse(&["example.com/allow4".to_string()])).unwrap();

        assert_eq!(m.sets_for("example.com"), vec!["allow4"]);
        assert_eq!(m.sets_for("www.example.com"), vec!["allow4"]);
        assert_eq!(m.sets_for("EXAMPLE.COM."), vec!["allow4"]);
        assert!(m.sets_for("notexample.com").is_empty());
        assert!(m.sets_for("example.net").is_empty());
    }

    #[test]
    fn overlapping_rules_are_merged_without_duplicates() {
        let m = Manager::new(parse(&[
            "example.com/allow4".to_string(),
            "www.example.com/allow4,allow6".to_string(),
        ]))
        .unwrap();

        assert_eq!(m.sets_for("www.example.com"), vec!["allow4", "allow6"]);
    }

    #[test]
    fn nothing_configured_builds_nothing() {
        assert!(Manager::new(Vec::new()).is_none());
    }

    #[test]
    fn a_file_replaces_the_inline_list() {
        let dir = std::env::temp_dir().join(format!("sift-ipset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ipset.conf");
        std::fs::write(&path, "a.example/from-file\n").unwrap();

        let got = lines(
            &["b.example/inline".to_string()],
            &path.display().to_string(),
        );
        assert_eq!(got, vec!["a.example/from-file".to_string()]);

        // And with no file the inline list is used.
        assert_eq!(
            lines(&["b.example/inline".to_string()], ""),
            vec!["b.example/inline".to_string()]
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_address_is_only_offered_once() {
        let m = Manager::new(parse(&["example.com/allow4".to_string()])).unwrap();
        let addr: IpAddr = "192.0.2.1".parse().unwrap();

        assert!(m.remember("allow4", addr));
        assert!(!m.remember("allow4", addr), "a repeat is not re-added");
        assert!(m.remember("allow6", addr), "a different set is separate");

        m.forget("allow4", addr);
        assert!(m.remember("allow4", addr), "a failure is retried later");
    }

    #[test]
    fn a_query_with_no_matching_rule_does_nothing() {
        let m = Manager::new(parse(&["example.com/allow4".to_string()])).unwrap();
        assert_eq!(m.add("other.example", &["192.0.2.1".parse().unwrap()]), 0);
        assert_eq!(m.add("example.com", &[]), 0);
    }
}
