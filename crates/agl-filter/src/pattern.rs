//! Translation of adblock patterns into regular expressions.
//!
//! This mirrors `urlfilter`'s `patternToRegexp` step for step, because the
//! translation *is* the matching semantics.  Two details are easy to miss and
//! both change results on real lists:
//!
//!   * For a DNS query the pattern is matched against the **bare hostname**
//!     unless it carries a URL-specific prefix (`||`, `http://`, `https://`,
//!     `://`).  So `|load.gtm.` anchors to the start of the hostname, not to
//!     the start of `http://…`.
//!   * `^` is not "any separator": it is `([^ a-zA-Z0-9.%_-]|$)`, so a space
//!     counts as a token character, and end-of-string matches.

/// The regex `||` expands to.
const REGEX_START_URL: &str = r"^(http|https|ws|wss)://([a-z0-9_.-]+\.)?";

/// The regex `^` expands to.
const REGEX_SEPARATOR: &str = "([^ a-zA-Z0-9.%_-]|$)";

/// The minimum pattern length upstream considers when deciding a target.
const MIN_PATTERN_LEN: usize = 4;

/// What a compiled pattern is matched against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    /// The pseudo-URL `http://<hostname>`.
    Url,
    /// The bare hostname.
    Hostname,
}

/// Reports whether the pattern carries a URL-specific prefix.
fn has_url_prefix(p: &str) -> bool {
    p.starts_with("||")
        || p.starts_with("http://")
        || p.starts_with("https://")
        || p.starts_with("://")
}

/// Decides what a pattern matches against, mirroring `shouldMatchHostname`.
///
/// Every DNS query is a hostname request, so the only question is whether the
/// pattern looks URL-specific.
pub fn target_for(pattern: &str) -> Target {
    if has_url_prefix(pattern) {
        return Target::Url;
    }

    // Upstream treats a pattern that both starts with `/` and ends with `.`
    // as URL-specific; everything else matches the hostname.
    let b = pattern.as_bytes();
    let url_specific =
        b.len() >= MIN_PATTERN_LEN && b[0] == b'/' && b[b.len() - 1] == b'.';

    if url_specific { Target::Url } else { Target::Hostname }
}

/// Reports whether `p` is a `/regex/` pattern.
pub fn is_regex_pattern(p: &str) -> bool {
    p.len() > 2 && p.starts_with('/') && p.ends_with('/')
}

/// Reports whether the pattern matches every request.
pub fn matches_all(p: &str) -> bool {
    matches!(p, "||" | "|" | "*" | "")
}

/// Translates an adblock pattern into a regular expression source string.
///
/// The result is always case-insensitive: upstream compiles every pattern with
/// a `(?i)` prefix unless the rule carries `$match-case`, and real lists do
/// rely on it — `||iphone-caviar.ru*entranceId` is expected to match a
/// lowercased hostname.
pub fn to_regex(pattern: &str) -> String {
    if matches_all(pattern) {
        return ".*".to_string();
    }

    if is_regex_pattern(pattern) {
        return format!("(?i){}", &pattern[1..pattern.len() - 1]);
    }

    let s = escape_special_chars(pattern);
    let s = escape_inner_pipes(&s);
    let s = expand_masks(&s);
    let s = replace_prefix(&s);
    let s = replace_suffix(&s);

    format!("(?i){s}")
}

/// Escapes regex metacharacters, leaving `*`, `|` and `^` for later stages.
fn escape_special_chars(p: &str) -> String {
    let mut out = String::with_capacity(p.len() + 8);
    for c in p.chars() {
        if matches!(c, '.' | '+' | '?' | '$' | '{' | '}' | '(' | ')' | '[' | ']' | '/' | '\\')
        {
            out.push('\\');
        }
        out.push(c);
    }

    out
}

/// Escapes `|` characters that are neither the leading anchor nor the final
/// character, matching upstream's `escapePipes`.
fn escape_inner_pipes(s: &str) -> String {
    if s.len() <= 1 {
        return s.to_string();
    }

    let prefix_len = if s.starts_with("||") { 2 } else { 1 };
    if prefix_len >= s.len() {
        return s.to_string();
    }

    let head = &s[..prefix_len];
    let tail_start = s.len() - 1;
    if prefix_len > tail_start {
        return s.to_string();
    }
    let middle = &s[prefix_len..tail_start];
    let tail = &s[tail_start..];

    format!("{head}{}{tail}", middle.replace('|', r"\|"))
}

/// Expands `*` and `^` in a single pass, so the expansion's own characters are
/// never re-expanded.
fn expand_masks(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '*' => out.push_str(".*"),
            '^' => out.push_str(REGEX_SEPARATOR),
            c => out.push(c),
        }
    }

    out
}

/// Replaces a leading `||` or `|` anchor with its regex equivalent.
fn replace_prefix(s: &str) -> String {
    if let Some(rest) = s.strip_prefix("||") {
        return format!("{REGEX_START_URL}{rest}");
    }
    if let Some(rest) = s.strip_prefix('|') {
        return format!("^{rest}");
    }

    s.to_string()
}

/// Replaces a trailing `|` anchor with an end-of-string assertion.
fn replace_suffix(s: &str) -> String {
    match s.strip_suffix('|') {
        Some(head) => format!("{head}$"),
        None => s.to_string(),
    }
}

/// Extracts the longest literal run usable as a prefilter shortcut.
///
/// Returns `None` when nothing long enough exists.
pub fn shortcut(pattern: &str, min_len: usize) -> Option<String> {
    let src = if is_regex_pattern(pattern) {
        &pattern[1..pattern.len() - 1]
    } else {
        pattern
    };

    let mut best = "";
    let mut start = 0usize;
    let bytes = src.as_bytes();
    for i in 0..=bytes.len() {
        let is_literal = i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'.' | b'-' | b'_' | b'%'));
        if !is_literal {
            if i - start > best.len() {
                best = &src[start..i];
            }
            start = i + 1;
        }
    }

    (best.len() >= min_len).then(|| best.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    /// Compiles a pattern and matches it the way the engine will.
    fn matches(pattern: &str, hostname: &str) -> bool {
        let re = Regex::new(&to_regex(pattern)).expect("pattern must compile");
        match target_for(pattern) {
            Target::Url => re.is_match(&format!("http://{hostname}")),
            Target::Hostname => re.is_match(hostname),
        }
    }

    #[test]
    fn translates_the_domain_anchor() {
        assert_eq!(
            to_regex("||example.org^"),
            format!(r"(?i){REGEX_START_URL}example\.org{REGEX_SEPARATOR}")
        );
    }

    #[test]
    fn translates_anchors_and_wildcards() {
        assert_eq!(to_regex("|http://ads."), r"(?i)^http:\/\/ads\.");
        assert_eq!(to_regex("ads*banner"), r"(?i)ads.*banner");
        assert_eq!(to_regex("example.org|"), r"(?i)example\.org$");
    }

    #[test]
    fn bare_patterns_match_the_hostname() {
        assert_eq!(target_for("|load.gtm."), Target::Hostname);
        assert_eq!(target_for("tracker"), Target::Hostname);
        assert_eq!(target_for("/ads[0-9]/"), Target::Hostname);
    }

    #[test]
    fn url_prefixed_patterns_match_the_url() {
        assert_eq!(target_for("||example.org^"), Target::Url);
        assert_eq!(target_for("http://example.org"), Target::Url);
        assert_eq!(target_for("://example.org"), Target::Url);
        // Starts with `/` and ends with `.` — upstream's URL-specific case.
        assert_eq!(target_for("/ads."), Target::Url);
    }

    #[test]
    fn left_anchor_pins_to_the_hostname_start() {
        // This is the case that made the Go and Rust engines disagree.
        assert!(matches("|load.gtm.", "load.gtm.gaminggiveaways.co.uk"));
        assert!(!matches("|load.gtm.", "x.load.gtm.example.com"));
    }

    #[test]
    fn domain_anchor_covers_subdomains_only_at_label_boundaries() {
        assert!(matches("||example.org^", "example.org"));
        assert!(matches("||example.org^", "sub.example.org"));
        assert!(matches("||example.org^", "a.b.example.org"));
        assert!(!matches("||example.org^", "notexample.org"));
        assert!(!matches("||example.org^", "example.org.evil.com"));
    }

    #[test]
    fn domain_anchor_without_a_separator_is_a_prefix_match() {
        assert!(matches("||example.org", "example.org.evil.com"));
    }

    #[test]
    fn patterns_are_case_insensitive() {
        // Real lists contain mixed-case patterns matched against lowercased hosts.
        let re = Regex::new(&to_regex("||iphone-caviar.ru*entranceId")).unwrap();
        assert!(re.is_match("http://sub.iphone-caviar.ruxentranceid"));
    }

    #[test]
    fn separator_treats_space_as_a_token_character() {
        // `^` is `[^ a-zA-Z0-9.%_-]|$`, so a space does *not* satisfy it.
        let re = Regex::new(&to_regex("ads^")).unwrap();
        assert!(re.is_match("ads/"));
        assert!(re.is_match("ads"));
        assert!(!re.is_match("ads x"));
    }

    #[test]
    fn matches_all_patterns() {
        for p in ["||", "|", "*", ""] {
            assert!(matches_all(p), "{p:?} should match everything");
            assert_eq!(to_regex(p), ".*");
        }
    }

    #[test]
    fn extracts_shortcuts() {
        assert_eq!(shortcut("||example.org^", 3).as_deref(), Some("example.org"));
        assert_eq!(shortcut("ad*.example.com^", 3).as_deref(), Some(".example.com"));
        assert_eq!(shortcut("|a|", 3), None);
    }

    #[test]
    fn every_translated_pattern_compiles() {
        for p in [
            "||example.org^",
            "|load.gtm.",
            "ads*banner",
            "/^ads[0-9]+/",
            "||a.b-c_d.org^",
            "example.org|",
            "||example.org^$",
        ] {
            let rx = to_regex(p);
            assert!(Regex::new(&rx).is_ok(), "{p:?} produced invalid regex {rx:?}");
        }
    }
}
