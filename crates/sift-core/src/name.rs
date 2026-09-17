//! Domain-name normalisation shared by the filter engine, DNS server and API.

/// Lowercases `host` and strips one trailing dot, allocating only when the
/// input is not already normalised.
pub fn normalize(host: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

/// Yields `host` and each of its parent domains, longest first.
///
/// `a.b.example.com` yields `a.b.example.com`, `b.example.com`, `example.com`,
/// `com`.
pub fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    let mut cur = Some(host);
    std::iter::from_fn(move || {
        let c = cur?;
        cur = c
            .split_once('.')
            .map(|(_, rest)| rest)
            .filter(|r| !r.is_empty());

        Some(c)
    })
}

/// Reports whether `host` is equal to `domain` or is a subdomain of it.
pub fn is_subdomain_of(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }

    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// Reports whether `host` looks like a valid DNS name: non-empty, at most 253
/// bytes, labels of 1..=63 bytes, no empty labels.
pub fn is_valid(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }

    host.split('.').all(|l| !l.is_empty() && l.len() <= 63)
}

/// Reports whether `host` is a wildcard pattern (contains `*`).
pub fn is_wildcard(host: &str) -> bool {
    host.contains('*')
}

/// Matches `host` against a pattern that may contain `*` wildcards.
///
/// A leading `*.` matches any subdomain but, matching upstream's rewrite
/// behaviour, also the bare domain itself.
pub fn wildcard_match(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return is_subdomain_of(host, suffix);
    }

    glob_match(pattern.as_bytes(), host.as_bytes())
}

/// A minimal `*`-only glob matcher, iterative so it cannot blow the stack.
fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);

    while t < text.len() {
        if p < pat.len() && (pat[p] == text[t] || pat[p] == b'?') {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = p;
            mark = t;
            p += 1;
        } else if star != usize::MAX {
            p = star + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }

    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }

    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        assert_eq!(normalize("Example.COM."), "example.com");
        assert_eq!(normalize("example.com"), "example.com");
        // Already normalised input must not allocate.
        assert!(matches!(normalize("a.b"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn enumerates_parent_domains() {
        let got: Vec<_> = suffixes("a.b.example.com").collect();
        assert_eq!(
            got,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
        assert_eq!(suffixes("com").collect::<Vec<_>>(), ["com"]);
    }

    #[test]
    fn subdomain_check_requires_a_label_boundary() {
        assert!(is_subdomain_of("a.example.com", "example.com"));
        assert!(is_subdomain_of("example.com", "example.com"));
        // "notexample.com" must not count as a subdomain of "example.com".
        assert!(!is_subdomain_of("notexample.com", "example.com"));
        assert!(!is_subdomain_of("example.com", "a.example.com"));
    }

    #[test]
    fn validates_names() {
        assert!(is_valid("example.com"));
        assert!(!is_valid(""));
        assert!(!is_valid("a..b"));
        assert!(!is_valid(&"a".repeat(64)));
        assert!(is_valid(&"a".repeat(63)));
        assert!(!is_valid(&vec!["aaaaaaaa"; 40].join(".")));
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*.example.com", "a.example.com"));
        assert!(wildcard_match("*.example.com", "example.com"));
        assert!(!wildcard_match("*.example.com", "example.org"));
        assert!(wildcard_match("ad*.example.com", "ads.example.com"));
        assert!(!wildcard_match("ad*.example.com", "bd.example.com"));
        assert!(wildcard_match("exact.com", "exact.com"));
    }
}
