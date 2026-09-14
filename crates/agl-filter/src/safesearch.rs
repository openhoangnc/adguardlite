//! Safe search, as a small filter list of `$dnsrewrite` rules.
//!
//! Each supported provider publishes a hostname that serves a filtered
//! version of its results; enforcing safe search is just rewriting the normal
//! hostname onto it.  The rule files are AdGuard's own, copied verbatim from
//! `internal/filtering/safesearch/rules/` — see `NOTICE.md`.

use crate::engine::Engine;

/// The filter list identifier upstream reserves for safe-search rules.
pub const LIST_ID: i64 = -5;

/// One search provider.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Provider {
    /// Bing.
    Bing,
    /// DuckDuckGo.
    DuckDuckGo,
    /// Ecosia.
    Ecosia,
    /// Google.
    Google,
    /// Pixabay.
    Pixabay,
    /// Yandex.
    Yandex,
    /// YouTube.
    YouTube,
}

impl Provider {
    /// Every provider, in the order the API lists them.
    pub const ALL: [Provider; 7] = [
        Provider::Bing,
        Provider::DuckDuckGo,
        Provider::Ecosia,
        Provider::Google,
        Provider::Pixabay,
        Provider::Yandex,
        Provider::YouTube,
    ];

    /// The name used in the config file and the API.
    pub const fn id(self) -> &'static str {
        match self {
            Provider::Bing => "bing",
            Provider::DuckDuckGo => "duckduckgo",
            Provider::Ecosia => "ecosia",
            Provider::Google => "google",
            Provider::Pixabay => "pixabay",
            Provider::Yandex => "yandex",
            Provider::YouTube => "youtube",
        }
    }

    /// The rules that enforce safe search for this provider.
    pub const fn rules(self) -> &'static str {
        match self {
            Provider::Bing => include_str!("safesearch/bing.txt"),
            Provider::DuckDuckGo => include_str!("safesearch/duckduckgo.txt"),
            Provider::Ecosia => include_str!("safesearch/ecosia.txt"),
            Provider::Google => include_str!("safesearch/google.txt"),
            Provider::Pixabay => include_str!("safesearch/pixabay.txt"),
            Provider::Yandex => include_str!("safesearch/yandex.txt"),
            Provider::YouTube => include_str!("safesearch/youtube.txt"),
        }
    }
}

/// Which providers safe search is enforced for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Whether safe search is enforced at all.
    pub enabled: bool,
    /// Enforce on Bing.
    pub bing: bool,
    /// Enforce on DuckDuckGo.
    pub duckduckgo: bool,
    /// Enforce on Ecosia.
    pub ecosia: bool,
    /// Enforce on Google.
    pub google: bool,
    /// Enforce on Pixabay.
    pub pixabay: bool,
    /// Enforce on Yandex.
    pub yandex: bool,
    /// Enforce on YouTube.
    pub youtube: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bing: true,
            duckduckgo: true,
            ecosia: true,
            google: true,
            pixabay: true,
            yandex: true,
            youtube: true,
        }
    }
}

impl Config {
    /// Reports whether a provider is enforced.
    pub const fn covers(&self, p: Provider) -> bool {
        match p {
            Provider::Bing => self.bing,
            Provider::DuckDuckGo => self.duckduckgo,
            Provider::Ecosia => self.ecosia,
            Provider::Google => self.google,
            Provider::Pixabay => self.pixabay,
            Provider::Yandex => self.yandex,
            Provider::YouTube => self.youtube,
        }
    }

    /// The rule text for the enabled providers, or an empty string.
    pub fn rules(&self) -> String {
        if !self.enabled {
            return String::new();
        }

        let mut out = String::new();
        for p in Provider::ALL {
            if self.covers(p) {
                out.push_str(p.rules());
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
        }

        out
    }
}

/// Builds a matching engine for the enabled providers.
///
/// Returns `None` when nothing is enforced, so callers can skip the step
/// entirely rather than matching against an empty engine on every query.
pub fn engine(cfg: &Config) -> Option<Engine> {
    let rules = cfg.rules();
    if rules.trim().is_empty() {
        return None;
    }

    Some(Engine::build([(LIST_ID, rules.as_str())], []))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Request;

    fn enabled() -> Config {
        Config {
            enabled: true,
            ..Config::default()
        }
    }

    #[test]
    fn nothing_is_built_when_safe_search_is_off() {
        assert!(engine(&Config::default()).is_none());
    }

    #[test]
    fn nothing_is_built_when_every_provider_is_off() {
        let cfg = Config {
            enabled: true,
            bing: false,
            duckduckgo: false,
            ecosia: false,
            google: false,
            pixabay: false,
            yandex: false,
            youtube: false,
        };
        assert!(engine(&cfg).is_none());
    }

    #[test]
    fn google_is_rewritten_to_the_forcing_host() {
        let e = engine(&enabled()).expect("an engine should be built");
        let m = e.match_request(&Request {
            hostname: "www.google.com",
            qtype: 1,
            client_ip: None,
            client_name: None,
            client_tags: &[],
        });

        assert_eq!(m.reason, agl_core::Reason::RewrittenRule);
        assert!(
            m.rewrites.iter().any(|r| matches!(
                r,
                crate::rule::DnsRewrite::CName(c) if c == "forcesafesearch.google.com"
            )),
            "expected a CNAME rewrite, got {:?}",
            m.rewrites
        );
    }

    #[test]
    fn yandex_is_rewritten_to_an_address() {
        let e = engine(&enabled()).unwrap();
        let m = e.match_request(&Request {
            hostname: "yandex.com",
            qtype: 1,
            client_ip: None,
            client_name: None,
            client_tags: &[],
        });

        assert_eq!(m.reason, agl_core::Reason::RewrittenRule);
        assert!(m.rewrites.iter().any(|r| matches!(
            r,
            crate::rule::DnsRewrite::Addr(ip) if ip.to_string() == "213.180.193.56"
        )));
    }

    #[test]
    fn a_disabled_provider_is_left_alone() {
        let cfg = Config {
            google: false,
            ..enabled()
        };
        let e = engine(&cfg).unwrap();
        let m = e.match_request(&Request {
            hostname: "www.google.com",
            qtype: 1,
            client_ip: None,
            client_name: None,
            client_tags: &[],
        });

        assert_eq!(m.reason, agl_core::Reason::NotFilteredNotFound);
    }

    #[test]
    fn an_unrelated_host_does_not_match() {
        let e = engine(&enabled()).unwrap();
        let m = e.match_request(&Request {
            hostname: "example.com",
            qtype: 1,
            client_ip: None,
            client_name: None,
            client_tags: &[],
        });

        assert_eq!(m.reason, agl_core::Reason::NotFilteredNotFound);
    }

    #[test]
    fn every_provider_contributes_rules() {
        for p in Provider::ALL {
            assert!(!p.rules().trim().is_empty(), "{} has no rules", p.id());
        }
    }
}
