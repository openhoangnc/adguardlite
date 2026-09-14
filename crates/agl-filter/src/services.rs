//! The blocked-services catalogue.
//!
//! AdGuard Home ships a fixed list of services, each a name, an icon and the
//! filtering rules that block it.  The catalogue here was captured from
//! `/control/blocked_services/all` on v0.107.79, so the identifiers the UI
//! sends back match the ones it was given.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// One service in the catalogue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    /// The identifier the API exchanges.
    pub id: String,
    /// The display name.
    pub name: String,
    /// The icon, as a base64-encoded SVG.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub icon_svg: String,
    /// The rules that block the service.
    #[serde(default)]
    pub rules: Vec<String>,
    /// The group the UI files the service under.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group_id: String,
}

/// A group of services, as the UI presents them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    /// The group's identifier.
    pub id: String,
    /// The group's display name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

/// The whole catalogue.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Catalogue {
    /// Every known service.
    pub blocked_services: Vec<Service>,
    /// The groups they belong to.
    #[serde(default)]
    pub groups: Vec<Group>,
}

/// Returns the bundled catalogue, decompressing it on first use.
pub fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();

    CATALOGUE.get_or_init(|| {
        use std::io::Read as _;

        let gz: &[u8] = include_bytes!("../data/blocked-services.json.gz");
        let mut s = String::new();
        if flate2::read::GzDecoder::new(gz).read_to_string(&mut s).is_err() {
            return Catalogue { blocked_services: Vec::new(), groups: Vec::new() };
        }

        serde_json::from_str(&s)
            .unwrap_or(Catalogue { blocked_services: Vec::new(), groups: Vec::new() })
    })
}

/// Looks a service up by identifier.
pub fn service(id: &str) -> Option<&'static Service> {
    catalogue().blocked_services.iter().find(|s| s.id == id)
}

/// Returns every identifier in the catalogue.
pub fn ids() -> Vec<String> {
    catalogue().blocked_services.iter().map(|s| s.id.clone()).collect()
}

/// Collects the rules that block the named services.
///
/// Unknown identifiers are skipped rather than failing: a config written by a
/// newer AdGuard Home may name a service this build's catalogue predates.
pub fn rules_for(ids: &[String]) -> String {
    let mut out = String::new();
    for id in ids {
        let Some(s) = service(id) else {
            continue;
        };
        for r in &s.rules {
            out.push_str(r);
            out.push('\n');
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_loads() {
        let c = catalogue();
        assert_eq!(c.blocked_services.len(), 139);
        assert!(!c.groups.is_empty());
    }

    #[test]
    fn services_carry_rules_and_icons() {
        let s = service("youtube").expect("youtube should be catalogued");
        assert!(!s.rules.is_empty(), "a service must bring rules to be blockable");
        assert!(!s.icon_svg.is_empty(), "the UI shows an icon");
        assert!(!s.group_id.is_empty());
    }

    #[test]
    fn rules_are_collected_for_the_named_services() {
        let rules = rules_for(&["youtube".into(), "facebook".into()]);
        assert!(rules.contains("youtube"), "got {rules}");
        assert!(rules.lines().count() > 2);
    }

    #[test]
    fn unknown_services_are_skipped() {
        // A config from a newer release may name a service this build predates.
        let rules = rules_for(&["not-a-real-service".into(), "youtube".into()]);
        assert!(!rules.is_empty(), "the known service still contributes");

        assert!(rules_for(&["not-a-real-service".into()]).is_empty());
    }

    #[test]
    fn every_identifier_is_listed() {
        let all = ids();
        assert_eq!(all.len(), 139);
        assert!(all.contains(&"youtube".to_string()));
        assert!(all.iter().all(|i| service(i).is_some()));
    }

    #[test]
    fn the_catalogue_rules_actually_parse() {
        // A rule the engine cannot parse would silently fail to block.
        let mut unparsed = Vec::new();
        for s in &catalogue().blocked_services {
            for r in &s.rules {
                if crate::rule::parse(r, 0).is_err() {
                    unparsed.push(format!("{}: {r}", s.id));
                }
            }
        }

        assert!(
            unparsed.is_empty(),
            "{} catalogue rules do not parse:\n{}",
            unparsed.len(),
            unparsed.iter().take(10).cloned().collect::<Vec<_>>().join("\n")
        );
    }
}
