//! The catalogue of known blocklists the interface offers to add.
//!
//! AdGuard Home's client bundles this list -- names, categories, homepages and
//! download addresses for the lists in AdGuard's
//! [HostlistsRegistry](https://github.com/AdguardTeam/HostlistsRegistry) -- and
//! renders it as a picker.  It is carried here instead of in the frontend, for
//! the same reason the blocked-services catalogue is: it is AdGuard's
//! compilation, `NOTICE.md` records it as such, and keeping it on this side of
//! the API leaves `web/client` free of anything of theirs.
//!
//! The categories keep their identifiers and lose their names, which upstream
//! stores as translation keys; the interface names them itself.
//!
//! The **tags, the notes and the rule counts are this project's**, not
//! AdGuard's: `scripts/blocklist-notes.json` holds what each list is good for,
//! and `scripts/import-blocklists.py --measure` downloads every list to count
//! what is really in it, so the size shown beside a list is measured rather
//! than remembered.  That file also carries any list this project adds that
//! upstream's registry does not.
//!
//! A two-letter tag is an ISO 3166-1 country code, kept out of `tags` and
//! named in `countries`, because the interface draws those as flags in a row
//! of their own.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// One list a user can add without typing its address.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Blocklist {
    /// The identifier upstream's registry gives it.
    pub id: String,
    /// The display name.
    pub name: String,
    /// The category the interface groups it under.
    #[serde(default)]
    pub category_id: String,
    /// Where the list is documented, for a reader deciding whether to add it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub homepage: String,
    /// The address the list is downloaded from.
    pub url: String,
    /// How many rules the list held when it was last measured.
    #[serde(default)]
    pub rules: u64,
    /// What the list is for, and what to expect of it.
    ///
    /// One of these is always a size, derived from `rules` at import time.
    #[serde(default)]
    pub tags: Vec<String>,
    /// A sentence or two on when to pick this list, written for this project.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// A category, as the interface groups the lists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Category {
    /// The category's identifier.
    pub id: String,
}

/// The whole catalogue.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Catalogue {
    /// The categories, in the order the interface shows them.
    #[serde(default)]
    pub categories: Vec<Category>,
    /// Every tag in use, sorted, so the interface can offer them as filters
    /// without walking the whole catalogue to find them.
    ///
    /// Country codes are **not** here; they are in [`Catalogue::countries`].
    #[serde(default)]
    pub tags: Vec<String>,
    /// The countries a list serves, as a code and the name to show with it.
    #[serde(default)]
    pub countries: std::collections::BTreeMap<String, String>,
    /// Every known list, sorted by category and then by name.
    #[serde(default)]
    pub filters: Vec<Blocklist>,
}

/// Returns the bundled catalogue, decompressing it on first use.
pub fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();

    CATALOGUE.get_or_init(|| {
        use std::io::Read as _;

        let gz: &[u8] = include_bytes!("../data/blocklists.json.gz");
        let mut s = String::new();
        if flate2::read::GzDecoder::new(gz)
            .read_to_string(&mut s)
            .is_err()
        {
            return Catalogue::default();
        }

        serde_json::from_str(&s).unwrap_or_default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalogue_decompresses_and_parses() {
        let c = catalogue();

        assert!(!c.filters.is_empty(), "the bundled catalogue is empty");
        assert!(!c.categories.is_empty(), "no categories");
    }

    #[test]
    fn every_list_is_addable() {
        // A row the interface cannot act on is worse than no row: it offers a
        // list and then fails to fetch it.
        for f in &catalogue().filters {
            assert!(!f.id.is_empty(), "a list with no identifier");
            assert!(!f.name.is_empty(), "{} has no name", f.id);
            assert!(
                f.url.starts_with("https://"),
                "{} is not downloadable over https: {}",
                f.id,
                f.url
            );
        }
    }

    #[test]
    fn every_list_belongs_to_a_declared_category() {
        // The interface groups by category and drops nothing, but a stray
        // identifier would show up as a group named after itself.
        let known: Vec<&str> = catalogue()
            .categories
            .iter()
            .map(|c| c.id.as_str())
            .collect();

        for f in &catalogue().filters {
            assert!(
                known.contains(&f.category_id.as_str()),
                "{} is in category {:?}, which is not declared",
                f.id,
                f.category_id
            );
        }
    }

    #[test]
    fn every_list_is_annotated() {
        // A row with no tags cannot be filtered to and a row with no note is
        // a name and a URL -- which is what the picker exists to improve on.
        for f in &catalogue().filters {
            assert!(!f.tags.is_empty(), "{} has no tags", f.id);
            assert!(!f.note.is_empty(), "{} has no note", f.id);
            assert!(f.rules > 0, "{} has no measured rule count", f.id);
        }
    }

    #[test]
    fn every_tag_is_declared() {
        // The interface builds its filter chips from `tags` and `countries`;
        // a tag in neither would be unreachable.
        let c = catalogue();

        for f in &c.filters {
            for t in &f.tags {
                assert!(
                    c.tags.contains(t) || c.countries.contains_key(t),
                    "{} carries tag {t:?}, which the catalogue does not declare",
                    f.id
                );
            }
        }
    }

    #[test]
    fn a_country_tag_is_a_country_code() {
        // Two letters means a flag in the interface, so anything shaped like
        // that has to be a real code with a name to show beside it -- and
        // nothing else may be two letters.
        let c = catalogue();

        for code in c.countries.keys() {
            assert!(
                code.len() == 2 && code.chars().all(|ch| ch.is_ascii_lowercase()),
                "{code:?} is not a lowercase two-letter country code"
            );
            assert!(!c.countries[code].is_empty(), "{code} has no name");
        }

        for t in &c.tags {
            assert_ne!(t.len(), 2, "{t:?} is in tags but looks like a country code");
        }
    }

    #[test]
    fn a_regional_list_names_its_country() {
        // The whole point of the country chips: a list tagged `regional` that
        // names no country cannot be found by anyone looking for their own.
        let c = catalogue();

        for f in &c.filters {
            if f.tags.iter().any(|t| t == "regional") {
                assert!(
                    f.tags.iter().any(|t| c.countries.contains_key(t)),
                    "{} is regional but names no country: {:?}",
                    f.id,
                    f.tags
                );
            }
        }
    }

    #[test]
    fn every_list_carries_exactly_one_size() {
        // The size is derived from the measured count, so two of them means
        // the importer went wrong, and none means it did not run.
        const SIZES: [&str; 5] = ["tiny", "small", "medium", "large", "huge"];

        for f in &catalogue().filters {
            let n = f
                .tags
                .iter()
                .filter(|t| SIZES.contains(&t.as_str()))
                .count();
            assert_eq!(n, 1, "{} carries {n} size tags: {:?}", f.id, f.tags);
        }
    }

    #[test]
    fn the_size_matches_the_count() {
        // Guards the one thing a human could not check by reading: that the
        // word beside a list agrees with the number measured for it.
        for f in &catalogue().filters {
            let expected = match f.rules {
                0..1_000 => "tiny",
                1_000..25_000 => "small",
                25_000..150_000 => "medium",
                150_000..1_000_000 => "large",
                _ => "huge",
            };

            assert!(
                f.tags.iter().any(|t| t == expected),
                "{} has {} rules, so it should be {expected:?}: {:?}",
                f.id,
                f.rules,
                f.tags
            );
        }
    }

    #[test]
    fn identifiers_are_unique() {
        let mut ids: Vec<&str> = catalogue().filters.iter().map(|f| f.id.as_str()).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();

        assert_eq!(before, ids.len(), "duplicate identifiers in the catalogue");
    }
}
