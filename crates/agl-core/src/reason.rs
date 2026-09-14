//! Filtering result reasons, wire-compatible with `internal/filtering.Reason`.

use std::fmt;

/// Why a query was filtered, allowed, or rewritten.
///
/// The discriminants must stay in sync with upstream: they are persisted as
/// integers in the query log's `Result.Reason` field.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Reason {
    /// The host was not found in any check.  The default.
    #[default]
    NotFilteredNotFound = 0,
    /// The host is explicitly allowed.
    NotFilteredAllowList = 1,
    /// An error occurred during checking.  Reserved, currently unused.
    NotFilteredError = 2,
    /// The host matched a blocklist rule.
    FilteredBlockList = 3,
    /// The host was found to be malicious or phishing.
    FilteredSafeBrowsing = 4,
    /// The host is outside of parental control settings.
    FilteredParental = 5,
    /// The request was invalid and was not processed.
    FilteredInvalid = 6,
    /// The host was replaced with a safe-search variant.
    FilteredSafeSearch = 7,
    /// The host is blocked by the blocked-services feature.
    FilteredBlockedService = 8,
    /// A legacy DNS rewrite rule was applied.
    Rewritten = 9,
    /// A rewrite came from the hosts file.
    RewrittenAutoHosts = 10,
    /// A `$dnsrewrite` filter rule was applied.
    RewrittenRule = 11,
}

impl Reason {
    /// All reasons in discriminant order.
    pub const ALL: [Reason; 12] = [
        Reason::NotFilteredNotFound,
        Reason::NotFilteredAllowList,
        Reason::NotFilteredError,
        Reason::FilteredBlockList,
        Reason::FilteredSafeBrowsing,
        Reason::FilteredParental,
        Reason::FilteredInvalid,
        Reason::FilteredSafeSearch,
        Reason::FilteredBlockedService,
        Reason::Rewritten,
        Reason::RewrittenAutoHosts,
        Reason::RewrittenRule,
    ];

    /// Reports whether anything matched at all.
    pub const fn matched(self) -> bool {
        !matches!(self, Reason::NotFilteredNotFound)
    }

    /// Reports whether the query should be answered with a blocked response.
    pub const fn is_filtered(self) -> bool {
        matches!(
            self,
            Reason::FilteredBlockList
                | Reason::FilteredSafeBrowsing
                | Reason::FilteredParental
                | Reason::FilteredInvalid
                | Reason::FilteredBlockedService
        )
    }

    /// The name used in the HTTP API.
    ///
    /// These deliberately differ from the Rust identifiers: upstream kept the
    /// older wire names when the constants were renamed.
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::NotFilteredNotFound => "NotFilteredNotFound",
            Reason::NotFilteredAllowList => "NotFilteredWhiteList",
            Reason::NotFilteredError => "NotFilteredError",
            Reason::FilteredBlockList => "FilteredBlackList",
            Reason::FilteredSafeBrowsing => "FilteredSafeBrowsing",
            Reason::FilteredParental => "FilteredParental",
            Reason::FilteredInvalid => "FilteredInvalid",
            Reason::FilteredSafeSearch => "FilteredSafeSearch",
            Reason::FilteredBlockedService => "FilteredBlockedService",
            Reason::Rewritten => "Rewrite",
            Reason::RewrittenAutoHosts => "RewriteEtcHosts",
            Reason::RewrittenRule => "RewriteRule",
        }
    }

    /// Looks a reason up by its API name.
    pub fn from_name(s: &str) -> Option<Self> {
        Reason::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Converts from the persisted integer discriminant.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Reason::NotFilteredNotFound,
            1 => Reason::NotFilteredAllowList,
            2 => Reason::NotFilteredError,
            3 => Reason::FilteredBlockList,
            4 => Reason::FilteredSafeBrowsing,
            5 => Reason::FilteredParental,
            6 => Reason::FilteredInvalid,
            7 => Reason::FilteredSafeSearch,
            8 => Reason::FilteredBlockedService,
            9 => Reason::Rewritten,
            10 => Reason::RewrittenAutoHosts,
            11 => Reason::RewrittenRule,
            _ => return None,
        })
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for Reason {
    /// Serialises as the integer discriminant, matching the query log.
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for Reason {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Reason;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a filtering reason")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Reason, E> {
                Reason::from_u8(v as u8)
                    .ok_or_else(|| serde::de::Error::custom(format!("unknown reason {v}")))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Reason, E> {
                self.visit_u64(v.max(0) as u64)
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Reason, E> {
                Reason::from_name(s)
                    .ok_or_else(|| serde::de::Error::custom(format!("unknown reason {s:?}")))
            }
        }

        de.deserialize_any(V)
    }
}

/// The number of statistics result buckets, matching upstream's `resultLast`.
///
/// Upstream's stats package groups results into: not filtered, filtered
/// (blocklist), safe browsing, safe search, parental, and the total.
pub const STATS_RESULT_COUNT: usize = 6;

/// A statistics bucket index, matching upstream's `Result` constants in the
/// stats package.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum StatsResult {
    /// Not filtered.
    NotFiltered = 1,
    /// Filtered by a blocklist.
    FilteredBlack = 2,
    /// Filtered by safe browsing.
    SafeBrowsing = 3,
    /// Rewritten by safe search.
    SafeSearch = 4,
    /// Filtered by parental control.
    Parental = 5,
}

impl StatsResult {
    /// Maps a filtering reason onto its statistics bucket.
    pub const fn from_reason(r: Reason) -> Self {
        match r {
            Reason::FilteredBlockList
            | Reason::FilteredBlockedService
            | Reason::FilteredInvalid => StatsResult::FilteredBlack,
            Reason::FilteredSafeBrowsing => StatsResult::SafeBrowsing,
            Reason::FilteredSafeSearch => StatsResult::SafeSearch,
            Reason::FilteredParental => StatsResult::Parental,
            _ => StatsResult::NotFiltered,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_names_match_upstream() {
        // These strings are what the HTTP API emits; renaming them breaks the UI.
        assert_eq!(Reason::NotFilteredAllowList.as_str(), "NotFilteredWhiteList");
        assert_eq!(Reason::FilteredBlockList.as_str(), "FilteredBlackList");
        assert_eq!(Reason::Rewritten.as_str(), "Rewrite");
        assert_eq!(Reason::RewrittenAutoHosts.as_str(), "RewriteEtcHosts");
        assert_eq!(Reason::RewrittenRule.as_str(), "RewriteRule");
    }

    #[test]
    fn discriminants_are_stable() {
        for (i, r) in Reason::ALL.into_iter().enumerate() {
            assert_eq!(r as usize, i);
            assert_eq!(Reason::from_u8(i as u8), Some(r));
        }
    }

    #[test]
    fn name_lookup_round_trips() {
        for r in Reason::ALL {
            assert_eq!(Reason::from_name(r.as_str()), Some(r));
        }
    }

    #[test]
    fn blocking_classification() {
        assert!(Reason::FilteredBlockList.is_filtered());
        assert!(Reason::FilteredBlockedService.is_filtered());
        assert!(!Reason::NotFilteredNotFound.is_filtered());
        assert!(!Reason::RewrittenRule.is_filtered());
        assert!(!Reason::NotFilteredNotFound.matched());
        assert!(Reason::NotFilteredAllowList.matched());
    }
}
