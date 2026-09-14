//! Go `c2h5oh/datasize.ByteSize`-compatible size parsing and formatting.
//!
//! Note the unit names are decimal-looking but the multipliers are binary:
//! `KB = 1 << 10`, `MB = 1 << 20`, and so on.  A real config contains
//! `max_http_size: 256MB`, meaning 268435456 bytes.

use std::fmt;

const KB: u64 = 1 << 10;
const MB: u64 = 1 << 20;
const GB: u64 = 1 << 30;
const TB: u64 = 1 << 40;
const PB: u64 = 1 << 50;
const EB: u64 = 1 << 60;

/// A byte count that round-trips through AdGuard Home's YAML representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct ByteSize(pub u64);

impl ByteSize {
    /// Builds a size from a count of mebibytes.
    pub const fn from_mb(mb: u64) -> Self {
        Self(mb * MB)
    }

    /// Returns the raw byte count.
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Parses a size literal such as `256MB`, `1K`, `10 kB` or `512`.
    pub fn parse(s: &str) -> Result<Self, ByteSizeParseError> {
        let err = || ByteSizeParseError(s.to_string());
        let t = s.trim();
        if t.is_empty() {
            return Err(err());
        }

        let split = t
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(t.len());
        let (num, unit) = t.split_at(split);
        if num.is_empty() {
            return Err(err());
        }

        let n: u64 = num.parse().map_err(|_| err())?;
        let mult = match unit.trim().to_ascii_uppercase().as_str() {
            "" | "B" => 1,
            "K" | "KB" => KB,
            "M" | "MB" => MB,
            "G" | "GB" => GB,
            "T" | "TB" => TB,
            "P" | "PB" => PB,
            "E" | "EB" => EB,
            _ => return Err(err()),
        };

        n.checked_mul(mult).map(ByteSize).ok_or_else(err)
    }
}

/// Failure to parse a byte-size literal.
#[derive(Debug, thiserror::Error)]
#[error("invalid byte size {0:?}")]
pub struct ByteSizeParseError(pub String);

impl fmt::Display for ByteSize {
    /// Formats using the largest unit that divides the value exactly, matching
    /// `datasize.ByteSize.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = self.0;
        for (mult, suffix) in [
            (EB, "EB"),
            (PB, "PB"),
            (TB, "TB"),
            (GB, "GB"),
            (MB, "MB"),
            (KB, "KB"),
        ] {
            if v >= mult && v % mult == 0 {
                return write!(f, "{}{}", v / mult, suffix);
            }
        }

        write!(f, "{v}B")
    }
}

impl fmt::Debug for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl serde::Serialize for ByteSize {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for ByteSize {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = ByteSize;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte-size string or an integer")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<ByteSize, E> {
                ByteSize::parse(s).map_err(serde::de::Error::custom)
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<ByteSize, E> {
                Ok(ByteSize(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<ByteSize, E> {
                Ok(ByteSize(v.max(0) as u64))
            }
        }

        de.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_real_config_value() {
        assert_eq!(ByteSize::parse("256MB").unwrap().bytes(), 256 * 1024 * 1024);
    }

    #[test]
    fn round_trips() {
        for s in ["256MB", "1KB", "2GB", "512B"] {
            assert_eq!(ByteSize::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn matches_go_formatting_of_uneven_values() {
        // From datasize's own test table.
        assert_eq!(ByteSize(MB + 20 * KB).to_string(), "1044KB");
        assert_eq!(ByteSize(1025).to_string(), "1025B");
        assert_eq!(ByteSize(2048 * MB).to_string(), "2GB");
    }

    #[test]
    fn accepts_loose_spellings() {
        assert_eq!(ByteSize::parse("1K").unwrap().bytes(), 1024);
        assert_eq!(ByteSize::parse("10 kB ").unwrap().bytes(), 10 * 1024);
        assert_eq!(ByteSize::parse("512").unwrap().bytes(), 512);
    }

    #[test]
    fn rejects_garbage() {
        for s in ["", "MB", "12XB"] {
            assert!(ByteSize::parse(s).is_err(), "should reject {s:?}");
        }
    }
}
