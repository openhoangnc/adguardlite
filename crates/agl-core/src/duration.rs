//! Go-compatible duration parsing and formatting.
//!
//! AdGuard Home serialises durations with `golibs/timeutil.Duration`, which
//! extends Go's `time.ParseDuration` with a day unit.  Examples seen in a real
//! config: `30d`, `90d`, `1d`, `12h`, `10s`, `1s`, `30s`.

use std::fmt;
use std::time::Duration as StdDuration;

/// Nanoseconds in one day, matching `timeutil.Day`.
const NANOS_PER_DAY: i128 = 24 * 60 * 60 * 1_000_000_000;

/// A duration that round-trips through AdGuard Home's YAML/JSON representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
pub struct GoDuration(pub i128);

impl GoDuration {
    /// Builds a duration from whole seconds.
    pub const fn from_secs(s: i64) -> Self {
        Self(s as i128 * 1_000_000_000)
    }

    /// Builds a duration from whole days.
    pub const fn from_days(d: i64) -> Self {
        Self(d as i128 * NANOS_PER_DAY)
    }

    /// Builds a duration from whole hours.
    pub const fn from_hours(h: i64) -> Self {
        Self(h as i128 * 3_600_000_000_000)
    }

    /// Builds a duration from whole milliseconds.
    pub const fn from_millis(ms: i64) -> Self {
        Self(ms as i128 * 1_000_000)
    }

    /// Returns the duration truncated to whole seconds.
    pub const fn as_secs(self) -> i64 {
        (self.0 / 1_000_000_000) as i64
    }

    /// Returns the duration truncated to whole milliseconds.
    pub const fn as_millis(self) -> i64 {
        (self.0 / 1_000_000) as i64
    }

    /// Returns the duration truncated to whole minutes.
    pub const fn as_mins(self) -> i64 {
        (self.0 / 60_000_000_000) as i64
    }

    /// Returns the duration truncated to whole hours.
    pub const fn as_hours(self) -> i64 {
        (self.0 / 3_600_000_000_000) as i64
    }

    /// Returns the duration truncated to whole days.
    pub const fn as_days(self) -> i64 {
        (self.0 / NANOS_PER_DAY) as i64
    }

    /// Converts to a [`StdDuration`], clamping negatives to zero.
    pub fn to_std(self) -> StdDuration {
        if self.0 <= 0 {
            StdDuration::ZERO
        } else {
            StdDuration::from_nanos(self.0.min(u64::MAX as i128) as u64)
        }
    }

    /// Parses a Go duration string such as `1h30m`, `30d` or `1.5s`.
    pub fn parse(s: &str) -> Result<Self, DurationParseError> {
        parse_go_duration(s).map(GoDuration)
    }
}

impl From<StdDuration> for GoDuration {
    fn from(d: StdDuration) -> Self {
        Self(d.as_nanos() as i128)
    }
}

/// Failure to parse a Go duration literal.
#[derive(Debug, thiserror::Error)]
#[error("invalid duration {0:?}")]
pub struct DurationParseError(pub String);

fn parse_go_duration(orig: &str) -> Result<i128, DurationParseError> {
    let err = || DurationParseError(orig.to_string());
    let mut s = orig;
    let mut neg = false;

    if let Some(rest) = s.strip_prefix('-') {
        neg = true;
        s = rest;
    } else if let Some(rest) = s.strip_prefix('+') {
        s = rest;
    }

    // Go accepts a bare "0" with no unit.
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(err());
    }

    let mut total: i128 = 0;
    let bytes = s.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Mantissa: integer part, optional fraction.
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        let int_part = &s[start..i];

        let mut frac_part = "";
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            let fstart = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            frac_part = &s[fstart..i];
        }

        if int_part.is_empty() && frac_part.is_empty() {
            return Err(err());
        }

        // Unit: the run of non-digit, non-dot characters that follows.
        let ustart = i;
        while i < bytes.len() && !bytes[i].is_ascii_digit() && bytes[i] != b'.' {
            i += 1;
        }
        let unit = &s[ustart..i];
        if unit.is_empty() {
            return Err(err());
        }

        let unit_nanos: i128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            "d" => NANOS_PER_DAY,
            _ => return Err(err()),
        };

        let whole: i128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse::<i128>().map_err(|_| err())?
        };
        let mut nanos = whole
            .checked_mul(unit_nanos)
            .ok_or_else(err)?;

        if !frac_part.is_empty() {
            // Scale the fraction without floating point to stay exact.
            let mut scale: i128 = 1;
            let mut frac: i128 = 0;
            for b in frac_part.bytes() {
                if scale > 1_000_000_000_000_000_000 {
                    break;
                }
                frac = frac * 10 + i128::from(b - b'0');
                scale *= 10;
            }
            nanos += frac * unit_nanos / scale;
        }

        total = total.checked_add(nanos).ok_or_else(err)?;
    }

    Ok(if neg { -total } else { total })
}

impl fmt::Display for GoDuration {
    /// Formats the way `timeutil.Duration` does: whole days/hours/minutes/
    /// seconds collapse to a single unit, anything else falls back to Go's
    /// `time.Duration` string form.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        if n == 0 {
            return f.write_str("0s");
        }

        let neg = n < 0;
        let a = n.abs();
        if neg {
            f.write_str("-")?;
        }

        if a % NANOS_PER_DAY == 0 {
            return write!(f, "{}d", a / NANOS_PER_DAY);
        }
        if a % 3_600_000_000_000 == 0 {
            return write!(f, "{}h", a / 3_600_000_000_000);
        }
        if a % 60_000_000_000 == 0 {
            return write!(f, "{}m", a / 60_000_000_000);
        }
        if a % 1_000_000_000 == 0 {
            return write!(f, "{}s", a / 1_000_000_000);
        }

        f.write_str(&go_duration_string(a))
    }
}

impl fmt::Debug for GoDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Renders a positive nanosecond count the way Go's `time.Duration.String`
/// does, e.g. `1h2m3.5s`, `1.5ms`, `100ns`.
fn go_duration_string(a: i128) -> String {
    if a < 1_000 {
        return format!("{a}ns");
    }
    if a < 1_000_000 {
        return format!("{}us", trim_frac(a as f64 / 1_000.0));
    }
    if a < 1_000_000_000 {
        return format!("{}ms", trim_frac(a as f64 / 1_000_000.0));
    }

    let mut out = String::new();
    let hours = a / 3_600_000_000_000;
    let rem = a % 3_600_000_000_000;
    let mins = rem / 60_000_000_000;
    let rem2 = rem % 60_000_000_000;
    let secs = rem2 as f64 / 1_000_000_000.0;

    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || mins > 0 {
        out.push_str(&format!("{mins}m"));
    }
    out.push_str(&format!("{}s", trim_frac(secs)));

    out
}

/// Formats a float without trailing zeros, as Go does.
fn trim_frac(v: f64) -> String {
    let mut s = format!("{v:.9}");
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }

    s
}

impl serde::Serialize for GoDuration {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for GoDuration {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = GoDuration;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a duration string or a number of nanoseconds")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<GoDuration, E> {
                GoDuration::parse(s).map_err(serde::de::Error::custom)
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<GoDuration, E> {
                Ok(GoDuration(i128::from(v)))
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<GoDuration, E> {
                Ok(GoDuration(i128::from(v)))
            }
        }

        de.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units_seen_in_real_configs() {
        let cases = [
            ("30d", GoDuration::from_days(30)),
            ("90d", GoDuration::from_days(90)),
            ("1d", GoDuration::from_days(1)),
            ("12h", GoDuration::from_hours(12)),
            ("10s", GoDuration::from_secs(10)),
            ("1s", GoDuration::from_secs(1)),
            ("30s", GoDuration::from_secs(30)),
            ("0", GoDuration(0)),
        ];
        for (s, want) in cases {
            assert_eq!(GoDuration::parse(s).unwrap(), want, "parsing {s}");
        }
    }

    #[test]
    fn round_trips_config_literals() {
        for s in ["30d", "90d", "1d", "12h", "10s", "1s", "30s"] {
            assert_eq!(GoDuration::parse(s).unwrap().to_string(), s);
        }
    }

    #[test]
    fn parses_compound_and_fractional() {
        assert_eq!(
            GoDuration::parse("1h30m").unwrap(),
            GoDuration(3_600_000_000_000 + 1_800_000_000_000)
        );
        assert_eq!(GoDuration::parse("1.5s").unwrap(), GoDuration(1_500_000_000));
        assert_eq!(GoDuration::parse("-5m").unwrap(), GoDuration(-300_000_000_000));
        assert_eq!(GoDuration::parse("100ns").unwrap(), GoDuration(100));
    }

    #[test]
    fn rejects_garbage() {
        for s in ["", "abc", "10", "5x", "-"] {
            assert!(GoDuration::parse(s).is_err(), "should reject {s:?}");
        }
    }

    #[test]
    fn formats_mixed_durations_like_go() {
        assert_eq!(GoDuration(1_500_000_000).to_string(), "1.5s");
        assert_eq!(GoDuration(0).to_string(), "0s");
        assert_eq!(GoDuration::from_hours(36).to_string(), "36h");
    }
}
