//! Time formatting compatible with Go's `encoding/json` output.
//!
//! Go marshals `time.Time` as RFC 3339 with nanosecond precision, trailing
//! zeros trimmed, and the location's offset (`Z` for UTC).  AdGuard Home's API
//! emits local times, e.g. `2026-09-14T16:44:24+07:00`.

use jiff::{Timestamp, Zoned, tz::TimeZone};

/// Formats a timestamp in the local zone the way Go's JSON encoder does.
pub fn format_local(ts: Timestamp) -> String {
    format_zoned(&ts.to_zoned(TimeZone::system()))
}

/// Formats a timestamp in UTC the way Go's JSON encoder does.
pub fn format_utc(ts: Timestamp) -> String {
    format_zoned(&ts.to_zoned(TimeZone::UTC))
}

/// Formats a zoned datetime as RFC 3339 with Go's trailing-zero trimming.
pub fn format_zoned(z: &Zoned) -> String {
    let d = z.datetime();
    let (y, mo, dy) = (d.year(), d.month(), d.day());
    let (h, mi, s) = (d.hour(), d.minute(), d.second());
    let nanos = d.subsec_nanosecond();

    let mut out = format!("{y:04}-{mo:02}-{dy:02}T{h:02}:{mi:02}:{s:02}");
    push_frac(&mut out, nanos);

    // Go's `Z07:00` prints `Z` whenever the *offset* is zero, whatever the
    // zone is called: `Etc/UTC` and a wintertime `Europe/London` both render
    // `Z`.  Comparing against `TimeZone::UTC` instead would emit `+00:00` in
    // the Docker image, where the zone resolves by name rather than
    // identity — and that goes into `querylog.json`, which has to match.
    let off = z.offset().seconds();
    if off == 0 {
        out.push('Z');
    } else {
        let sign = if off < 0 { '-' } else { '+' };
        let a = off.abs();
        out.push_str(&format!("{sign}{:02}:{:02}", a / 3600, (a % 3600) / 60));
    }

    out
}

/// Appends a fractional-second part, trimming trailing zeros as Go does.
fn push_frac(out: &mut String, nanos: i32) {
    if nanos == 0 {
        return;
    }

    let mut frac = format!("{nanos:09}");
    while frac.ends_with('0') {
        frac.pop();
    }
    out.push('.');
    out.push_str(&frac);
}

/// The zero `time.Time`, which Go renders as `0001-01-01T00:00:00Z`.
pub const GO_ZERO_TIME: &str = "0001-01-01T00:00:00Z";

/// Returns the current time as milliseconds since the Unix epoch, with the
/// fractional part Go's `float64` millisecond fields carry.
pub fn unix_millis_f64(ts: Timestamp) -> f64 {
    ts.as_nanosecond() as f64 / 1_000_000.0
}

/// Parses an RFC 3339 timestamp, accepting the formats Go emits.
pub fn parse_rfc3339(s: &str) -> Option<Timestamp> {
    s.parse::<Timestamp>()
        .ok()
        .or_else(|| s.parse::<Zoned>().ok().map(|z| z.timestamp()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_like_go() {
        let ts: Timestamp = "2026-09-14T09:44:24Z".parse().unwrap();
        assert_eq!(format_utc(ts), "2026-09-14T09:44:24Z");
    }

    #[test]
    fn trims_fractional_zeros_like_go() {
        let ts: Timestamp = "2026-09-14T09:44:24.500000000Z".parse().unwrap();
        assert_eq!(format_utc(ts), "2026-09-14T09:44:24.5Z");

        let ts: Timestamp = "2026-09-14T09:44:24.123456789Z".parse().unwrap();
        assert_eq!(format_utc(ts), "2026-09-14T09:44:24.123456789Z");
    }

    #[test]
    fn round_trips_through_parse() {
        let ts: Timestamp = "2026-09-14T09:44:24.25Z".parse().unwrap();
        let s = format_utc(ts);
        assert_eq!(parse_rfc3339(&s), Some(ts));
    }

    #[test]
    fn a_zero_offset_renders_z_whatever_the_zone_is_called() {
        // Go's `Z07:00` keys off the offset, not the zone's identity.  The
        // Docker image resolves its zone by name, so comparing against
        // `TimeZone::UTC` wrote `+00:00` into `querylog.json` where Go writes
        // `Z`.  Checked against the Go toolchain:
        //   Etc/UTC        -> "2026-09-14T17:15:46.802463441Z"
        //   Europe/London  -> "2026-01-14T12:00:00Z"  (winter, offset 0)
        let ts: Timestamp = "2026-09-14T17:15:46.802463441Z".parse().unwrap();
        for zone in ["UTC", "Etc/UTC"] {
            let z = ts.to_zoned(TimeZone::get(zone).unwrap());
            assert_eq!(
                format_zoned(&z),
                "2026-09-14T17:15:46.802463441Z",
                "zone {zone}"
            );
        }

        let winter: Timestamp = "2026-01-14T12:00:00Z".parse().unwrap();
        let london = winter.to_zoned(TimeZone::get("Europe/London").unwrap());
        assert_eq!(format_zoned(&london), "2026-01-14T12:00:00Z");

        // A non-zero offset still carries one, as Go renders it.
        let summer = ts.to_zoned(TimeZone::get("Europe/London").unwrap());
        assert_eq!(format_zoned(&summer), "2026-09-14T18:15:46.802463441+01:00");
    }

    #[test]
    fn parses_offset_form_go_emits() {
        // This is the exact shape seen in /control/filtering/status.
        let ts = parse_rfc3339("2026-09-14T16:44:24+07:00").unwrap();
        assert_eq!(format_utc(ts), "2026-09-14T09:44:24Z");
    }
}
