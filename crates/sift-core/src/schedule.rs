//! The weekly schedule used by the blocked-services feature.
//!
//! The sense of the schedule is easy to get backwards: a day range says when
//! the block is **paused**, not when it applies.  Upstream applies the
//! blocked-services rules only when the current time is *outside* every range,
//! so an empty schedule blocks around the clock.

use jiff::Timestamp;
use jiff::tz::TimeZone;

/// One day's pause window, as an offset from midnight.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct DayRange {
    /// The start of the window, in milliseconds from midnight.
    pub start_ms: i64,
    /// The end of the window, in milliseconds from midnight.
    pub end_ms: i64,
}

impl DayRange {
    /// A whole day.
    pub const FULL: DayRange = DayRange {
        start_ms: 0,
        end_ms: MAX_DAY_MS,
    };

    /// Reports whether an offset from midnight falls in the window.
    ///
    /// The interval is half-open, as upstream's is: `start <= offset < end`.
    /// A zero range therefore contains nothing.
    pub const fn contains(self, offset_ms: i64) -> bool {
        self.start_ms <= offset_ms && offset_ms < self.end_ms
    }

    /// Reports whether the range is usable.
    ///
    /// Upstream refuses a configuration where the start is not before the end
    /// or either bound leaves the day.
    pub const fn is_valid(self) -> bool {
        if self.start_ms == 0 && self.end_ms == 0 {
            return true;
        }

        self.start_ms >= 0
            && self.end_ms > self.start_ms
            && self.start_ms < MAX_DAY_MS
            && self.end_ms <= MAX_DAY_MS
    }
}

/// The number of milliseconds in a day, the largest a range's end may be.
pub const MAX_DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// A pause window for each day of the week.
#[derive(Clone, Debug, Default)]
pub struct Weekly {
    /// The IANA time zone name, or `Local` for the system's.
    pub time_zone: String,
    /// The windows, indexed Monday to Sunday.
    pub days: [Option<DayRange>; 7],
}

impl Weekly {
    /// Builds a schedule from a time zone and Monday-to-Sunday windows.
    pub fn new(time_zone: impl Into<String>, days: [Option<DayRange>; 7]) -> Self {
        Self {
            time_zone: time_zone.into(),
            days,
        }
    }

    /// Reports whether any day has a window at all.
    pub fn is_empty(&self) -> bool {
        self.days.iter().all(Option::is_none)
    }

    /// Resolves the configured time zone, falling back to the system's.
    ///
    /// `Local` is upstream's spelling for the host's zone, and an unknown name
    /// falls back rather than failing: a bad zone should not stop the server.
    fn zone(&self) -> TimeZone {
        match self.time_zone.as_str() {
            "" | "Local" => TimeZone::system(),
            "UTC" => TimeZone::UTC,
            name => TimeZone::get(name).unwrap_or_else(|_| TimeZone::system()),
        }
    }

    /// Reports whether `t` falls inside the day's window.
    pub fn contains(&self, t: Timestamp) -> bool {
        let zoned = t.to_zoned(self.zone());

        // jiff numbers Monday as 1 through Sunday as 7.
        let index = usize::from(zoned.weekday().to_monday_one_offset() as u8) - 1;
        let Some(range) = self.days.get(index).copied().flatten() else {
            return false;
        };

        let time = zoned.time();
        let offset_ms = i64::from(time.hour()) * 3_600_000
            + i64::from(time.minute()) * 60_000
            + i64::from(time.second()) * 1_000
            + i64::from(time.millisecond());

        range.contains(offset_ms)
    }

    /// Reports whether the blocked-services rules apply at `t`.
    ///
    /// This is the inverse of [`Weekly::contains`], and it is the question
    /// callers actually have.
    pub fn blocks_at(&self, t: Timestamp) -> bool {
        !self.contains(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Monday 2024-01-01 at 10:30 UTC.
    fn monday_1030() -> Timestamp {
        "2024-01-01T10:30:00Z".parse().unwrap()
    }

    /// Sunday 2024-01-07 at 10:30 UTC.
    fn sunday_1030() -> Timestamp {
        "2024-01-07T10:30:00Z".parse().unwrap()
    }

    fn hours(h: i64) -> i64 {
        h * 3_600_000
    }

    #[test]
    fn an_empty_schedule_never_pauses_the_block() {
        let w = Weekly::default();
        assert!(w.is_empty());
        assert!(!w.contains(monday_1030()));
        assert!(
            w.blocks_at(monday_1030()),
            "with no pause window the services stay blocked"
        );
    }

    #[test]
    fn a_window_pauses_the_block_within_its_hours() {
        let mut days = [None; 7];
        days[0] = Some(DayRange {
            start_ms: hours(9),
            end_ms: hours(17),
        });
        let w = Weekly::new("UTC", days);

        assert!(w.contains(monday_1030()));
        assert!(!w.blocks_at(monday_1030()), "inside the window, no block");
    }

    #[test]
    fn a_window_only_applies_to_its_own_day() {
        let mut days = [None; 7];
        days[0] = Some(DayRange {
            start_ms: hours(9),
            end_ms: hours(17),
        });
        let w = Weekly::new("UTC", days);

        assert!(!w.contains(sunday_1030()));
        assert!(w.blocks_at(sunday_1030()));
    }

    #[test]
    fn sunday_is_the_last_index() {
        let mut days = [None; 7];
        days[6] = Some(DayRange::FULL);
        let w = Weekly::new("UTC", days);

        assert!(w.contains(sunday_1030()));
        assert!(!w.contains(monday_1030()));
    }

    #[test]
    fn the_interval_is_half_open() {
        let r = DayRange {
            start_ms: hours(9),
            end_ms: hours(17),
        };
        assert!(r.contains(hours(9)));
        assert!(!r.contains(hours(17)));
        assert!(!r.contains(hours(8) + 3_599_999));
    }

    #[test]
    fn a_zero_range_contains_nothing() {
        assert!(!DayRange::default().contains(0));
    }

    #[test]
    fn the_time_zone_shifts_the_window() {
        // 10:30 UTC is 11:30 in Berlin in January, so a window that ends at
        // 11:00 has closed there while it is still open in UTC.
        let mut days = [None; 7];
        days[0] = Some(DayRange {
            start_ms: hours(9),
            end_ms: hours(11),
        });

        assert!(Weekly::new("UTC", days).contains(monday_1030()));
        assert!(!Weekly::new("Europe/Berlin", days).contains(monday_1030()));
    }

    #[test]
    fn an_unknown_time_zone_does_not_break_the_schedule() {
        let mut days = [None; 7];
        days[0] = Some(DayRange::FULL);
        let w = Weekly::new("Not/AZone", days);

        // Whatever the fallback zone is, the full-day window still matches
        // some day rather than panicking.
        let _ = w.contains(monday_1030());
    }

    #[test]
    fn ranges_are_validated_the_way_upstream_does() {
        assert!(DayRange::default().is_valid());
        assert!(DayRange::FULL.is_valid());
        assert!(
            !DayRange {
                start_ms: hours(17),
                end_ms: hours(9)
            }
            .is_valid()
        );
        assert!(
            !DayRange {
                start_ms: 0,
                end_ms: MAX_DAY_MS + 1
            }
            .is_valid()
        );
        assert!(
            !DayRange {
                start_ms: -1,
                end_ms: hours(1)
            }
            .is_valid()
        );
    }
}
