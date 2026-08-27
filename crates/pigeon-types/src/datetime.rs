//! RFC 5322 date formatting.
//!
//! Written out rather than pulling in a date library, because exactly one
//! format is needed and the conversion is a known closed-form algorithm. It is
//! also the kind of code that is easy to get subtly wrong and easy to test
//! exhaustively, which is a good trade.

/// Format a Unix timestamp as an RFC 5322 date.
///
/// Always UTC. Local time in a mail header is a source of confusion and offers
/// nothing in return — the timestamp is for correlating logs across machines
/// that will not share a timezone.
///
/// ```text
/// Thu, 27 Aug 2026 03:46:45 +0000
/// ```
pub fn rfc5322_date(unix_seconds: i64) -> String {
    const DAY: i64 = 86_400;

    // Floor division, so timestamps before 1970 do not round toward zero and
    // land a day out.
    let days = unix_seconds.div_euclid(DAY);
    let secs = unix_seconds.rem_euclid(DAY);

    let (year, month, day) = civil_from_days(days);

    // 1970-01-01 was a Thursday, so shifting by 4 puts Sunday at zero.
    let weekday = (days + 4).rem_euclid(7) as usize;

    const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[weekday],
        day,
        MONTHS[(month - 1) as usize],
        year,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
    )
}

/// Convert days since the Unix epoch into a civil date.
///
/// Howard Hinnant's `civil_from_days`, which is exact for the whole range and
/// avoids the loop-over-years approach that gets leap centuries wrong.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // day of era, [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March-based
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]

    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn formats_known_timestamps() {
        // Both of these are widely cited, so a mistake here is easy to spot.
        assert_eq!(
            rfc5322_date(1_000_000_000),
            "Sun, 09 Sep 2001 01:46:40 +0000"
        );
        assert_eq!(
            rfc5322_date(1_234_567_890),
            "Fri, 13 Feb 2009 23:31:30 +0000"
        );
    }

    #[test]
    fn handles_leap_days() {
        // 2000 is a leap year; 1900 was not. The century rule is where
        // hand-rolled date maths usually breaks.
        assert_eq!(rfc5322_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 +0000");
        assert_eq!(
            rfc5322_date(1_709_164_800),
            "Thu, 29 Feb 2024 00:00:00 +0000"
        );
    }

    #[test]
    fn handles_year_boundaries() {
        assert_eq!(
            rfc5322_date(1_735_689_599),
            "Tue, 31 Dec 2024 23:59:59 +0000"
        );
        assert_eq!(
            rfc5322_date(1_735_689_600),
            "Wed, 01 Jan 2025 00:00:00 +0000"
        );
    }

    #[test]
    fn handles_times_before_the_epoch() {
        // Floor division, not truncation: rounding toward zero here lands a
        // day out for every negative timestamp.
        assert_eq!(rfc5322_date(-1), "Wed, 31 Dec 1969 23:59:59 +0000");
    }

    #[test]
    fn weekdays_advance_correctly() {
        const DAY: i64 = 86_400;
        let names: Vec<String> = (0..7)
            .map(|i| rfc5322_date(i * DAY)[..3].to_string())
            .collect();
        assert_eq!(names, ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"]);
    }

    #[test]
    fn every_day_for_a_decade_round_trips_to_a_valid_date() {
        // Cheap exhaustive check that nothing produces a month of 13 or a day
        // of 0 across a range that includes several leap years.
        const DAY: i64 = 86_400;
        for d in 0..3_653 {
            let s = rfc5322_date(1_577_836_800 + d * DAY); // from 2020-01-01
            let parts: Vec<&str> = s.split(' ').collect();
            assert_eq!(parts.len(), 6, "malformed: {s}");
            let day: u32 = parts[1].parse().expect("day");
            assert!((1..=31).contains(&day), "bad day in {s}");
        }
    }
}
