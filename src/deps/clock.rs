//! "N days ago" and "N hours ago": the one place the release-age window is computed.

use anyhow::{Context, Result};
use jiff::{SignedDuration, Timestamp};

/// The newest publish time that is still old enough: now minus `days`. Fails for a
/// window beyond the representable calendar, which callers must treat as unmet
/// (never as "no limit").
pub(super) fn cutoff(days: u32) -> Result<Timestamp> {
    Timestamp::now()
        .checked_sub(SignedDuration::from_hours(i64::from(days) * 24))
        .with_context(|| format!("a release age of {days} days is out of range"))
}

pub(super) fn ago(d: SignedDuration) -> String {
    let hours = d.as_hours();
    if hours < 48 {
        format!("{hours} hour(s)")
    } else {
        format!("{} days", hours / 24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_and_durations() {
        let day = SignedDuration::from_hours(24);
        assert_eq!(ago(day), "24 hour(s)");
        assert_eq!(ago(day * 3), "3 days");
        let cutoff = cutoff(14).unwrap();
        let age = Timestamp::now().duration_since(cutoff);
        assert!((age.as_hours() - 14 * 24).abs() <= 1);
        assert!(super::cutoff(u32::MAX).is_err());
    }
}
