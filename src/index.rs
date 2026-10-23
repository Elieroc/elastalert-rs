//! Index name resolution for `use_strftime_index` (daily / hourly indices).

use crate::time::Ts;
use anyhow::{Result, bail};
use chrono::format::{Item, StrftimeItems};
use chrono::{DateTime, TimeZone, Utc};
use std::collections::BTreeSet;

const HOUR: i64 = 3_600_000_000;
const DAY: i64 = 24 * HOUR;

fn strftime(ts: Ts, pattern: &str) -> Result<String> {
    if StrftimeItems::new(pattern).any(|i| matches!(i, Item::Error)) {
        bail!("invalid strftime pattern in index: {pattern}");
    }
    let dt: DateTime<Utc> = Utc.timestamp_micros(ts).single().unwrap_or_default();
    Ok(dt.format(pattern).to_string())
}

/// Comma separated list of every index that can hold data between `start` and `end` (UTC).
/// Like upstream it also includes the step after `end`; `add_extra` adds the step before `start`.
pub fn format_index(index: &str, start: Ts, end: Ts, add_extra: bool) -> Result<String> {
    let step = if index.contains("%H") { HOUR } else { DAY };
    let end = end.div_euclid(step) * step;
    let mut start = if add_extra { start - step } else { start };
    let mut set = BTreeSet::new();
    set.insert(strftime(start, index)?);
    while start <= end {
        start += step;
        set.insert(strftime(start, index)?);
    }
    if add_extra && set.contains(index) {
        bail!("You cannot use a static index {index} with search_extra_index");
    }
    Ok(set.into_iter().collect::<Vec<_>>().join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::parse_iso;

    #[test]
    fn daily_and_hourly() {
        let s = parse_iso("2024-03-01T23:30:00Z").unwrap();
        let e = parse_iso("2024-03-02T00:10:00Z").unwrap();
        assert_eq!(format_index("logs-%Y.%m.%d", s, e, false).unwrap(), "logs-2024.03.01,logs-2024.03.02");
        assert_eq!(format_index("l-%Y%m%d%H", s, e, false).unwrap(), "l-2024030123,l-2024030200");
        assert!(format_index("static", s, e, true).is_err());
    }
}
