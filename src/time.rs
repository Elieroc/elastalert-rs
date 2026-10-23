//! Time handling. Everything internal is UTC microseconds since the epoch (`Ts`),
//! durations are microseconds too (`Dur`). Formatting follows ElastAlert's output.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use serde_json::Value;
use std::sync::OnceLock;

pub type Ts = i64;
pub type Dur = i64;

pub const SECOND: Dur = 1_000_000;
pub const MINUTE: Dur = 60 * SECOND;

pub fn now() -> Ts {
    Utc::now().timestamp_micros()
}

/// `{days: 1, hours: 2}` style map -> duration. Same units as Python's timedelta kwargs.
pub fn parse_duration_map(v: &Value) -> Result<Dur> {
    let map = v.as_object().context("time value must be a map like {minutes: 5}")?;
    let mut total = 0f64;
    for (unit, n) in map {
        let n = n.as_f64().with_context(|| format!("time unit {unit} must be a number"))?;
        let mult = match unit.as_str() {
            "weeks" => 7.0 * 86_400e6,
            "days" => 86_400e6,
            "hours" => 3_600e6,
            "minutes" => 60e6,
            "seconds" => 1e6,
            "milliseconds" => 1e3,
            "microseconds" => 1.0,
            _ => bail!("unknown time unit {unit}"),
        };
        total += n * mult;
    }
    Ok(total.round() as Dur)
}

/// `hours=2` (CLI `--silence`, `--patience`).
pub fn parse_duration_arg(s: &str) -> Result<Dur> {
    let (unit, n) = s.split_once('=').context("expected <unit>=<number>, e.g. hours=2")?;
    let n: f64 = n.trim().parse().context("duration number")?;
    parse_duration_map(&serde_json::json!({ unit.trim(): n }))
}

/// Lenient ISO8601 parse. Naive timestamps are taken as UTC.
pub fn parse_iso(s: &str) -> Option<Ts> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp_micros());
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f%z", "%Y-%m-%d %H:%M:%S%.f%z"] {
        if let Ok(dt) = DateTime::parse_from_str(s, f) {
            return Some(dt.timestamp_micros());
        }
    }
    for f in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, f) {
            return Some(dt.and_utc().timestamp_micros());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .map(|d| d.and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp_micros())
}

fn utc(ts: Ts) -> DateTime<Utc> {
    Utc.timestamp_micros(ts).single().unwrap_or_default()
}

/// ElastAlert's `dt_to_ts`: ISO with `Z`, no fraction when whole seconds,
/// milliseconds when the micros are a multiple of 1000, else micros.
pub fn to_iso(ts: Ts) -> String {
    let dt = utc(ts);
    let us = ts.rem_euclid(SECOND);
    if us == 0 {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else if us % 1000 == 0 {
        format!("{}.{:03}Z", dt.format("%Y-%m-%dT%H:%M:%S"), us / 1000)
    } else {
        format!("{}.{:06}Z", dt.format("%Y-%m-%dT%H:%M:%S"), us)
    }
}

/// ISO text with the offset of `tz` (Python `isoformat()` of an aware datetime): fraction only when non-zero.
pub fn to_iso_in(ts: Ts, tz: &chrono_tz::Tz) -> String {
    let dt = utc(ts).with_timezone(tz);
    let us = ts.rem_euclid(SECOND);
    let base = dt.format("%Y-%m-%dT%H:%M:%S").to_string();
    let off = dt.format("%:z").to_string();
    if us == 0 { format!("{base}{off}") } else { format!("{base}.{us:06}{off}") }
}

fn local_tz() -> chrono_tz::Tz {
    static TZ: OnceLock<chrono_tz::Tz> = OnceLock::new();
    *TZ.get_or_init(|| {
        std::env::var("TZ")
            .ok()
            .or_else(|| iana_time_zone::get_timezone().ok())
            .and_then(|n| n.trim_start_matches(':').parse().ok())
            .unwrap_or(chrono_tz::UTC)
    })
}

/// ElastAlert's `pretty_ts`: `YYYY-MM-DD HH:MM TZ`, local time unless `local` is false.
pub fn pretty(ts: Ts, local: bool, fmt: Option<&str>) -> String {
    let fmt = fmt.unwrap_or("%Y-%m-%d %H:%M %Z");
    if local {
        utc(ts).with_timezone(&local_tz()).format(fmt).to_string()
    } else {
        utc(ts).format(fmt).to_string()
    }
}

/// Python `str(timedelta)`: `0:15:00`, `1 day, 2:00:00`.
pub fn pretty_duration(d: Dur) -> String {
    let secs = d.div_euclid(SECOND);
    let us = d.rem_euclid(SECOND);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let mut s = String::new();
    if days != 0 {
        s = format!("{days} day{}, ", if days.abs() != 1 { "s" } else { "" });
    }
    s += &format!("{}:{:02}:{:02}", rem / 3600, rem % 3600 / 60, rem % 60);
    if us != 0 {
        s += &format!(".{us:06}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_roundtrip_matches_python_format() {
        let t = parse_iso("2024-03-01T10:00:00Z").unwrap();
        assert_eq!(to_iso(t), "2024-03-01T10:00:00Z");
        assert_eq!(to_iso(t + 120_000), "2024-03-01T10:00:00.120Z");
        assert_eq!(to_iso(t + 123_456), "2024-03-01T10:00:00.123456Z");
        assert_eq!(parse_iso("2024-03-01T12:00:00+02:00"), Some(t));
        assert_eq!(parse_iso("2024-03-01 10:00:00"), Some(t));
        assert_eq!(parse_iso("2024-03-01T10:00:00.000+0000"), Some(t));
    }

    #[test]
    fn durations() {
        assert_eq!(pretty_duration(15 * MINUTE), "0:15:00");
        assert_eq!(pretty_duration(26 * 60 * MINUTE), "1 day, 2:00:00");
        assert_eq!(parse_duration_map(&serde_json::json!({"minutes": 15})).unwrap(), 15 * MINUTE);
        assert_eq!(parse_duration_arg("hours=2").unwrap(), 120 * MINUTE);
    }
}
