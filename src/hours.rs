//! `active_hours`: time windows outside of which a rule's matches are ignored (extension, not in upstream).

use crate::time::Ts;
use anyhow::{Result, bail};
use chrono::{Datelike, TimeZone, Timelike, Utc};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
struct Window {
    /// Bit 0 = Monday ... bit 6 = Sunday.
    days: u8,
    /// Minutes since midnight.
    from: u16,
    to: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ActiveHours {
    tz: chrono_tz::Tz,
    windows: Vec<Window>,
}

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

fn day_bit(v: &Value) -> Result<u8> {
    let name = v.as_str().map(str::to_ascii_lowercase).unwrap_or_default();
    match DAYS.iter().position(|d| name.starts_with(d)) {
        Some(i) => Ok(1 << i),
        None => bail!("active_hours: unknown day {v} (use mon, tue, wed, thu, fri, sat, sun)"),
    }
}

fn minutes(w: &serde_json::Map<String, Value>, key: &str) -> Result<u16> {
    let s = w.get(key).and_then(Value::as_str).ok_or_else(|| anyhow::anyhow!("active_hours: window needs a quoted \"{key}\" time like \"08:30\""))?;
    let (h, m) = s.split_once(':').ok_or_else(|| anyhow::anyhow!("active_hours: invalid {key} time {s:?} (expected HH:MM)"))?;
    match (h.parse::<u16>(), m.parse::<u16>()) {
        (Ok(h), Ok(m)) if h < 24 && m < 60 => Ok(h * 60 + m),
        _ => bail!("active_hours: invalid {key} time {s:?} (expected HH:MM)"),
    }
}

impl ActiveHours {
    pub fn parse(v: &Value) -> Result<Self> {
        let Some(obj) = v.as_object() else { bail!("active_hours must be a mapping with a `windows` list") };
        if let Some(k) = obj.keys().find(|k| !["timezone", "windows"].contains(&k.as_str())) {
            bail!("active_hours: unknown key {k:?}");
        }
        let tz = match obj.get("timezone") {
            None | Some(Value::Null) => chrono_tz::UTC,
            Some(Value::String(t)) => t.parse::<chrono_tz::Tz>().map_err(|_| anyhow::anyhow!("active_hours: unknown timezone {t:?}"))?,
            Some(_) => bail!("active_hours: timezone must be a string"),
        };
        let list = obj.get("windows").and_then(Value::as_array).filter(|l| !l.is_empty());
        let Some(list) = list else { bail!("active_hours: `windows` must be a non-empty list") };
        let mut windows = Vec::new();
        for w in list {
            let Some(w) = w.as_object() else { bail!("active_hours: each window must be a mapping with days, from, to") };
            if let Some(k) = w.keys().find(|k| !["days", "from", "to"].contains(&k.as_str())) {
                bail!("active_hours: unknown window key {k:?}");
            }
            let days = match w.get("days") {
                None | Some(Value::Null) => 0x7f,
                Some(Value::Array(l)) if !l.is_empty() => l.iter().try_fold(0u8, |acc, d| day_bit(d).map(|b| acc | b))?,
                Some(_) => bail!("active_hours: `days` must be a non-empty list"),
            };
            let (from, to) = (minutes(w, "from")?, minutes(w, "to")?);
            if from == to {
                bail!("active_hours: window from and to are both {:02}:{:02}", from / 60, from % 60);
            }
            windows.push(Window { days, from, to });
        }
        Ok(ActiveHours { tz, windows })
    }

    /// Whether the instant falls in one of the windows. `to` is exclusive; a window with `from > to` crosses midnight
    /// and belongs to the day it starts on.
    pub fn contains(&self, ts: Ts) -> bool {
        let Some(utc) = Utc.timestamp_micros(ts).single() else { return true };
        let local = utc.with_timezone(&self.tz);
        let minute = (local.hour() * 60 + local.minute()) as u16;
        let today = 1u8 << local.weekday().num_days_from_monday();
        let yesterday = 1u8 << ((local.weekday().num_days_from_monday() + 6) % 7);
        self.windows.iter().any(|w| {
            if w.from < w.to {
                w.days & today != 0 && (w.from..w.to).contains(&minute)
            } else {
                (w.days & today != 0 && minute >= w.from) || (w.days & yesterday != 0 && minute < w.to)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(s: &str) -> Ts {
        crate::time::parse_iso(s).unwrap()
    }

    fn hours(v: Value) -> ActiveHours {
        ActiveHours::parse(&v).unwrap()
    }

    #[test]
    fn office_hours_in_paris() {
        let h = hours(json!({"timezone": "Europe/Paris", "windows": [{"days": ["mon", "tue", "wed", "thu", "fri"], "from": "08:00", "to": "18:30"}]}));
        // Wed 2026-10-21, CEST (UTC+2): 08:00 local is 06:00Z.
        assert!(h.contains(at("2026-10-21T06:00:00Z")));
        assert!(!h.contains(at("2026-10-21T05:59:00Z")));
        assert!(h.contains(at("2026-10-21T16:29:00Z")));
        assert!(!h.contains(at("2026-10-21T16:30:00Z")));
        // Wed 2026-12-02, CET (UTC+1): the same local window moves by an hour in UTC.
        assert!(h.contains(at("2026-12-02T07:00:00Z")));
        assert!(!h.contains(at("2026-12-02T06:59:00Z")));
        // Saturday is out.
        assert!(!h.contains(at("2026-10-24T10:00:00Z")));
    }

    #[test]
    fn window_crossing_midnight_belongs_to_its_start_day() {
        let h = hours(json!({"windows": [{"days": ["sat"], "from": "22:00", "to": "06:00"}]}));
        assert!(h.contains(at("2026-10-24T22:00:00Z"))); // Saturday evening
        assert!(h.contains(at("2026-10-25T05:59:00Z"))); // Sunday morning, still the Saturday window
        assert!(!h.contains(at("2026-10-25T06:00:00Z")));
        assert!(!h.contains(at("2026-10-24T05:00:00Z"))); // Saturday morning belongs to Friday's window
        assert!(!h.contains(at("2026-10-25T22:00:00Z"))); // Sunday evening
    }

    #[test]
    fn days_default_to_every_day_and_windows_are_ored() {
        let h = hours(json!({"windows": [{"from": "00:00", "to": "01:00"}, {"days": ["Sun"], "from": "12:00", "to": "13:00"}]}));
        assert!(h.contains(at("2026-10-22T00:30:00Z")));
        assert!(h.contains(at("2026-10-25T12:30:00Z")));
        assert!(!h.contains(at("2026-10-22T12:30:00Z")));
    }

    #[test]
    fn invalid_definitions_are_rejected() {
        for bad in [
            json!("nope"),
            json!({"windows": []}),
            json!({}),
            json!({"timezone": "Mars/Base", "windows": [{"from": "08:00", "to": "09:00"}]}),
            json!({"windows": [{"days": ["funday"], "from": "08:00", "to": "09:00"}]}),
            json!({"windows": [{"from": "8h", "to": "09:00"}]}),
            json!({"windows": [{"from": "24:00", "to": "09:00"}]}),
            json!({"windows": [{"from": "08:00", "to": "08:00"}]}),
            json!({"windows": [{"from": "08:00"}]}),
            json!({"windows": [{"from": "08:00", "to": "09:00", "extra": 1}]}),
            json!({"zone": "UTC", "windows": [{"from": "08:00", "to": "09:00"}]}),
        ] {
            assert!(ActiveHours::parse(&bad).is_err(), "{bad} should be rejected");
        }
    }
}
