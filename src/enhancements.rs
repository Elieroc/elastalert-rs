//! `match_enhancements`: ElastAlert 2 loads Python classes; only the built-in ones can run here.

use crate::field;
use crate::time::{parse_iso, pretty};
use anyhow::{Result, bail};
use serde_json::{Map, Value};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Enhancement {
    /// `TimeEnhancement`: `@timestamp` becomes `pretty_ts(@timestamp)` (local time, `YYYY-MM-DD HH:MM TZ`).
    Time,
}

impl Enhancement {
    /// `TimeEnhancement` or `<module>.TimeEnhancement` for the module of upstream's `enhancements.py`.
    pub fn from_name(name: &str) -> Result<Enhancement> {
        match name {
            "TimeEnhancement" | "elastalert.enhancements.TimeEnhancement" => Ok(Enhancement::Time),
            other => bail!("match enhancement {other} cannot be loaded: Python modules are not supported, only the built-in TimeEnhancement is"),
        }
    }

    pub fn process(self, m: &mut Map<String, Value>) -> Result<()> {
        match self {
            Enhancement::Time => {
                let Some(v) = field::lookup(m, "@timestamp") else { bail!("TimeEnhancement: the match has no @timestamp") };
                let Some(ts) = v.as_str().and_then(parse_iso) else { bail!("TimeEnhancement: cannot parse @timestamp {v}") };
                m.insert("@timestamp".into(), Value::String(pretty(ts, true, None)));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn names() {
        assert_eq!(Enhancement::from_name("TimeEnhancement").unwrap(), Enhancement::Time);
        assert_eq!(Enhancement::from_name("elastalert.enhancements.TimeEnhancement").unwrap(), Enhancement::Time);
        assert!(Enhancement::from_name("my.module.Mine").is_err());
    }

    #[test]
    fn time_enhancement_formats_like_pretty_ts() {
        let mut m = json!({"@timestamp": "2024-03-01T12:00:00Z", "a": 1}).as_object().unwrap().clone();
        Enhancement::Time.process(&mut m).unwrap();
        assert_eq!(m["@timestamp"], json!(pretty(parse_iso("2024-03-01T12:00:00Z").unwrap(), true, None)));
        assert!(m["@timestamp"].as_str().unwrap().starts_with("2024-03-01 "));
        assert!(Enhancement::Time.process(&mut Map::new()).is_err());
    }
}
