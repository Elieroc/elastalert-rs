//! Global `config.yaml`: env expansion, env overrides, required keys, defaults.

use crate::time::{Dur, MINUTE, parse_duration_map};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

pub struct Config {
    /// Every key from the file (after overrides). Rules inherit the ones they don't set.
    pub raw: Map<String, Value>,
    pub run_every: Dur,
    pub buffer_time: Dur,
    pub old_query_limit: Dur,
    pub writeback_index: String,
    pub rules_folders: Vec<PathBuf>,
    pub scan_subdirectories: bool,
    pub max_query_size: u64,
    pub scroll_keepalive: String,
    pub max_scrolling_count: u64,
    pub max_threads: usize,
    pub skip_invalid: bool,
    pub custom_pretty_ts_format: Option<String>,
}

const REQUIRED: [&str; 5] = ["run_every", "es_host", "es_port", "writeback_index", "buffer_time"];

const ENV_OVERRIDES: [(&str, &str); 11] = [
    ("ES_USE_SSL", "use_ssl"),
    ("ES_BEARER", "es_bearer"),
    ("ES_PASSWORD", "es_password"),
    ("ES_USERNAME", "es_username"),
    ("ES_API_KEY", "es_api_key"),
    ("ES_HOST", "es_host"),
    ("ES_HOSTS", "es_hosts"),
    ("ES_PORT", "es_port"),
    ("ES_URL_PREFIX", "es_url_prefix"),
    ("STATSD_INSTANCE_TAG", "statsd_instance_tag"),
    ("STATSD_HOST", "statsd_host"),
];

/// Python's `os.path.expandvars`: `$NAME` and `${NAME}`; unknown variables stay as written.
pub fn expand_env(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let (name, consumed) = if let Some(body) = after.strip_prefix('{') {
            match body.find('}') {
                Some(end) => (&body[..end], end + 2),
                None => ("", 0),
            }
        } else {
            let end = after.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(after.len());
            (&after[..end], end)
        };
        match (!name.is_empty()).then(|| std::env::var(name).ok()).flatten() {
            Some(val) => out.push_str(&val),
            None => out.push_str(&rest[pos..pos + 1 + consumed]),
        }
        rest = &rest[pos + 1 + consumed..];
    }
    out.push_str(rest);
    out
}

pub fn read_yaml(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let v: Value = serde_yaml_ng::from_str(&expand_env(&text)).with_context(|| format!("parsing {}", path.display()))?;
    Ok(if v.is_null() { json!({}) } else { v })
}

fn env_value(conf_key: &str, val: String) -> Value {
    match conf_key {
        "use_ssl" => json!(matches!(val.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")),
        "es_port" => val.parse::<u64>().map(Value::from).unwrap_or(Value::String(val)),
        _ => Value::String(val),
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let Value::Object(mut raw) = read_yaml(path)? else { bail!("{} must be a YAML map", path.display()) };
        for (env, key) in ENV_OVERRIDES {
            if let Ok(val) = std::env::var(env) {
                raw.insert(key.into(), env_value(key, val));
            }
        }
        let missing: Vec<_> = REQUIRED.iter().filter(|k| !raw.contains_key(**k)).collect();
        if !missing.is_empty() {
            bail!("{} must contain {:?}", path.display(), missing);
        }
        let dur = |k: &str, default: Dur| -> Result<Dur> {
            raw.get(k).map_or(Ok(default), |v| parse_duration_map(v).with_context(|| format!("invalid time format for {k}")))
        };
        let folders = match raw.get("rules_folder") {
            Some(Value::String(s)) => vec![PathBuf::from(s)],
            Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(PathBuf::from)).collect(),
            _ => bail!("{} must contain rules_folder", path.display()),
        };
        Ok(Config {
            run_every: dur("run_every", 0)?,
            buffer_time: dur("buffer_time", 0)?,
            old_query_limit: dur("old_query_limit", 7 * 24 * 60 * MINUTE)?,
            writeback_index: raw["writeback_index"].as_str().context("writeback_index must be a string")?.into(),
            rules_folders: folders,
            scan_subdirectories: raw.get("scan_subdirectories").and_then(Value::as_bool).unwrap_or(true),
            max_query_size: raw.get("max_query_size").and_then(Value::as_u64).unwrap_or(10_000),
            scroll_keepalive: raw.get("scroll_keepalive").and_then(Value::as_str).unwrap_or("30s").into(),
            max_scrolling_count: raw.get("max_scrolling_count").and_then(Value::as_u64).unwrap_or(990),
            max_threads: raw.get("max_threads").and_then(Value::as_u64).unwrap_or(10) as usize,
            skip_invalid: raw.get("skip_invalid").and_then(Value::as_bool).unwrap_or(false),
            custom_pretty_ts_format: raw.get("custom_pretty_ts_format").and_then(Value::as_str).map(String::from),
            raw,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expandvars_like_python() {
        // SAFETY: test-only, single-threaded use of this variable name.
        unsafe { std::env::set_var("EA_TEST_HOST", "es1") };
        assert_eq!(expand_env("h: $EA_TEST_HOST:${EA_TEST_HOST}"), "h: es1:es1");
        assert_eq!(expand_env("p: $NOPE_EA_X ${NOPE_EA_Y} $ 5$"), "p: $NOPE_EA_X ${NOPE_EA_Y} $ 5$");
    }
}
