//! Rule files: discovery, `import:` chains, defaults inherited from config.yaml, validation.

use crate::config::{Config, read_yaml};
use crate::time::{Dur, MINUTE, parse_duration_map};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Any,
    Frequency,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TsType {
    Iso,
    Unix,
    UnixMs,
}

pub struct Rule {
    pub name: String,
    pub kind: Kind,
    pub index: String,
    pub filter: Vec<Value>,
    pub include: Vec<String>,
    pub timestamp_field: String,
    pub timestamp_type: TsType,
    pub use_local_time: bool,
    pub query_key: Option<String>,
    pub compound_query_key: Vec<String>,
    pub realert: Dur,
    pub realert_key: String,
    pub buffer_time: Dur,
    pub run_every: Dur,
    pub query_delay: Dur,
    pub timeframe: Option<Dur>,
    pub num_events: u64,
    pub attach_related: bool,
    pub scan_entire_timeframe: bool,
    pub max_query_size: u64,
    pub max_scrolling_count: u64,
    pub alerts: Vec<String>,
    /// The merged rule document; alert text and alerters read arbitrary keys from it.
    pub raw: Map<String, Value>,
}

pub fn is_yaml(p: &Path) -> bool {
    matches!(p.extension().and_then(|e| e.to_str()), Some("yaml" | "yml"))
}

fn walk(dir: &Path, recurse: bool, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading rules folder {}", dir.display()))? {
        let path = entry?.path();
        let hidden_k8s = path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with(".."));
        if path.is_dir() {
            if recurse && !hidden_k8s {
                walk(&path, recurse, out)?;
            }
        } else if is_yaml(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// Rule files to load. `--rule` may be a path or a bare file name inside the rules folders.
pub fn discover(conf: &Config, only: Option<&str>) -> Result<Vec<PathBuf>> {
    if let Some(r) = only.map(Path::new).filter(|p| p.is_file()) {
        return Ok(vec![r.to_path_buf()]);
    }
    let mut files = Vec::new();
    for dir in &conf.rules_folders {
        if !dir.exists() {
            bail!("rules folder does not exist: {}", dir.display());
        }
        walk(dir, conf.scan_subdirectories, &mut files)?;
    }
    if let Some(name) = only {
        files.retain(|f| f.file_name().and_then(|n| n.to_str()) == Some(name));
    }
    files.sort();
    Ok(files)
}

/// Reads a rule and its `import:` chain. Later imports win, `filter` lists are concatenated (AND).
/// Import paths are relative to the top-level rule file.
pub fn load_yaml(file: &Path) -> Result<Map<String, Value>> {
    let mut rule = Map::new();
    rule.insert("rule_file".into(), json!(file.to_string_lossy()));
    let base = file.parent().unwrap_or(Path::new("."));
    let mut stack: Vec<PathBuf> = Vec::new();
    let mut current = file.to_path_buf();
    let mut seen = 0;
    loop {
        let Value::Object(mut loaded) = read_yaml(&current)? else { bail!("{} must be a YAML map", current.display()) };
        if let (Some(Value::Array(mine)), Some(Value::Array(theirs))) = (rule.get("filter"), loaded.get("filter")) {
            let merged: Vec<Value> = theirs.iter().chain(mine).cloned().collect();
            rule.insert("filter".into(), Value::Array(merged));
        }
        loaded.extend(rule);
        rule = loaded;
        if let Some(imports) = rule.remove("import") {
            let list = match imports {
                Value::String(s) => vec![s],
                Value::Array(a) => a.into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
                _ => bail!("import must be a string or a list"),
            };
            stack.extend(list.into_iter().map(|p| base.join(p)));
        }
        seen += 1;
        if seen > 100 {
            bail!("import chain too deep (cycle?) in {}", file.display());
        }
        match stack.pop() {
            Some(next) => current = next,
            None => return Ok(rule),
        }
    }
}

fn dur_opt(raw: &Map<String, Value>, key: &str) -> Result<Option<Dur>> {
    raw.get(key)
        .map(|v| parse_duration_map(v).with_context(|| format!("invalid time format for {key}")))
        .transpose()
}

fn str_list(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

pub fn load(file: &Path, conf: &Config) -> Result<Rule> {
    let mut raw = load_yaml(file)?;
    for (k, v) in &conf.raw {
        raw.entry(k.clone()).or_insert_with(|| v.clone());
    }
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("rule");
    let name = raw.get("name").and_then(Value::as_str).unwrap_or(stem).to_string();
    raw.insert("name".into(), json!(name));
    for key in ["type", "index", "alert"] {
        if !raw.contains_key(key) {
            bail!("missing required option: {key}");
        }
    }
    let kind = match raw["type"].as_str() {
        Some("any") => Kind::Any,
        Some("frequency") => Kind::Frequency,
        other => bail!("rule type {other:?} is not supported yet"),
    };
    let aggregation = raw.contains_key("aggregation");
    if aggregation {
        bail!("aggregation is not supported yet");
    }
    let timestamp_type = match raw.get("timestamp_type").and_then(Value::as_str).unwrap_or("iso").trim().to_lowercase().as_str() {
        "iso" => TsType::Iso,
        "unix" => TsType::Unix,
        "unix_ms" => TsType::UnixMs,
        t => bail!("timestamp_type {t} is not supported (iso, unix, unix_ms)"),
    };
    let timestamp_field = raw.get("timestamp_field").and_then(Value::as_str).unwrap_or("@timestamp").to_string();

    let mut compound_query_key = Vec::new();
    let query_key = match raw.get("query_key").cloned() {
        Some(Value::Array(list)) => {
            let keys: Vec<String> = list.iter().filter_map(|v| v.as_str().map(String::from)).collect();
            match keys.len() {
                0 => None,
                1 => Some(keys[0].clone()),
                _ => {
                    compound_query_key = keys.clone();
                    Some(keys.join(","))
                }
            }
        }
        Some(Value::String(s)) => Some(s),
        _ => None,
    };
    match &query_key {
        Some(q) => raw.insert("query_key".into(), json!(q)),
        None => raw.remove("query_key"),
    };

    let mut include = raw.get("include").map(str_list).unwrap_or_else(|| vec!["*".into()]);
    include.extend(query_key.clone());
    include.extend(compound_query_key.iter().cloned());
    include.push(timestamp_field.clone());
    include.sort();
    include.dedup();

    let timeframe = dur_opt(&raw, "timeframe")?;
    let num_events = raw.get("num_events").and_then(Value::as_u64).unwrap_or(0);
    if kind == Kind::Frequency && (timeframe.is_none() || num_events == 0) {
        bail!("frequency rule needs num_events and timeframe");
    }
    if raw.get("scan_entire_timeframe").and_then(Value::as_bool).unwrap_or(false) && timeframe.is_none() {
        bail!("scan_entire_timeframe can only be used if there is a timeframe specified");
    }

    let alerts = match &raw["alert"] {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a
            .iter()
            .filter_map(|x| match x {
                Value::String(s) => Some(s.clone()),
                Value::Object(m) => m.keys().next().cloned(),
                _ => None,
            })
            .collect(),
        _ => bail!("alert must be a string or a list"),
    };

    let filter = match raw.get("filter") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) => a.clone(),
        Some(_) => bail!("filter must be a list"),
    };

    Ok(Rule {
        realert: dur_opt(&raw, "realert")?.unwrap_or(if aggregation { 0 } else { MINUTE }),
        realert_key: raw.get("realert_key").and_then(Value::as_str).unwrap_or(&name).to_string(),
        buffer_time: dur_opt(&raw, "buffer_time")?.unwrap_or(conf.buffer_time),
        run_every: dur_opt(&raw, "run_every")?.unwrap_or(conf.run_every),
        query_delay: dur_opt(&raw, "query_delay")?.unwrap_or(0),
        use_local_time: raw.get("use_local_time").and_then(Value::as_bool).unwrap_or(true),
        attach_related: raw.get("attach_related").and_then(Value::as_bool).unwrap_or(false),
        scan_entire_timeframe: raw.get("scan_entire_timeframe").and_then(Value::as_bool).unwrap_or(false),
        max_query_size: raw.get("max_query_size").and_then(Value::as_u64).unwrap_or(conf.max_query_size),
        max_scrolling_count: raw.get("max_scrolling_count").and_then(Value::as_u64).unwrap_or(conf.max_scrolling_count),
        index: raw["index"].as_str().context("index must be a string")?.to_string(),
        name,
        kind,
        filter,
        include,
        timestamp_field,
        timestamp_type,
        query_key,
        compound_query_key,
        timeframe,
        num_events,
        alerts,
        raw,
    })
}

/// Loads every rule. Invalid files abort unless `skip_invalid`; duplicate names always abort.
pub fn load_all(conf: &Config, only: Option<&str>) -> Result<Vec<Rule>> {
    let mut rules: Vec<Rule> = Vec::new();
    for file in discover(conf, only)? {
        match load(&file, conf) {
            Ok(r) if r.raw.get("is_enabled").and_then(Value::as_bool) == Some(false) => {}
            Ok(r) => {
                if rules.iter().any(|x| x.name == r.name) {
                    bail!("duplicate rule named {}", r.name);
                }
                rules.push(r);
            }
            Err(e) if conf.skip_invalid => log::error!("Invalid rule file skipped: {}: {e:#}", file.display()),
            Err(e) => bail!("error loading file {}: {e:#}", file.display()),
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn import_chain_merges_filters_and_keys() {
        let dir = std::env::temp_dir().join(format!("ea-rule-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("base.yaml"), "index: logs-*\nfilter:\n- term: {a: 1}\nrealert: {minutes: 5}\n").unwrap();
        std::fs::write(dir.join("r.yaml"), "import: base.yaml\nname: r\ntype: any\nalert: debug\nfilter:\n- term: {b: 2}\n").unwrap();
        let raw = load_yaml(&dir.join("r.yaml")).unwrap();
        assert_eq!(raw["index"], json!("logs-*"));
        assert_eq!(raw["filter"], json!([{"term": {"a": 1}}, {"term": {"b": 2}}]));
        assert!(!raw.contains_key("import"));
        std::fs::remove_dir_all(dir).ok();
    }
}
