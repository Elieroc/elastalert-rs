//! `match_enhancements`: modules that change or drop a match before it is alerted.
//!
//! ElastAlert 2 loads Python classes here; those cannot run. Instead each entry names a module compiled into the
//! binary: upstream's built-in `TimeEnhancement`, or a native module `rust.<name>` (see https://elastalert3.neopipe.fr/enhancements.html).
//! A new module is a type implementing [`Enhancement`] plus one line in [`REGISTRY`].

use crate::field::{self, py_str};
use crate::time::{parse_iso, pretty};
use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};
use std::sync::Arc;

type Doc = Map<String, Value>;

/// What happens to the match after a module ran.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Keep,
    /// The match is not alerted (upstream's `DropMatchException`).
    Drop,
}

pub trait Enhancement: Send + Sync {
    /// Changes the match in place. An error is logged; the match is then dropped, or kept with
    /// `run_enhancements_first`, as upstream does.
    fn process(&self, m: &mut Doc) -> Result<Outcome>;
}

/// Builds a module from its options (`Value::Null` when the entry is a plain name) and the rule document.
type Constructor = fn(&Value, &Doc) -> Result<Arc<dyn Enhancement>>;

/// Every module a rule can name. Names without the `rust.` prefix are upstream's own.
const REGISTRY: &[(&str, Constructor)] = &[
    ("TimeEnhancement", TimeEnhancement::build),
    ("elastalert.enhancements.TimeEnhancement", TimeEnhancement::build),
    ("rust.add_field", AddField::build),
    ("rust.drop_if", DropIf::build),
    ("rust.lookup", Lookup::build),
];

/// Reads `match_enhancements`: a list of names (`TimeEnhancement`) or one-key maps (`rust.add_field: {...}`).
pub fn load(entries: Option<&Value>, rule: &Doc) -> Result<Vec<Arc<dyn Enhancement>>> {
    let list = match entries {
        None | Some(Value::Null) => return Ok(vec![]),
        Some(Value::Array(a)) => a,
        Some(_) => bail!("match_enhancements must be a list"),
    };
    list.iter()
        .map(|entry| {
            let (name, opts) = match entry {
                Value::String(s) => (s.as_str(), &Value::Null),
                Value::Object(m) if m.len() == 1 => {
                    let (k, v) = m.iter().next().expect("one key");
                    (k.as_str(), v)
                }
                _ => bail!("match_enhancements entries must be a name or a map with one name"),
            };
            let Some((_, build)) = REGISTRY.iter().find(|(n, _)| *n == name) else {
                if name.starts_with("rust.") {
                    let known: Vec<&str> = REGISTRY.iter().map(|(n, _)| *n).filter(|n| n.starts_with("rust.")).collect();
                    bail!("unknown match enhancement {name} (known: {})", known.join(", "));
                }
                bail!("match enhancement {name} cannot be loaded: Python modules are not supported, use TimeEnhancement or a rust.* module");
            };
            build(opts, rule).with_context(|| format!("match enhancement {name}"))
        })
        .collect()
}

// ---- option helpers ----

fn opts_map<'a>(opts: &'a Value, module: &str) -> Result<&'a Map<String, Value>> {
    opts.as_object().with_context(|| format!("{module} needs options, e.g. `- {module}: {{field: ...}}`"))
}

fn opt_str(o: &Map<String, Value>, key: &str) -> Result<String> {
    o.get(key).and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from).with_context(|| format!("option {key} (a field name) is required"))
}

fn check_keys(o: &Map<String, Value>, allowed: &[&str]) -> Result<()> {
    match o.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => bail!("unknown option {k} (allowed: {})", allowed.join(", ")),
        None => Ok(()),
    }
}

/// Sets `path` (dotted) in the match, creating the intermediate objects.
fn set_path(m: &mut Doc, path: &str, value: Value) {
    if field::set(m, path, value.clone()) {
        return;
    }
    let mut keys = path.split('.').peekable();
    let mut node = m;
    while let Some(k) = keys.next() {
        if keys.peek().is_none() {
            node.insert(k.to_string(), value);
            return;
        }
        let slot = node.entry(k).or_insert_with(|| Value::Object(Map::new()));
        if !slot.is_object() {
            *slot = Value::Object(Map::new());
        }
        node = slot.as_object_mut().expect("made an object above");
    }
}

// ---- TimeEnhancement ----

/// Upstream's `TimeEnhancement`: `@timestamp` becomes `pretty_ts(@timestamp)` (local time, `YYYY-MM-DD HH:MM TZ`).
struct TimeEnhancement;

impl TimeEnhancement {
    fn build(_: &Value, _: &Doc) -> Result<Arc<dyn Enhancement>> {
        Ok(Arc::new(TimeEnhancement))
    }
}

impl Enhancement for TimeEnhancement {
    fn process(&self, m: &mut Doc) -> Result<Outcome> {
        let Some(v) = field::lookup(m, "@timestamp") else { bail!("TimeEnhancement: the match has no @timestamp") };
        let Some(ts) = v.as_str().and_then(parse_iso) else { bail!("TimeEnhancement: cannot parse @timestamp {v}") };
        m.insert("@timestamp".into(), Value::String(pretty(ts, true, None)));
        Ok(Outcome::Keep)
    }
}

// ---- rust.add_field ----

/// Sets `field` to a fixed `value` or to the value of `copy_from`.
struct AddField {
    field: String,
    value: Option<Value>,
    copy_from: Option<String>,
    overwrite: bool,
}

impl AddField {
    fn build(opts: &Value, _: &Doc) -> Result<Arc<dyn Enhancement>> {
        let o = opts_map(opts, "rust.add_field")?;
        check_keys(o, &["field", "value", "copy_from", "overwrite"])?;
        let (value, copy_from) = (o.get("value").cloned(), o.get("copy_from").and_then(Value::as_str).map(String::from));
        if value.is_some() == copy_from.is_some() {
            bail!("set exactly one of value and copy_from");
        }
        Ok(Arc::new(AddField { field: opt_str(o, "field")?, value, copy_from, overwrite: o.get("overwrite").and_then(Value::as_bool).unwrap_or(true) }))
    }
}

impl Enhancement for AddField {
    fn process(&self, m: &mut Doc) -> Result<Outcome> {
        if !self.overwrite && field::lookup(m, &self.field).is_some_and(|v| !v.is_null()) {
            return Ok(Outcome::Keep);
        }
        let value = match (&self.value, &self.copy_from) {
            (Some(v), _) => v.clone(),
            (None, Some(src)) => match field::lookup(m, src) {
                Some(v) => v.clone(),
                None => return Ok(Outcome::Keep), // nothing to copy
            },
            (None, None) => unreachable!("checked at load"),
        };
        set_path(m, &self.field, value);
        Ok(Outcome::Keep)
    }
}

// ---- rust.drop_if ----

/// Drops the match when `field` equals one of `equals`, or when it is (`exists: false`) / is not (`exists: true`) missing.
struct DropIf {
    field: String,
    equals: Vec<String>,
    exists: Option<bool>,
}

impl DropIf {
    fn build(opts: &Value, _: &Doc) -> Result<Arc<dyn Enhancement>> {
        let o = opts_map(opts, "rust.drop_if")?;
        check_keys(o, &["field", "equals", "exists"])?;
        let equals: Vec<String> = match o.get("equals") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => a.iter().map(py_str).collect(),
            Some(v) => vec![py_str(v)],
        };
        let exists = o.get("exists").map(|v| v.as_bool().context("exists must be true or false")).transpose()?;
        if equals.is_empty() == exists.is_none() {
            bail!("set exactly one of equals and exists");
        }
        Ok(Arc::new(DropIf { field: opt_str(o, "field")?, equals, exists }))
    }
}

impl Enhancement for DropIf {
    fn process(&self, m: &mut Doc) -> Result<Outcome> {
        let v = field::lookup(m, &self.field).filter(|v| !v.is_null());
        let drop = match self.exists {
            Some(want) => v.is_some() == want,
            None => match v {
                // A list field matches when any element does.
                Some(Value::Array(a)) => a.iter().any(|x| self.equals.contains(&py_str(x))),
                Some(x) => self.equals.contains(&py_str(x)),
                None => false,
            },
        };
        Ok(if drop { Outcome::Drop } else { Outcome::Keep })
    }
}

// ---- rust.lookup ----

/// Maps the value of `field` through `table` into `target` (default: `field` itself). Unknown values get `default`
/// when it is set and are left alone otherwise.
struct Lookup {
    field: String,
    target: String,
    table: Map<String, Value>,
    default: Option<Value>,
}

impl Lookup {
    fn build(opts: &Value, _: &Doc) -> Result<Arc<dyn Enhancement>> {
        let o = opts_map(opts, "rust.lookup")?;
        check_keys(o, &["field", "target", "table", "default"])?;
        let field = opt_str(o, "field")?;
        let table = o.get("table").and_then(Value::as_object).cloned().context("option table (a map of value: replacement) is required")?;
        let target = o.get("target").and_then(Value::as_str).map_or_else(|| field.clone(), String::from);
        Ok(Arc::new(Lookup { field, target, table, default: o.get("default").cloned() }))
    }
}

impl Enhancement for Lookup {
    fn process(&self, m: &mut Doc) -> Result<Outcome> {
        // YAML keys are strings, so `404:` matches the number 404 too.
        let found = field::lookup(m, &self.field).filter(|v| !v.is_null()).and_then(|v| self.table.get(&py_str(v)));
        if let Some(v) = found.or(self.default.as_ref()).cloned() {
            set_path(m, &self.target, v);
        }
        Ok(Outcome::Keep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn doc(v: Value) -> Doc {
        v.as_object().unwrap().clone()
    }

    fn one(entry: Value) -> Arc<dyn Enhancement> {
        load(Some(&json!([entry])), &Map::new()).unwrap().remove(0)
    }

    #[test]
    fn names_and_errors() {
        assert_eq!(load(Some(&json!(["TimeEnhancement", "elastalert.enhancements.TimeEnhancement"])), &Map::new()).unwrap().len(), 2);
        assert!(load(None, &Map::new()).unwrap().is_empty());
        let err = |v: Value| format!("{:#}", load(Some(&v), &Map::new()).err().unwrap());
        assert!(err(json!(["my.module.Mine"])).contains("Python modules"));
        assert!(err(json!(["rust.nope"])).contains("known: rust.add_field"));
        assert!(err(json!(["rust.add_field"])).contains("needs options"));
        assert!(err(json!([{"rust.add_field": {"field": "a"}}])).contains("exactly one"));
        assert!(err(json!([{"rust.drop_if": {"field": "a", "equals": 1, "typo": 2}}])).contains("unknown option typo"));
        assert!(err(json!("x")).contains("must be a list"));
    }

    #[test]
    fn time_enhancement_formats_like_pretty_ts() {
        let e = one(json!("TimeEnhancement"));
        let mut m = doc(json!({"@timestamp": "2024-03-01T12:00:00Z", "a": 1}));
        assert_eq!(e.process(&mut m).unwrap(), Outcome::Keep);
        assert_eq!(m["@timestamp"], json!(pretty(parse_iso("2024-03-01T12:00:00Z").unwrap(), true, None)));
        assert!(e.process(&mut Map::new()).is_err());
    }

    #[test]
    fn add_field() {
        let e = one(json!({"rust.add_field": {"field": "team.name", "value": "secops"}}));
        let mut m = doc(json!({"a": 1}));
        e.process(&mut m).unwrap();
        assert_eq!(m["team"], json!({"name": "secops"}));

        let e = one(json!({"rust.add_field": {"field": "who", "copy_from": "user.name", "overwrite": false}}));
        let mut m = doc(json!({"user": {"name": "eve"}}));
        e.process(&mut m).unwrap();
        assert_eq!(m["who"], json!("eve"));
        let mut m = doc(json!({"user": {"name": "eve"}, "who": "kept"}));
        e.process(&mut m).unwrap();
        assert_eq!(m["who"], json!("kept"));
    }

    #[test]
    fn drop_if() {
        let e = one(json!({"rust.drop_if": {"field": "user.name", "equals": ["svc_backup", 7]}}));
        assert_eq!(e.process(&mut doc(json!({"user": {"name": "svc_backup"}}))).unwrap(), Outcome::Drop);
        assert_eq!(e.process(&mut doc(json!({"user": {"name": 7}}))).unwrap(), Outcome::Drop);
        assert_eq!(e.process(&mut doc(json!({"user": {"name": ["x", "svc_backup"]}}))).unwrap(), Outcome::Drop);
        assert_eq!(e.process(&mut doc(json!({"user": {"name": "eve"}}))).unwrap(), Outcome::Keep);
        assert_eq!(e.process(&mut doc(json!({}))).unwrap(), Outcome::Keep);

        let e = one(json!({"rust.drop_if": {"field": "tags", "exists": false}}));
        assert_eq!(e.process(&mut doc(json!({}))).unwrap(), Outcome::Drop);
        assert_eq!(e.process(&mut doc(json!({"tags": null}))).unwrap(), Outcome::Drop);
        assert_eq!(e.process(&mut doc(json!({"tags": "a"}))).unwrap(), Outcome::Keep);
    }

    #[test]
    fn lookup() {
        let e = one(json!({"rust.lookup": {"field": "status", "target": "status_text", "table": {"404": "not found", "500": "server error"}, "default": "other"}}));
        let mut m = doc(json!({"status": 404}));
        e.process(&mut m).unwrap();
        assert_eq!(m["status_text"], json!("not found"));
        let mut m = doc(json!({"status": 302}));
        e.process(&mut m).unwrap();
        assert_eq!(m["status_text"], json!("other"));

        let e = one(json!({"rust.lookup": {"field": "host", "table": {"db-1": "database"}}}));
        let mut m = doc(json!({"host": "web-1"}));
        e.process(&mut m).unwrap();
        assert_eq!(m["host"], json!("web-1"));
        let mut m = doc(json!({"host": "db-1"}));
        e.process(&mut m).unwrap();
        assert_eq!(m["host"], json!("database"));
    }
}
