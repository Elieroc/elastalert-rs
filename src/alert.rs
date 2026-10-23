//! Alert body text (ElastAlert-compatible layout) and the debug alerter.

use crate::field::{self, py_str};
use crate::rule::Rule;
use crate::types::RuleType;
use serde_json::{Map, Value};

const MISSING: &str = "<MISSING VALUE>";

/// Python `str.format` subset: `{}`, `{0}`, `{name}`, `{{`/`}}`. Format specs after `:` are ignored.
pub fn py_format(template: &str, positional: &[String], named: &Map<String, Value>) -> String {
    let mut out = String::with_capacity(template.len() + 32);
    let mut chars = template.char_indices().peekable();
    let mut auto = 0;
    while let Some((i, c)) = chars.next() {
        match c {
            '{' if chars.peek().map(|x| x.1) == Some('{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek().map(|x| x.1) == Some('}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let Some(end) = template[i..].find('}') else {
                    out.push_str(&template[i..]);
                    break;
                };
                let inner = &template[i + 1..i + end];
                let name = inner.split([':', '!']).next().unwrap_or("");
                let val = if name.is_empty() {
                    auto += 1;
                    positional.get(auto - 1).cloned()
                } else if let Ok(n) = name.parse::<usize>() {
                    positional.get(n).cloned()
                } else {
                    named.get(name).map(py_str)
                };
                out.push_str(&val.unwrap_or_else(|| format!("{{{inner}}}")));
                while chars.peek().is_some_and(|x| x.0 <= i + end) {
                    chars.next();
                }
            }
            _ => out.push(c),
        }
    }
    out
}

fn rule_str<'a>(rule: &'a Rule, key: &str) -> Option<&'a str> {
    rule.raw.get(key).and_then(Value::as_str)
}

/// Value for an `alert_text_args` / `alert_text_kw` entry: the match field, else a rule option, else missing.
fn arg_value(rule: &Rule, m: &Map<String, Value>, name: &str, missing: &str) -> Value {
    match field::lookup(m, name) {
        Some(v) if !v.is_null() => v.clone(),
        _ => match rule.raw.get(name) {
            Some(v) if !v.is_null() && v != &Value::Bool(false) && v != "" => v.clone(),
            _ => Value::String(missing.into()),
        },
    }
}

fn custom_text(rule: &Rule, m: &Map<String, Value>) -> String {
    let missing = rule_str(rule, "alert_missing_value").unwrap_or(MISSING);
    let text = rule.raw.get("alert_text").map(py_str).unwrap_or_default();
    if let Some(Value::Array(args)) = rule.raw.get("alert_text_args") {
        let vals: Vec<String> = args.iter().map(|a| py_str(&arg_value(rule, m, &py_str(a), missing))).collect();
        py_format(&text, &vals, &Map::new())
    } else if let Some(Value::Object(kw)) = rule.raw.get("alert_text_kw") {
        let named: Map<String, Value> = kw.iter().map(|(name, alias)| (py_str(alias), arg_value(rule, m, name, missing))).collect();
        py_format(&text, &[], &named)
    } else {
        text
    }
}

fn ensure_blank_line(s: &mut String) {
    while !s.ends_with("\n\n") {
        s.push('\n');
    }
}

fn py_tuple(items: &[Value]) -> String {
    let repr = |v: &Value| match v {
        Value::String(s) if s.contains('\'') && !s.contains('"') => format!("\"{s}\""),
        Value::String(s) => format!("'{}'", s.replace('\'', "\\'")),
        other => py_str(other),
    };
    match items {
        [one] => format!("({},)", repr(one)),
        many => format!("({})", many.iter().map(repr).collect::<Vec<_>>().join(", ")),
    }
}

fn pretty_json(v: &Value) -> String {
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, fmt);
    serde::Serialize::serialize(v, &mut ser).expect("json to memory");
    String::from_utf8(buf).unwrap_or_default()
}

/// The text ElastAlert puts in every alert for one match.
pub fn match_body(rule: &Rule, rtype: &RuleType, m: &Map<String, Value>, ts_fmt: Option<&str>) -> String {
    let mut text = String::new();
    if !rule.raw.contains_key("alert_text") {
        text.push_str(&rule.name);
        text.push_str("\n\n");
    }
    text.push_str(&custom_text(rule, m));
    ensure_blank_line(&mut text);
    let text_type = rule_str(rule, "alert_text_type").unwrap_or("");
    if text_type != "alert_text_only" && text_type != "alert_text_jinja" {
        text.push_str(&rtype.match_str(rule, m, ts_fmt));
        ensure_blank_line(&mut text);
        if text_type != "exclude_fields" {
            // serde_json maps are sorted by key, like Python's `sorted(match.items())`.
            for (k, v) in m.iter().filter(|(k, _)| !k.starts_with("top_events_")) {
                let val = match v {
                    // new_term puts a Python tuple here for composite fields; it prints as a tuple, not JSON.
                    Value::Array(a) if k == "new_field" || k == "missing_field" => py_tuple(a),
                    Value::Array(_) | Value::Object(_) => pretty_json(v),
                    _ => py_str(v),
                };
                text.push_str(&format!("{k}: {val}\n"));
            }
        }
    }
    text
}

/// Body of one alert: one block per match, separated by a rule when there are several.
pub fn create_alert_body(rule: &Rule, rtype: &RuleType, matches: &[Map<String, Value>], ts_fmt: Option<&str>) -> String {
    let mut body = String::new();
    for m in matches {
        body.push_str(&match_body(rule, rtype, m, ts_fmt));
        if matches.len() > 1 {
            body.push_str("\n----------------------------------------\n");
        }
    }
    body
}

/// Subject / title: `alert_subject` (+ `alert_subject_args`), else the alerter's default.
pub fn create_title(rule: &Rule, matches: &[Map<String, Value>], default: impl FnOnce() -> String) -> String {
    let Some(subject) = rule.raw.get("alert_subject") else { return default() };
    let missing = rule_str(rule, "alert_missing_value").unwrap_or(MISSING);
    let mut text = py_str(subject);
    if let Some(Value::Array(args)) = rule.raw.get("alert_subject_args") {
        let vals: Vec<String> = args.iter().map(|a| py_str(&arg_value(rule, &matches[0], &py_str(a), missing))).collect();
        text = py_format(&text, &vals, &Map::new());
    }
    let max = rule.raw.get("alert_subject_max_len").and_then(Value::as_u64).unwrap_or(2048) as usize;
    text.chars().take(max).collect()
}

/// `alert: debug` and `--debug`: log the alert instead of sending it.
pub fn debug_alert(rule: &Rule, rtype: &RuleType, matches: &[Map<String, Value>], ts_fmt: Option<&str>) {
    for m in matches {
        let ts = field::lookup(m, &rule.timestamp_field).map(py_str).unwrap_or_else(|| "None".into());
        let head = match rule.query_key.as_ref().and_then(|qk| m.get(qk)) {
            Some(qv) => format!("Alert for {}, {} at {}:", rule.name, py_str(qv), ts),
            None => format!("Alert for {} at {}:", rule.name, ts),
        };
        // One log call so lines from rules running in parallel can't interleave; the second line
        // reproduces the logger prefix the Python version prints for the body.
        log::info!("{head}\nINFO:elastalert:{}", match_body(rule, rtype, m, ts_fmt));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn format_subset() {
        let named = json!({"user": "bob", "n": 3}).as_object().unwrap().clone();
        assert_eq!(py_format("{} logged {} times", &["bob".into(), "3".into()], &Map::new()), "bob logged 3 times");
        assert_eq!(py_format("{1}-{0}", &["a".into(), "b".into()], &Map::new()), "b-a");
        assert_eq!(py_format("{user}: {n:>3} {{x}}", &[], &named), "bob: 3 {x}");
        assert_eq!(py_format("{nope}", &[], &named), "{nope}");
    }

    #[test]
    fn json_like_python() {
        assert_eq!(pretty_json(&json!({"b": [1, 2.0], "a": {}})), "{\n    \"a\": {},\n    \"b\": [\n        1,\n        2.0\n    ]\n}");
    }
}
