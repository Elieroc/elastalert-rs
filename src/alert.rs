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

/// Renders a Jinja template with `rule | match` (match wins) also available under `jinja_root_name`.
fn render_jinja(rule: &Rule, source: &str, m: &Map<String, Value>) -> String {
    let mut values = rule.raw.clone();
    values.extend(m.clone());
    let root = rule_str(rule, "jinja_root_name").unwrap_or("_data").to_string();
    values.insert(root, Value::Object(values.clone()));
    match minijinja::Environment::new().render_str(source, minijinja::value::Serde(Value::Object(values))) {
        Ok(t) => t,
        Err(e) => format!("[template error: {e}]"),
    }
}

/// Checks a Jinja template at rule load.
pub fn check_jinja(source: &str) -> Result<(), String> {
    minijinja::Environment::new().template_from_str(source).map(|_| ()).map_err(|e| e.to_string())
}

fn custom_text(rule: &Rule, m: &Map<String, Value>) -> String {
    if rule_str(rule, "alert_text_type") == Some("alert_text_jinja") {
        return render_jinja(rule, rule.jinja_template.as_deref().unwrap_or(""), m);
    }
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
        for key in &rule.top_count_keys {
            let name = format!("top_events_{key}");
            let Some(counts) = m.get(&name).and_then(Value::as_object) else { continue };
            text.push_str(&format!("{key}:\n"));
            if counts.is_empty() {
                text.push_str("No events found.\n");
            }
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by(|a, b| b.1.as_i64().cmp(&a.1.as_i64())); // stable: ties stay in key order
            for (term, n) in sorted {
                text.push_str(&format!("{term}: {}\n", py_str(n)));
            }
            text.push('\n');
        }
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

/// Body of one alert: aggregation summary (if configured), then one block per match.
pub fn create_alert_body(rule: &Rule, rtype: &RuleType, matches: &[Map<String, Value>], ts_fmt: Option<&str>) -> String {
    create_alert_body_with(rule, rtype, matches, ts_fmt, 80, false)
}

/// `summary_width` / `code_fence` let Slack narrow the table and wrap it in a code block.
pub fn create_alert_body_with(rule: &Rule, rtype: &RuleType, matches: &[Map<String, Value>], ts_fmt: Option<&str>, summary_width: usize, code_fence: bool) -> String {
    let mut body = summary_text(rule, matches, summary_width);
    if code_fence && !body.is_empty() {
        body = format!("```\n{body}```\n");
    }
    if rule_str(rule, "alert_text_type") != Some("aggregation_summary_only") {
        for m in matches {
            body.push_str(&match_body(rule, rtype, m, ts_fmt));
            if matches.len() > 1 {
                body.push_str("\n----------------------------------------\n");
            }
        }
    }
    body
}

fn py_list_repr(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|i| format!("'{}'", i.replace('\'', "\\'"))).collect::<Vec<_>>().join(", "))
}

/// Python `textwrap.wrap`: greedy, breaks after hyphens inside words, splits words longer than `width`.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut chunks: Vec<String> = Vec::new();
    for word in text.split_whitespace() {
        let chars: Vec<char> = word.chars().collect();
        let mut cur = String::new();
        for (i, c) in chars.iter().enumerate() {
            cur.push(*c);
            let hyphen_break = *c == '-' && i > 0 && chars[i - 1].is_alphanumeric() && chars.get(i + 1).is_some_and(|n| n.is_alphanumeric());
            if hyphen_break {
                chunks.push(std::mem::take(&mut cur) + "\u{0}");
            }
        }
        chunks.push(cur + " "); // trailing space marks "followed by whitespace"
    }
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for ch in chunks {
        let (piece, space) = match ch.strip_suffix('\u{0}') {
            Some(p) => (p.to_string(), false),
            None => (ch.trim_end_matches(' ').to_string(), true),
        };
        let mut piece = piece;
        let sep = |l: &String| if l.ends_with('-') && !l.ends_with(' ') { "" } else { " " };
        loop {
            let add = if line.is_empty() { 0 } else { sep(&line).len() };
            if line.chars().count() + add + piece.chars().count() <= width {
                if !line.is_empty() {
                    line.push_str(sep(&line));
                }
                line.push_str(&piece);
                break;
            }
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
                continue;
            }
            let head: String = piece.chars().take(width).collect();
            piece = piece.chars().skip(width).collect();
            lines.push(head);
            if piece.is_empty() {
                break;
            }
        }
        let _ = space;
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

/// Port of texttable's output for `header + rows` (columns left aligned, header centered).
fn ascii_table(headers: &[String], rows: &[Vec<String>], max_width: usize) -> String {
    let n = headers.len();
    let mut maxi: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            maxi[i] = maxi[i].max(c.lines().map(|l| l.chars().count()).max().unwrap_or(0));
        }
    }
    let deco = 3 * (n - 1) + 4;
    if maxi.iter().sum::<usize>() + deco > max_width && max_width >= n + deco {
        let mut avail = max_width - deco;
        let mut new = vec![0usize; n];
        let mut i = 0;
        while avail > 0 {
            if new[i] < maxi[i] {
                new[i] += 1;
                avail -= 1;
            }
            i = (i + 1) % n;
        }
        maxi = new;
    }
    let hline = |c: char| format!("+{c}{}{c}+\n", maxi.iter().map(|w| c.to_string().repeat(*w)).collect::<Vec<_>>().join(&format!("{c}+{c}")));
    let line = |cells: &[String], header: bool| {
        let wrapped: Vec<Vec<String>> = cells.iter().zip(&maxi).map(|(c, w)| if c.trim().is_empty() { vec![String::new()] } else { c.split('\n').flat_map(|l| wrap(l, *w)).collect() }).collect();
        let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
        let mut out = String::new();
        for r in 0..height {
            out.push_str("| ");
            let parts: Vec<String> = wrapped
                .iter()
                .zip(&maxi)
                .map(|(cell, w)| {
                    let text = cell.get(r).cloned().unwrap_or_default();
                    let fill = w - text.chars().count();
                    if header { format!("{}{text}{}", " ".repeat(fill / 2), " ".repeat(fill - fill / 2)) } else { format!("{text}{}", " ".repeat(fill)) }
                })
                .collect();
            out.push_str(&parts.join(" | "));
            out.push_str(" |\n");
        }
        out
    };
    let mut out = hline('-') + &line(headers, true) + &hline('=');
    for r in rows {
        out.push_str(&line(r, false));
        out.push_str(&hline('-'));
    }
    out
}

/// "Aggregation resulted in the following data..." table: count of matches per `summary_table_fields` tuple.
fn summary_text(rule: &Rule, matches: &[Map<String, Value>], width: usize) -> String {
    if rule.aggregation.is_none() || !rule.raw.contains_key("summary_table_fields") {
        return String::new();
    }
    let fields = match &rule.raw["summary_table_fields"] {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    let (mut paths, mut headers) = (Vec::new(), Vec::new());
    for f in &fields {
        match f {
            Value::Object(o) => {
                let p = o.get("path").map(py_str).unwrap_or_default();
                headers.push(o.get("header").map(py_str).unwrap_or_else(|| p.clone()));
                paths.push(p);
            }
            other => {
                paths.push(py_str(other));
                headers.push(py_str(other));
            }
        }
    }
    let mut text = rule_str(rule, "summary_prefix").unwrap_or("").to_string();
    if !text.is_empty() {
        text.push('\n');
    }
    let mut with_count = paths.clone();
    with_count.push("count".into());
    text.push_str(&format!("Aggregation resulted in the following data for summary_table_fields ==> {}:\n\n", py_list_repr(&with_count)));
    let mut order: Vec<Vec<String>> = Vec::new();
    let mut counts: std::collections::HashMap<Vec<String>, u64> = Default::default();
    for m in matches {
        let key: Vec<String> = paths.iter().map(|p| py_str(&field::lookup(m, p).cloned().unwrap_or(Value::Null))).collect();
        let c = counts.entry(key.clone()).or_insert(0);
        if *c == 0 {
            order.push(key);
        }
        *c += 1;
    }
    let max_rows = rule.raw.get("summary_table_max_rows").and_then(Value::as_u64);
    if let Some(n) = max_rows {
        order.sort_by(|a, b| counts[b].cmp(&counts[a])); // stable, like Counter.most_common
        order.truncate(n as usize);
    }
    let mut hdr = headers.clone();
    hdr.push("count".into());
    if rule_str(rule, "summary_table_type") == Some("markdown") {
        text.push_str(&format!("| {} |\n{}|\n", hdr.join(" | "), "|-----".repeat(hdr.len())));
        for k in &order {
            text.push_str(&format!("{}| {} |\n", k.iter().map(|c| format!("| {c} ")).collect::<String>(), counts[k]));
        }
        text.push('\n');
    } else {
        let rows: Vec<Vec<String>> = order.iter().map(|k| k.iter().cloned().chain([counts[k].to_string()]).collect()).collect();
        text.push_str(&ascii_table(&hdr, &rows, width));
        text.push_str("\n");
    }
    if let Some(n) = max_rows {
        text.push_str(&format!("Showing top {n} rows\n"));
    }
    text.push_str(rule_str(rule, "summary_suffix").unwrap_or(""));
    text
}

/// Subject / title: `alert_subject` (+ `alert_subject_args`), else the alerter's default.
pub fn create_title(rule: &Rule, matches: &[Map<String, Value>], default: impl FnOnce() -> String) -> String {
    let Some(subject) = rule.raw.get("alert_subject") else { return default() };
    let missing = rule_str(rule, "alert_missing_value").unwrap_or(MISSING);
    let mut text = py_str(subject);
    if rule_str(rule, "alert_text_type") == Some("alert_text_jinja") {
        text = render_jinja(rule, &text, &matches[0]);
        let max = rule.raw.get("alert_subject_max_len").and_then(Value::as_u64).unwrap_or(2048) as usize;
        return text.chars().take(max).collect();
    }
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

    /// Summary tables must match what Python's texttable / markdown code printed for the same matches
    /// (golden files generated by `Alerter.get_aggregation_summary_text`).
    #[test]
    fn summary_tables_match_python() {
        let hosts = ["web-1", "web-1", "db-1", "a-very-long-hostname-that-goes-on-and-on-and-on-and-on-and-on-and-on-forever-yes", "web-1", "db-1", "x y z"];
        let matches: Vec<Map<String, Value>> = hosts
            .iter()
            .cycle()
            .take(14)
            .chain(["web-1"].iter())
            .enumerate()
            .map(|(i, h)| json!({"host": h, "user": {"name": if i % 3 != 0 { "eve" } else { "bob" }}, "n": i}).as_object().unwrap().clone())
            .collect();
        let dir = std::env::temp_dir().join(format!("ea-summary-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cases = [
            ("ascii", "summary_table_fields: [host, {path: user.name, header: User}]\n", include_str!("../tests/golden/summary_ascii.txt")),
            ("markdown", "summary_table_fields: [host, user.name]\nsummary_table_type: markdown\nsummary_table_max_rows: 2\nsummary_prefix: PRE\nsummary_suffix: SUF\n", include_str!("../tests/golden/summary_markdown.txt")),
            ("ascii_rows", "summary_table_fields: host\nsummary_table_max_rows: 3\n", include_str!("../tests/golden/summary_ascii_rows.txt")),
        ];
        let conf = crate::config::Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        for (name, extra, golden) in cases {
            let f = dir.join(format!("{name}.yaml"));
            std::fs::write(&f, format!("name: t\ntype: any\nindex: x\nalert: debug\naggregation: {{minutes: 1}}\n{extra}")).unwrap();
            let rule = crate::rule::load(&f, &conf).unwrap();
            assert_eq!(summary_text(&rule, &matches, 80), golden, "case {name}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn json_like_python() {
        assert_eq!(pretty_json(&json!({"b": [1, 2.0], "a": {}})), "{\n    \"a\": {},\n    \"b\": [\n        1,\n        2.0\n    ]\n}");
    }
}
