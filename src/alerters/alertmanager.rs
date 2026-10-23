//! `alertmanager` alerter.

use super::http::Http;
use super::{Doc, View, list, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::lookup;
use crate::rule::Rule;
use crate::time;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

pub struct Alertmanager {
    api_version: String,
    hosts: Vec<String>,
    alertname: String,
    labels: Map<String, Value>,
    annotations: Map<String, Value>,
    fields: Map<String, Value>,
    title_labelname: String,
    body_labelname: String,
    resolve_timeout: Option<time::Dur>,
    root_name: Option<String>,
    http: Http,
}

/// `json.dumps(value)` as Python prints it: `", "` and `": "` separators, non-ASCII escaped.
pub(super) fn py_json_dumps(v: &Value) -> String {
    match v {
        Value::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            out.push_str(&format!("\\u{unit:04x}"));
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        Value::Array(a) => format!("[{}]", a.iter().map(py_json_dumps).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!("{{{}}}", o.iter().map(|(k, x)| format!("{}: {}", py_json_dumps(&json!(k)), py_json_dumps(x))).collect::<Vec<_>>().join(", ")),
        other => other.to_string(),
    }
}

fn render_all(templates: &Map<String, Value>, context: &Value) -> Result<Map<String, Value>> {
    let env = minijinja::Environment::new();
    let mut out = Map::new();
    for (key, template) in templates {
        let Some(source) = template.as_str() else { bail!("Alertmanager: the template provided by key '{key}' must be a string") };
        let rendered = env.render_str(source, minijinja::value::Serde(context.clone())).map_err(|e| {
            if e.kind() == minijinja::ErrorKind::SyntaxError {
                anyhow::anyhow!("Alertmanager: The template provided by key '{key}' has an invalid Jinja2 syntax. Please check your template syntax: {e}")
            } else {
                anyhow::anyhow!("Alertmanager: rendering the template provided by key '{key}' failed: {e}")
            }
        })?;
        out.insert(key.clone(), json!(rendered));
    }
    Ok(out)
}

fn obj(rule: &Rule, key: &str) -> Map<String, Value> {
    rule.raw.get(key).and_then(Value::as_object).cloned().unwrap_or_default()
}

impl Alertmanager {
    pub(super) fn new(rule: &Rule) -> Result<Alertmanager> {
        required(rule, "alertmanager", "alertmanager_hosts")?;
        let mut http = Http::new(rule, "alertmanager", 10)?;
        if let Some(login) = s(rule, "alertmanager_basic_auth_login").filter(|l| !l.is_empty()) {
            http = http.with_basic_auth(login, s(rule, "alertmanager_basic_auth_password").unwrap_or_default());
        }
        Ok(Alertmanager {
            api_version: s_or(rule, "alertmanager_api_version", "v1"),
            hosts: list(rule, "alertmanager_hosts"),
            alertname: s(rule, "alertmanager_alertname").unwrap_or_else(|| rule.name.clone()),
            labels: obj(rule, "alertmanager_labels"),
            annotations: obj(rule, "alertmanager_annotations"),
            fields: obj(rule, "alertmanager_fields"),
            title_labelname: s_or(rule, "alertmanager_alert_subject_labelname", "summary"),
            body_labelname: s_or(rule, "alertmanager_alert_text_labelname", "description"),
            resolve_timeout: rule.raw.get("alertmanager_resolve_time").map(time::parse_duration_map).transpose()?,
            root_name: s(rule, "jinja_root_name"),
            http,
        })
    }

    fn payload(&self, v: &View<'_>, matches: &[Doc], now: time::Ts) -> Result<Value> {
        let first = &matches[0];
        let mut context = first.clone();
        if let Some(root) = &self.root_name {
            context.insert(root.clone(), Value::Object(first.clone()));
        }
        let context = Value::Object(context);
        let mut labels = render_all(&self.labels, &context)?;
        for (label, term) in &self.fields {
            let value = term.as_str().and_then(|t| lookup(first, t)).cloned().unwrap_or(Value::Null);
            labels.insert(label.clone(), json!(match &value { Value::String(s) => s.clone(), other => py_json_dumps(other) }));
        }
        labels.insert("alertname".into(), json!(self.alertname));
        labels.insert("elastalert_rule".into(), json!(v.rule.name));
        let mut annotations = render_all(&self.annotations, &context)?;
        annotations.insert(self.title_labelname.clone(), json!(create_title(v.rule, matches, || v.rule.name.clone())));
        annotations.insert(self.body_labelname.clone(), json!(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)));
        let mut payload = json!({"annotations": annotations, "labels": labels});
        if let Some(d) = self.resolve_timeout {
            payload["endsAt"] = json!(isoformat(now + d));
        }
        Ok(payload)
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = Value::Array(vec![self.payload(v, matches, time::now())?]);
        for host in &self.hosts {
            let url = format!("{host}/api/{}/alerts", self.api_version);
            self.http.post_json("to Alertmanager", &url, &[], &payload).await?;
        }
        log::info!("Alert sent to Alertmanager");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "alertmanager"})
    }
}

/// Python's `datetime.isoformat()` for an aware UTC datetime.
fn isoformat(ts: time::Ts) -> String {
    use chrono::TimeZone;
    let dt = chrono::Utc.timestamp_micros(ts).single().unwrap_or_default();
    let frac = if ts.rem_euclid(1_000_000) == 0 { String::new() } else { dt.format("%.6f").to_string() };
    format!("{}{frac}+00:00", dt.format("%Y-%m-%dT%H:%M:%S"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    fn m() -> Doc {
        json!({"host": {"name": "web-1"}, "n": 3, "tags": ["a", "é"], "msg": "hi"}).as_object().unwrap().clone()
    }

    #[test]
    fn python_json_spacing_and_escapes() {
        assert_eq!(py_json_dumps(&json!({"a": [1, "é", null], "b": true})), r#"{"a": [1, "\u00e9", null], "b": true}"#);
        assert_eq!(py_json_dumps(&Value::Null), "null");
        assert_eq!(isoformat(1_700_000_000_000_000), "2023-11-14T22:13:20+00:00");
        assert_eq!(isoformat(1_700_000_000_123_456), "2023-11-14T22:13:20.123456+00:00");
    }

    #[test]
    fn labels_annotations_and_end_time() {
        let r = rule(
            "alertmanager",
            "alertmanager_hosts: ['http://am']\nalertmanager_alertname: Custom\nalert_subject: Subj\nalertmanager_labels: {env: 'prod-{{ host.name }}', root: '{{ r.msg }}'}\nalertmanager_annotations: {note: 'n={{ n }}'}\nalertmanager_fields: {tags: tags, missing: nothere, msg: msg}\nalertmanager_resolve_time: {minutes: 5}\njinja_root_name: r\n",
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        let p = Alertmanager::new(&r).unwrap().payload(&v, &[m()], 1_700_000_000_000_000).unwrap();
        assert_eq!(
            p["labels"],
            json!({"env": "prod-web-1", "root": "hi", "tags": "[\"a\", \"\\u00e9\"]", "missing": "null", "msg": "hi", "alertname": "Custom", "elastalert_rule": "r"})
        );
        assert_eq!(p["annotations"], json!({"note": "n=3", "summary": "Subj", "description": p["annotations"]["description"]}));
        assert!(p["annotations"]["description"].as_str().unwrap().starts_with("r\n\n"));
        assert_eq!(p["endsAt"], json!("2023-11-14T22:18:20+00:00"));
    }

    #[test]
    fn bad_template_syntax() {
        let r = rule("alertmanager", "alertmanager_hosts: ['http://am']\nalertmanager_labels: {a: '{{ oops'}\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        let err = Alertmanager::new(&r).unwrap().payload(&v, &[m()], 0).unwrap_err();
        assert!(err.to_string().contains("invalid Jinja2 syntax"), "{err}");
    }

    #[tokio::test]
    async fn posts_array_with_basic_auth_to_each_host() {
        let (a, got_a) = capture(1, 200).await;
        let (b, got_b) = capture(1, 200).await;
        let r = rule("alertmanager", &format!("alertmanager_hosts: ['{a}', '{b}']\nalertmanager_api_version: v2\nalertmanager_basic_auth_login: u\nalertmanager_basic_auth_password: p\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        Alertmanager::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let (ga, gb) = (got_a.await.unwrap(), got_b.await.unwrap());
        assert_eq!(ga[0].path, "/api/v2/alerts");
        assert_eq!(gb[0].path, "/api/v2/alerts");
        assert_eq!(ga[0].header("authorization"), Some("Basic dTpw"));
        assert!(ga[0].json().is_array());
    }
}
