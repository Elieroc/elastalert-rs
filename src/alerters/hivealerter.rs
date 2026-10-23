//! `hivealerter`: creates an alert, with observables, in TheHive.

use super::http::Http;
use super::{Doc, View, lookup_field, required};
use crate::alert::{create_alert_body, create_title, py_format};
use crate::field::{py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::time::Duration;

pub struct Hive {
    config: Map<String, Value>,
    mapping: Vec<Map<String, Value>>,
    host: String,
    port: Value,
    api_key: String,
    http: Http,
}

fn obj(rule: &Rule, key: &str) -> Result<Map<String, Value>> {
    match rule.raw.get(key) {
        Some(Value::Object(o)) => Ok(o.clone()),
        _ => bail!("{key} must be a map"),
    }
}

impl Hive {
    pub(super) fn new(rule: &Rule) -> Result<Hive> {
        required(rule, "hivealerter", "hive_connection")?;
        required(rule, "hivealerter", "hive_alert_config")?;
        let conn = obj(rule, "hive_connection")?;
        let mut client = reqwest::Client::builder().timeout(Duration::from_secs(60));
        // `hive_verify` defaults to false, as upstream: TheHive instances are often internal with their own CA.
        match conn.get("hive_verify") {
            Some(Value::String(ca)) => {
                let pem = std::fs::read(ca)?;
                for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
                    client = client.add_root_certificate(cert);
                }
            }
            Some(v) if truthy(Some(v)) => {}
            _ => client = client.danger_accept_invalid_certs(true),
        }
        if let Some(proxies) = conn.get("hive_proxies").and_then(Value::as_object) {
            if let Some(p) = proxies.get("http").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                client = client.proxy(reqwest::Proxy::http(p)?);
            }
            if let Some(p) = proxies.get("https").and_then(Value::as_str).filter(|p| !p.is_empty()) {
                client = client.proxy(reqwest::Proxy::https(p)?);
            }
        }
        Ok(Hive {
            config: obj(rule, "hive_alert_config")?,
            mapping: rule.raw.get("hive_observable_data_mapping").and_then(Value::as_array).into_iter().flatten().filter_map(|m| m.as_object().cloned()).collect(),
            host: conn.get("hive_host").map_or("http://localhost".to_string(), py_str),
            port: conn.get("hive_port").cloned().unwrap_or(json!(9000)),
            api_key: conn.get("hive_apikey").map_or(String::new(), py_str),
            http: Http::from_client(client.build()?),
        })
    }

    /// One observable per mapping entry. Upstream only reads the first key of each mapping (the loop ends with a stray `break`),
    /// so a mapping that starts with `tlp`, `message` or `tags` yields nothing there. Rule maps do not keep their file order,
    /// so the first key that is not one of those three is the observable type: same result whenever the type is written first.
    fn observables(&self, rule: &Rule, m: &Doc) -> Vec<Value> {
        let mut out = vec![];
        for mapping in &self.mapping {
            let Some((kind, key)) = mapping.iter().find(|(k, _)| !matches!(k.as_str(), "tlp" | "message" | "tags")) else { continue };
            let data = py_str(&lookup_field(rule, m, &py_str(key), json!("")));
            if data.is_empty() {
                continue;
            }
            let pick = |k: &str, default: Value| mapping.get(k).filter(|v| !v.is_null()).cloned().unwrap_or(default);
            out.push(json!({"tlp": pick("tlp", json!(2)), "tags": pick("tags", json!([])), "message": pick("message", Value::Null), "dataType": kind, "data": data}));
        }
        out
    }

    fn tags(rule: &Rule, names: &Value, m: &Doc) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for tag in names.as_array().into_iter().flatten() {
            let name = py_str(tag);
            match lookup_field(rule, m, &name, tag.clone()) {
                Value::Array(a) => out.extend(a.iter().map(py_str)),
                other => {
                    out.insert(py_str(&other));
                }
            }
        }
        out
    }

    fn custom_fields(rule: &Rule, raw: &Value, m: &Doc) -> Result<Value> {
        let mut out = Map::new();
        for (position, field) in raw.as_array().into_iter().flatten().enumerate() {
            let (Some(name), Some(kind), Some(value)) = (field.get("name").and_then(Value::as_str), field.get("type").and_then(Value::as_str), field.get("value")) else {
                bail!("hive_alert_config.customFields entries need name, type and value")
            };
            let value = match value {
                Value::String(s) => lookup_field(rule, m, s, value.clone()),
                other => other.clone(),
            };
            out.insert(name.to_string(), json!({"order": position, kind: value}));
        }
        Ok(Value::Object(out))
    }

    /// `<field>` formatted with `<field>_args` taken from the match, the rule, or `<field>_missing_value`.
    fn load_args(&self, rule: &Rule, field: &str, raw: Option<&Value>, m: &Doc) -> Result<Value> {
        let Some(raw) = raw else { bail!("KeyError: '{field}' (hive_alert_config needs it)") };
        let Some(args) = self.config.get(&format!("{field}_args")) else { return Ok(raw.clone()) };
        let missing = self.config.get(&format!("{field}_missing_value")).cloned().unwrap_or(json!("<MISSING VALUE>"));
        let Some(template) = raw.as_str() else { bail!("hive_alert_config.{field} must be a string to be formatted with {field}_args") };
        let values: Vec<String> = args.as_array().into_iter().flatten().map(|a| py_str(&lookup_field(rule, m, &py_str(a), missing.clone()))).collect();
        Ok(json!(py_format(template, &values, &Map::new())))
    }

    fn payload(&self, v: &View<'_>, matches: &[Doc], now_ms: i64) -> Result<Value> {
        let mut cfg = Map::new();
        cfg.insert("artifacts".into(), json!([]));
        cfg.insert("customFields".into(), json!({}));
        cfg.insert("date".into(), json!(now_ms));
        cfg.insert("description".into(), json!(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)));
        cfg.insert("sourceRef".into(), json!(uuid::Uuid::new_v4().to_string()));
        cfg.insert("tags".into(), json!([]));
        cfg.insert("title".into(), json!(create_title(v.rule, matches, || v.rule.name.clone())));
        cfg.extend(self.config.clone());
        let mut tags = BTreeSet::new();
        let mut artifacts = vec![];
        for m in matches {
            artifacts.extend(self.observables(v.rule, m));
            tags.extend(Self::tags(v.rule, &cfg["tags"], m));
        }
        cfg.insert("artifacts".into(), Value::Array(artifacts));
        cfg.insert("tags".into(), json!(tags));
        if let Some(m) = matches.first() {
            let custom = Self::custom_fields(v.rule, &cfg["customFields"], m)?;
            cfg.insert("customFields".into(), custom);
            for field in ["description", "title", "type", "source"] {
                let value = self.load_args(v.rule, field, cfg.get(field), m)?;
                cfg.insert(field.into(), value);
                cfg.remove(&format!("{field}_args"));
            }
        }
        Ok(Value::Object(cfg))
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = self.payload(v, matches, chrono::Utc::now().timestamp() * 1000)?;
        let url = format!("{}:{}/api/alert", self.host, py_str(&self.port));
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Authorization".into(), format!("Bearer {}", self.api_key))];
        self.http.post_json("to TheHive", &url, &headers, &payload).await?;
        log::info!("Alert sent to TheHive");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "hivealerter", "hive_host": self.host})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    const CFG: &str = "hive_connection: {hive_host: http://hive, hive_port: 9000, hive_apikey: key}\nhive_observable_data_mapping:\n- ip: src.ip\n- domain: nothere\n- url: url\n  tlp: 3\n  tags: [web]\n  message: seen\nhive_alert_config:\n  type: 'alert-{0}'\n  type_args: [user]\n  source: elastalert\n  title: 'Title {0}'\n  title_args: [user]\n  tags: [fixed, user, groups]\n  customFields:\n  - {name: who, type: string, value: user}\n  - {name: count, type: integer, value: 3}\n  severity: 2\n";

    fn m() -> Doc {
        json!({"user": "bob", "src": {"ip": "10.0.0.1"}, "url": "http://x", "groups": ["a", "b"]}).as_object().unwrap().clone()
    }

    #[test]
    fn payload_shape() {
        let r = rule("hivealerter", CFG).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let p = Hive::new(&r).unwrap().payload(&v, &[m()], 1_700_000_000_000).unwrap();
        assert_eq!(p["date"], json!(1_700_000_000_000i64));
        assert_eq!(p["type"], json!("alert-bob"));
        assert_eq!(p["title"], json!("Title bob"));
        assert_eq!((&p["source"], &p["severity"]), (&json!("elastalert"), &json!(2)));
        assert!(p.get("type_args").is_none() && p.get("title_args").is_none());
        assert_eq!(p["tags"], json!(["a", "b", "bob", "fixed"]));
        assert_eq!(p["customFields"], json!({"who": {"order": 0, "string": "bob"}, "count": {"order": 1, "integer": 3}}));
        assert_eq!(
            p["artifacts"],
            json!([
                {"tlp": 2, "tags": [], "message": null, "dataType": "ip", "data": "10.0.0.1"},
                {"tlp": 3, "tags": ["web"], "message": "seen", "dataType": "url", "data": "http://x"}
            ])
        );
        assert_eq!(p["sourceRef"].as_str().unwrap().len(), 36);
        assert!(p["description"].as_str().unwrap().starts_with("r\n\n"));
    }

    #[test]
    fn type_and_source_are_needed() {
        let r = rule("hivealerter", "hive_connection: {}\nhive_alert_config: {title: t}\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let err = Hive::new(&r).unwrap().payload(&v, &[m()], 0).unwrap_err();
        assert!(err.to_string().contains("KeyError: 'type'"), "{err}");
    }

    #[tokio::test]
    async fn posts_with_bearer() {
        let (url, got) = capture(1, 201).await;
        let (host, port) = url.rsplit_once(':').unwrap();
        let r = rule("hivealerter", &format!("hive_connection: {{hive_host: '{host}', hive_port: {port}, hive_apikey: key}}\nhive_alert_config: {{type: t, source: s}}\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Hive::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!((got[0].path.as_str(), got[0].header("authorization")), ("/api/alert", Some("Bearer key")));
    }
}
