//! `alerta` alerter.

use super::http::Http;
use super::{Doc, View, missing_text, opt, required, resolve_string, resolve_string_with, s, s_or};
use crate::alert::create_alert_body;
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use crate::time;
use anyhow::{Result, bail};
use chrono::TimeZone;
use serde_json::{Value, json};

pub struct Alerta {
    url: String,
    api_key: Option<String>,
    timeout: Value,
    use_match_timestamp: bool,
    use_qk_as_resource: bool,
    severity: String,
    resource: String,
    environment: String,
    origin: String,
    service: Vec<String>,
    text: String,
    kind: Value,
    event: String,
    correlate: Vec<String>,
    tags: Vec<String>,
    group: String,
    attributes_keys: Vec<String>,
    attributes_values: Vec<String>,
    value: String,
    http: Http,
}

fn strings(rule: &Rule, key: &str, default: &[&str]) -> Vec<String> {
    match rule.raw.get(key) {
        Some(Value::Array(a)) => a.iter().map(py_str).collect(),
        Some(Value::Null) | None => default.iter().map(|s| s.to_string()).collect(),
        Some(other) => vec![py_str(other)],
    }
}

fn stamp(ts: time::Ts) -> String {
    chrono::Utc.timestamp_micros(ts).single().unwrap_or_default().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

impl Alerta {
    pub(super) fn new(rule: &Rule) -> Result<Alerta> {
        required(rule, "alerta", "alerta_api_url")?;
        let skip_ssl = rule.raw.get("alerta_api_skip_ssl").is_some_and(|v| truthy(Some(v)));
        Ok(Alerta {
            url: s(rule, "alerta_api_url").unwrap_or_default(),
            api_key: s(rule, "alerta_api_key"),
            timeout: opt(rule, "alerta_timeout", json!(86400)),
            use_match_timestamp: rule.raw.get("alerta_use_match_timestamp").is_some_and(|v| truthy(Some(v))),
            use_qk_as_resource: rule.raw.get("alerta_use_qk_as_resource").is_some_and(|v| truthy(Some(v))),
            severity: s_or(rule, "alerta_severity", "warning"),
            resource: s_or(rule, "alerta_resource", "elastalert"),
            environment: s_or(rule, "alerta_environment", "Production"),
            origin: s_or(rule, "alerta_origin", "elastalert"),
            service: strings(rule, "alerta_service", &["elastalert"]),
            text: s_or(rule, "alerta_text", "elastalert"),
            kind: opt(rule, "alerta_type", json!("elastalert")),
            event: s_or(rule, "alerta_event", "elastalert"),
            correlate: strings(rule, "alerta_correlate", &[]),
            tags: strings(rule, "alerta_tags", &[]),
            group: s_or(rule, "alerta_group", ""),
            attributes_keys: strings(rule, "alerta_attributes_keys", &[]),
            attributes_values: strings(rule, "alerta_attributes_values", &[]),
            value: s_or(rule, "alerta_value", ""),
            // `alerta_timeout` is the alert's lifetime, not an HTTP timeout, so no prefix-based options here.
            http: Http::raw(None, None, skip_ssl, 60)?,
        })
    }

    /// The Create Alert body; references to match fields in the options are resolved against the first match.
    fn payload(&self, v: &View<'_>, matches: &[Doc], now: time::Ts) -> Result<Value> {
        let m = &matches[0];
        let missing = missing_text(v.rule);
        let r = |text: &str| resolve_string_with(text, m, missing);
        // Upstream overwrites its stored resource with the query key value the first time this applies; here it is per alert.
        let qk_value = v.rule.query_key.as_deref().and_then(|qk| lookup(m, qk)).filter(|x| truthy(Some(x)));
        let resource = match qk_value {
            Some(x) if self.use_qk_as_resource => py_str(x),
            _ => self.resource.clone(),
        };
        let default_title = || {
            let mut t = v.rule.name.clone();
            if let Some(qk) = v.rule.query_key.as_ref().and_then(|qk| m.get(qk)).filter(|x| truthy(Some(x))) {
                t.push_str(&format!(".{}", py_str(qk)));
            }
            t
        };
        let text = if self.text.is_empty() { v.rtype.match_str(v.rule, m, v.ts_fmt) } else { r(&self.text) };
        let event = if self.event.is_empty() { default_title() } else { r(&self.event) };
        let create_time = if self.use_match_timestamp {
            let raw = lookup(m, &v.rule.timestamp_field).filter(|x| !x.is_null());
            match raw {
                Some(x) => match time::parse_iso(&py_str(x)) {
                    Some(ts) => stamp(ts),
                    None => bail!("Error building Alerta request: cannot parse timestamp {x}"),
                },
                None => stamp(now),
            }
        } else {
            stamp(now)
        };
        let attributes: serde_json::Map<String, Value> = self.attributes_keys.iter().zip(&self.attributes_values).map(|(k, val)| (k.clone(), json!(r(val)))).collect();
        Ok(json!({
            "resource": r(&resource),
            "severity": resolve_string(&self.severity, m),
            "timeout": self.timeout,
            "createTime": create_time,
            "type": self.kind,
            "environment": r(&self.environment),
            "origin": r(&self.origin),
            "group": r(&self.group),
            "event": event,
            "text": text,
            "value": r(&self.value),
            "service": self.service.iter().map(|x| r(x)).collect::<Vec<_>>(),
            "tags": self.tags.iter().map(|x| r(x)).collect::<Vec<_>>(),
            "correlate": self.correlate.iter().map(|x| r(x)).collect::<Vec<_>>(),
            "attributes": attributes,
            "rawData": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt),
        }))
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = self.payload(v, matches, time::now())?;
        let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
        if let Some(k) = &self.api_key {
            headers.push(("Authorization".into(), format!("Key {k}")));
        }
        self.http.post_json("to Alerta", &self.url, &headers, &payload).await?;
        log::info!("Alert sent to Alerta");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "alerta", "alerta_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;
    use crate::types::RuleType;

    #[test]
    fn payload_resolves_fields() {
        let r = rule(
            "alerta",
            "alerta_api_url: http://a\nquery_key: host\nalerta_resource: 'res-{host}'\nalerta_severity: critical\nalerta_event: 'ev %(host)s {nope}'\nalerta_service: ['svc-{host}']\nalerta_tags: [t1]\nalerta_attributes_keys: [k]\nalerta_attributes_values: ['v-{host}']\nalerta_use_match_timestamp: true\nalerta_timeout: 3600\n",
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        let m = json!({"@timestamp": "2021-01-01T00:00:00Z", "host": "web-1"}).as_object().unwrap().clone();
        let p = Alerta::new(&r).unwrap().payload(&v, &[m], 1_700_000_000_000_000).unwrap();
        assert_eq!(p["resource"], json!("res-web-1"));
        assert_eq!(p["event"], json!("ev web-1 <MISSING VALUE>"));
        assert_eq!(p["createTime"], json!("2021-01-01T00:00:00.000000Z"));
        assert_eq!(p["timeout"], json!(3600));
        assert_eq!((&p["service"], &p["tags"], &p["attributes"], &p["severity"]), (&json!(["svc-web-1"]), &json!(["t1"]), &json!({"k": "v-web-1"}), &json!("critical")));
        assert_eq!((&p["type"], &p["environment"], &p["origin"], &p["text"]), (&json!("elastalert"), &json!("Production"), &json!("elastalert"), &json!("elastalert")));
    }

    #[test]
    fn query_key_as_resource_and_default_event() {
        let r = rule("alerta", "alerta_api_url: http://a\nquery_key: host\nalerta_use_qk_as_resource: true\nalerta_event: ''\nalerta_text: ''\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        let m = json!({"host": "web-1", "x": 1}).as_object().unwrap().clone();
        let a = Alerta::new(&r).unwrap();
        let p = a.payload(&v, &[m.clone()], 0).unwrap();
        assert_eq!((&p["resource"], &p["event"]), (&json!("web-1"), &json!("r.web-1")));
        // an empty `alerta_text` means the rule type's own match text
        assert_eq!(p["text"], json!(rt.match_str(&r, &m, None)));
        assert_eq!(p["createTime"], json!("1970-01-01T00:00:00.000000Z"));
    }
}
