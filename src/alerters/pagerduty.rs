//! `pagerduty` alerter: Events API v1 (create_event) and v2 (enqueue).

use super::http::Http;
use super::{Doc, View, format_with_args, missing_text, opt, required, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::{lookup, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

const API_BASE_URL: &str = "https://events.pagerduty.com/";

pub struct PagerDuty {
    url: String,
    service_key: Value,
    pub(super) client_name: Value,
    incident_key: String,
    incident_key_args: Option<Vec<Value>>,
    event_type: String,
    v2: bool,
    class: (String, Option<Vec<Value>>),
    component: (String, Option<Vec<Value>>),
    group: (String, Option<Vec<Value>>),
    source: (String, Option<Vec<Value>>),
    severity: Value,
    custom_details: Map<String, Value>,
    include_all_info: bool,
    http: Http,
}

fn args(rule: &Rule, key: &str) -> Option<Vec<Value>> {
    rule.raw.get(key).and_then(Value::as_array).filter(|a| !a.is_empty()).cloned()
}

impl PagerDuty {
    pub(super) fn new(rule: &Rule) -> Result<PagerDuty> {
        required(rule, "pagerduty", "pagerduty_service_key")?;
        required(rule, "pagerduty", "pagerduty_client_name")?;
        if truthy(rule.raw.get("pagerduty_proxy_login")) || truthy(rule.raw.get("pagerduty_proxy_pass")) {
            bail!("pagerduty_proxy_login / pagerduty_proxy_pass (NTLM proxy authentication) are not supported");
        }
        let v2 = s_or(rule, "pagerduty_api_version", "v1") == "v2";
        let pair = |k: &str, default: &str| (s_or(rule, &format!("pagerduty_v2_payload_{k}"), default), args(rule, &format!("pagerduty_v2_payload_{k}_args")));
        Ok(PagerDuty {
            url: if v2 { format!("{API_BASE_URL}v2/enqueue") } else { format!("{API_BASE_URL}generic/2010-04-15/create_event.json") },
            service_key: rule.raw["pagerduty_service_key"].clone(),
            client_name: rule.raw["pagerduty_client_name"].clone(),
            incident_key: s_or(rule, "pagerduty_incident_key", ""),
            incident_key_args: args(rule, "pagerduty_incident_key_args"),
            event_type: s_or(rule, "pagerduty_event_type", "trigger"),
            v2,
            class: pair("class", ""),
            component: pair("component", ""),
            group: pair("group", ""),
            source: pair("source", "ElastAlert"),
            severity: opt(rule, "pagerduty_v2_payload_severity", json!("critical")),
            custom_details: rule.raw.get("pagerduty_v2_payload_custom_details").and_then(Value::as_object).cloned().unwrap_or_default(),
            include_all_info: rule.raw.get("pagerduty_v2_payload_include_all_info").map(|v| truthy(Some(v))).unwrap_or(true),
            http: Http::new(rule, "pagerduty", 60)?,
        })
    }

    fn payload(&self, v: &View<'_>, matches: &[Doc]) -> Value {
        let body = create_alert_body(v.rule, v.rtype, matches, v.ts_fmt);
        let first = &matches[0];
        let missing = missing_text(v.rule);
        let formatted = |(key, key_args): &(String, Option<Vec<Value>>)| match key_args {
            Some(a) => format_with_args(v.rule, key, a, first, missing),
            None => key.clone(),
        };
        let incident_key = match &self.incident_key_args {
            Some(a) => format_with_args(v.rule, &self.incident_key, a, first, missing),
            None => self.incident_key.clone(),
        };
        let title = create_title(v.rule, matches, || v.rule.name.clone());
        if !self.v2 {
            return json!({
                "service_key": self.service_key,
                "description": title,
                "event_type": self.event_type,
                "incident_key": incident_key,
                "client": self.client_name,
                "details": {"information": body},
            });
        }
        let mut details = Map::new();
        if self.include_all_info {
            details.insert("information".into(), json!(body));
        }
        for m in matches {
            for (key, es_key) in &self.custom_details {
                let found = es_key.as_str().and_then(|k| lookup(m, k)).filter(|x| truthy(Some(x)));
                details.insert(key.clone(), found.unwrap_or(es_key).clone());
            }
        }
        let mut payload = json!({
            "routing_key": self.service_key,
            "event_action": self.event_type,
            "dedup_key": incident_key,
            "client": self.client_name,
            "payload": {
                "class": formatted(&self.class),
                "component": formatted(&self.component),
                "group": formatted(&self.group),
                "severity": self.severity,
                "source": formatted(&self.source),
                "summary": title,
                "custom_details": details,
            },
        });
        if let Some(ts) = lookup(first, &v.rule.timestamp_field).filter(|x| truthy(Some(x))) {
            payload["payload"]["timestamp"] = ts.clone();
        }
        payload
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = self.payload(v, matches);
        self.http.post_json("to pagerduty", &self.url, &[], &payload).await?;
        match self.event_type.as_str() {
            "trigger" => log::info!("Trigger sent to PagerDuty"),
            "resolve" => log::info!("Resolve sent to PagerDuty"),
            "acknowledge" => log::info!("acknowledge sent to PagerDuty"),
            _ => {}
        }
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "pagerduty", "pagerduty_client_name": self.client_name})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    fn m() -> Doc {
        json!({"@timestamp": "2021-01-01T00:00:00Z", "somefield": "foobarbaz", "host": {"name": "web-1"}}).as_object().unwrap().clone()
    }

    #[test]
    fn v1_payload_with_incident_key_args() {
        let r = rule(
            "pagerduty",
            "pagerduty_service_key: svc\npagerduty_client_name: ElastAlert\nalert_subject: Subj\npagerduty_incident_key: 'inc {0} {1}'\npagerduty_incident_key_args: [somefield, nope]\n",
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let pd = PagerDuty::new(&r).unwrap();
        assert_eq!(pd.url, "https://events.pagerduty.com/generic/2010-04-15/create_event.json");
        assert_eq!(
            pd.payload(&v, &[m()]),
            json!({
                "service_key": "svc", "description": "Subj", "event_type": "trigger", "incident_key": "inc foobarbaz <MISSING VALUE>",
                "client": "ElastAlert", "details": {"information": "r\n\n@timestamp: 2021-01-01T00:00:00Z\nhost: {\n    \"name\": \"web-1\"\n}\nsomefield: foobarbaz\n"}
            })
        );
    }

    #[test]
    fn v2_payload() {
        let r = rule(
            "pagerduty",
            "pagerduty_service_key: svc\npagerduty_client_name: C\npagerduty_api_version: v2\nalert_subject: Subj\npagerduty_v2_payload_class: 'cls {0}'\npagerduty_v2_payload_class_args: [somefield]\npagerduty_v2_payload_severity: warning\npagerduty_v2_payload_include_all_info: false\npagerduty_v2_payload_custom_details: {h: host.name, c: literal}\n",
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let pd = PagerDuty::new(&r).unwrap();
        assert_eq!(pd.url, "https://events.pagerduty.com/v2/enqueue");
        assert_eq!(
            pd.payload(&v, &[m()]),
            json!({
                "routing_key": "svc", "event_action": "trigger", "dedup_key": "", "client": "C",
                "payload": {"class": "cls foobarbaz", "component": "", "group": "", "severity": "warning", "source": "ElastAlert",
                            "summary": "Subj", "custom_details": {"h": "web-1", "c": "literal"}, "timestamp": "2021-01-01T00:00:00Z"}
            })
        );
    }

    #[test]
    fn ntlm_proxy_is_rejected() {
        let err = PagerDuty::new(&rule("pagerduty", "pagerduty_service_key: s\npagerduty_client_name: c\npagerduty_proxy: http://p\npagerduty_proxy_login: u\npagerduty_proxy_pass: p\n").unwrap()).err().unwrap();
        assert!(err.to_string().contains("NTLM"), "{err}");
    }

    #[tokio::test]
    async fn posts_json() {
        let (url, got) = capture(1, 200).await;
        let r = rule("pagerduty", "pagerduty_service_key: svc\npagerduty_client_name: C\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let mut pd = PagerDuty::new(&r).unwrap();
        pd.url = format!("{url}/generic/2010-04-15/create_event.json");
        pd.alert(&v, &[m()]).await.unwrap();
        assert_eq!(got.await.unwrap()[0].json()["service_key"], json!("svc"));
    }
}
