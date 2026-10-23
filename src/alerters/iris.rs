//! `iris` (DFIR-IRIS) alerter: creates an alert, or a case with its IOCs.

use super::http::Http;
use super::{Doc, View, lookup_field, opt, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use reqwest::Method;
use serde_json::{Map, Value, json};

pub struct Iris {
    url: String,
    headers: Vec<(String, String)>,
    customer_id: Value,
    description: Option<String>,
    overwrite_timestamp: bool,
    case: bool,
    case_template_id: Value,
    note: Value,
    source: Value,
    tags: Value,
    status_id: Value,
    source_link: Value,
    severity_id: Value,
    context: Option<Map<String, Value>>,
    iocs: Option<Vec<Value>>,
    http: Http,
}

impl Iris {
    pub(super) fn new(rule: &Rule) -> Result<Iris> {
        required(rule, "iris", "iris_host")?;
        required(rule, "iris", "iris_api_token")?;
        let kind = s_or(rule, "iris_type", "alert");
        // Upstream does nothing at all when the type contains neither word.
        if !kind.contains("alert") && !kind.contains("case") {
            bail!("iris_type must be alert or case, got {kind:?}");
        }
        let ignore = rule.raw.get("iris_ignore_ssl_errors").is_some_and(|v| truthy(Some(v)));
        Ok(Iris {
            url: format!("https://{}", py_str(&rule.raw["iris_host"])),
            headers: vec![("Content-Type".into(), "application/json".into()), ("Authorization".into(), format!("Bearer {}", py_str(&rule.raw["iris_api_token"])))],
            customer_id: opt(rule, "iris_customer_id", json!(1)),
            description: s(rule, "iris_description").filter(|d| !d.is_empty()),
            overwrite_timestamp: rule.raw.get("iris_overwrite_timestamp").is_some_and(|v| truthy(Some(v))),
            case: !kind.contains("alert"),
            case_template_id: opt(rule, "iris_case_template_id", Value::Null),
            note: opt(rule, "iris_alert_note", Value::Null),
            source: opt(rule, "iris_alert_source", json!("ElastAlert2")),
            tags: opt(rule, "iris_alert_tags", Value::Null),
            status_id: opt(rule, "iris_alert_status_id", json!(2)),
            source_link: opt(rule, "iris_alert_source_link", Value::Null),
            severity_id: opt(rule, "iris_alert_severity_id", json!(1)),
            context: rule.raw.get("iris_alert_context").and_then(Value::as_object).filter(|c| !c.is_empty()).cloned(),
            iocs: rule.raw.get("iris_iocs").and_then(Value::as_array).filter(|c| !c.is_empty()).cloned(),
            http: Http::raw(None, s(rule, "iris_ca_cert").as_deref(), ignore, 60)?,
        })
    }

    fn iocs(&self, iocs: &[Value], first: &Doc) -> Vec<Value> {
        iocs.iter()
            .filter_map(|record| {
                let mut r = record.clone();
                let value = record.get("ioc_value").and_then(Value::as_str).and_then(|k| lookup(first, k)).filter(|v| !v.is_null())?.clone();
                r["ioc_value"] = value;
                Some(r)
            })
            .collect()
    }

    fn alert_data(&self, v: &View<'_>, matches: &[Doc], now_local: String) -> Value {
        let first = &matches[0];
        let event_time = if self.overwrite_timestamp { first.get("@timestamp").cloned().unwrap_or(Value::Null) } else { json!(now_local) };
        let mut data = json!({
            "alert_title": create_title(v.rule, matches, || v.rule.name.clone()),
            "alert_description": self.description.clone().unwrap_or_else(|| create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)),
            "alert_source": self.source,
            "alert_severity_id": self.severity_id,
            "alert_status_id": self.status_id,
            "alert_source_event_time": event_time,
            "alert_note": self.note,
            "alert_tags": self.tags,
            "alert_customer_id": self.customer_id,
        });
        if truthy(Some(&self.source_link)) {
            data["alert_source_link"] = self.source_link.clone();
        }
        if let Some(iocs) = &self.iocs {
            data["alert_iocs"] = Value::Array(self.iocs(iocs, first));
        }
        if let Some(ctx) = &self.context {
            let rendered: Map<String, Value> = ctx.iter().map(|(k, f)| (k.clone(), json!(py_str(&lookup_field(v.rule, first, &py_str(f), json!("")))))).collect();
            data["alert_context"] = Value::Object(rendered);
        }
        data
    }

    fn case_data(&self, v: &View<'_>) -> Value {
        let mut data = json!({
            "case_soc_id": format!("SOC_{}", &uuid::Uuid::new_v4().to_string()[..6]),
            "case_customer": self.customer_id,
            "case_name": v.rule.name,
            "case_description": self.description,
        });
        if truthy(Some(&self.case_template_id)) {
            data["case_template_id"] = self.case_template_id.clone();
        }
        data
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        if !self.case {
            let data = self.alert_data(v, matches, chrono::Local::now().format("%Y-%m-%dT%H:%M:%S").to_string());
            let resp = self.http.request(Method::POST, "posting alert to Iris", &format!("{}/alerts/add", self.url), &self.headers, Some(&data)).await?;
            if resp.status().as_u16() != 200 {
                bail!("Cannot create a new alert: {}", resp.status().as_u16());
            }
            log::info!("Alert sent to Iris");
            return Ok(());
        }
        let case = self.case_data(v);
        let iocs = self.iocs.as_ref().map(|i| self.iocs(i, &matches[0])).unwrap_or_default();
        let resp = self.http.request(Method::POST, "posting the case to Iris", &format!("{}/manage/cases/add", self.url), &self.headers, Some(&case)).await?;
        if resp.status().as_u16() != 200 {
            bail!("Cannot create a new case: {}", resp.status().as_u16());
        }
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        let case_id = body["data"]["case_id"].clone();
        for mut ioc in iocs {
            ioc["cid"] = case_id.clone();
            let resp = self.http.request(Method::POST, &format!("when adding IOC to the case {}", py_str(&case_id)), &format!("{}/case/ioc/add", self.url), &self.headers, Some(&ioc)).await?;
            if resp.status().as_u16() != 200 {
                bail!("Unable to add a new IOC to the case {}", py_str(&case_id));
            }
            log::info!("IOCs successfully added to the case");
        }
        log::info!("Case successfully created in Iris");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "IrisAlerter", "iris_api_endpoint": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    fn m() -> Doc {
        json!({"@timestamp": "2024-01-01T00:00:00Z", "src": {"ip": "10.0.0.1"}, "user": "bob"}).as_object().unwrap().clone()
    }

    #[test]
    fn alert_payload() {
        let r = rule(
            "iris",
            "iris_host: iris.local\niris_api_token: tok\nalert_subject: Subj\niris_alert_tags: a,b\niris_alert_source_link: http://src\niris_overwrite_timestamp: true\niris_alert_context: {who: user, absent: nothere}\niris_iocs:\n- {ioc_value: src.ip, ioc_type_id: 76}\n- {ioc_value: gone, ioc_type_id: 1}\n",
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let d = Iris::new(&r).unwrap().alert_data(&v, &[m()], "NOW".into());
        assert_eq!(
            d,
            json!({
                "alert_title": "Subj", "alert_description": "r\n\n@timestamp: 2024-01-01T00:00:00Z\nsrc: {\n    \"ip\": \"10.0.0.1\"\n}\nuser: bob\n",
                "alert_source": "ElastAlert2", "alert_severity_id": 1, "alert_status_id": 2, "alert_source_event_time": "2024-01-01T00:00:00Z",
                "alert_note": null, "alert_tags": "a,b", "alert_customer_id": 1, "alert_source_link": "http://src",
                "alert_iocs": [{"ioc_value": "10.0.0.1", "ioc_type_id": 76}], "alert_context": {"who": "bob", "absent": ""}
            })
        );
    }

    #[tokio::test]
    async fn alert_requires_status_200() {
        for (status, ok) in [(200, true), (201, false)] {
            let (url, got) = capture(1, status).await;
            let r = rule("iris", "iris_host: x\niris_api_token: tok\n").unwrap();
            let mut iris = Iris::new(&r).unwrap();
            iris.url = url;
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
            assert_eq!(iris.alert(&v, &[m()]).await.is_ok(), ok);
            let got = got.await.unwrap();
            assert_eq!((got[0].path.as_str(), got[0].header("authorization")), ("/alerts/add", Some("Bearer tok")));
        }
    }

    #[tokio::test]
    async fn case_with_iocs() {
        // one listener answers three requests: case add (returns the id), then one IOC
        let (url, got) = capture(2, 200).await;
        let r = rule("iris", "iris_host: x\niris_api_token: tok\niris_type: case\niris_description: d\niris_case_template_id: 7\niris_iocs: [{ioc_value: src.ip, ioc_type_id: 76}]\n").unwrap();
        let mut iris = Iris::new(&r).unwrap();
        iris.url = url;
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        iris.alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].path, "/manage/cases/add");
        let case = got[0].json();
        assert!(case["case_soc_id"].as_str().unwrap().starts_with("SOC_") && case["case_soc_id"].as_str().unwrap().len() == 10);
        assert_eq!((&case["case_name"], &case["case_description"], &case["case_template_id"], &case["case_customer"]), (&json!("r"), &json!("d"), &json!(7), &json!(1)));
        assert_eq!(got[1].path, "/case/ioc/add");
        assert_eq!(got[1].json(), json!({"ioc_value": "10.0.0.1", "ioc_type_id": 76, "cid": null}));
    }

    #[test]
    fn unknown_type_is_rejected() {
        assert!(Iris::new(&rule("iris", "iris_host: x\niris_api_token: t\niris_type: ticket\n").unwrap()).is_err());
    }
}
