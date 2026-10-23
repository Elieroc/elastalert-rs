//! `servicenow` alerter: creates a record through the Table API.

use super::http::Http;
use super::{Doc, View, opt, required, s};
use crate::alert::match_body;
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

const REQUIRED: [&str; 10] = ["username", "password", "servicenow_rest_url", "short_description", "comments", "assignment_group", "category", "subcategory", "cmdb_ci", "caller_id"];

pub struct ServiceNow {
    url: String,
    fields: Map<String, Value>,
    impact: Value,
    urgency: Value,
    additional: Map<String, Value>,
    http: Http,
}

impl ServiceNow {
    pub(super) fn new(rule: &Rule) -> Result<ServiceNow> {
        for k in REQUIRED {
            required(rule, "servicenow", k)?;
        }
        let Some(url) = s(rule, "servicenow_rest_url") else { bail!("servicenow_rest_url must be a string") };
        let user = s(rule, "username").unwrap_or_default();
        let password = s(rule, "password").unwrap_or_default();
        Ok(ServiceNow {
            url,
            fields: ["short_description", "comments", "assignment_group", "category", "subcategory", "cmdb_ci", "caller_id"].into_iter().map(|k| (k.to_string(), rule.raw[k].clone())).collect(),
            impact: opt(rule, "servicenow_impact", Value::Null),
            urgency: opt(rule, "servicenow_urgency", Value::Null),
            additional: rule.raw.get("service_now_additional_fields").and_then(Value::as_object).cloned().unwrap_or_default(),
            http: Http::new(rule, "servicenow", 60)?.with_basic_auth(user, password),
        })
    }

    fn payload(&self, v: &View<'_>, matches: &[Doc]) -> Value {
        // Upstream loops over the matches and keeps only the last description.
        let description = matches.last().map(|m| match_body(v.rule, v.rtype, m, v.ts_fmt)).unwrap_or_default();
        let mut payload = self.fields.clone();
        payload.insert("description".into(), json!(description));
        if !self.impact.is_null() {
            payload.insert("impact".into(), self.impact.clone());
        }
        if !self.urgency.is_null() {
            payload.insert("urgency".into(), self.urgency.clone());
        }
        payload.extend(self.additional.clone());
        Value::Object(payload)
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        self.http.post_json("to ServiceNow", &self.url, &headers, &self.payload(v, matches)).await?;
        log::info!("Alert sent to ServiceNow");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "ServiceNow", "self.servicenow_rest_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    const BASE: &str = "username: u\npassword: p\nshort_description: sd\ncomments: c\nassignment_group: g\ncategory: cat\nsubcategory: sub\ncmdb_ci: ci\ncaller_id: me\n";

    #[tokio::test]
    async fn payload_auth_and_last_match() {
        let (url, got) = capture(1, 200).await;
        let r = rule("servicenow", &format!("{BASE}servicenow_rest_url: {url}/api/now/table/incident\nservicenow_impact: 2\nservice_now_additional_fields: {{u_extra: x}}\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let (a, b) = (json!({"n": 1}).as_object().unwrap().clone(), json!({"n": 2}).as_object().unwrap().clone());
        ServiceNow::new(&r).unwrap().alert(&v, &[a, b]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].header("authorization"), Some("Basic dTpw"));
        assert_eq!(
            got[0].json(),
            json!({"description": "r\n\nn: 2\n", "short_description": "sd", "comments": "c", "assignment_group": "g", "category": "cat",
                   "subcategory": "sub", "cmdb_ci": "ci", "caller_id": "me", "impact": 2, "u_extra": "x"})
        );
    }

    #[test]
    fn missing_option_is_rejected() {
        assert!(ServiceNow::new(&rule("servicenow", "servicenow_rest_url: http://x\n").unwrap()).is_err());
    }
}
