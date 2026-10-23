//! `datadog` alerter: posts an event.

use super::http::Http;
use super::{Doc, View, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Datadog {
    url: String,
    api_key: String,
    app_key: String,
    http: Http,
}

impl Datadog {
    pub(super) fn new(rule: &Rule) -> Result<Datadog> {
        required(rule, "datadog", "datadog_api_key")?;
        required(rule, "datadog", "datadog_app_key")?;
        Ok(Datadog {
            url: s_or(rule, "datadog_api_url", "https://api.datadoghq.com/api/v1/events"),
            api_key: s(rule, "datadog_api_key").unwrap_or_default(),
            app_key: s(rule, "datadog_app_key").unwrap_or_default(),
            http: Http::raw(None, None, false, 60)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let headers = [
            ("Content-Type".to_string(), "application/json".to_string()),
            ("DD-API-KEY".into(), self.api_key.clone()),
            ("DD-APPLICATION-KEY".into(), self.app_key.clone()),
        ];
        let payload = json!({"title": create_title(v.rule, matches, || v.rule.name.clone()), "text": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)});
        self.http.post_json("event to Datadog", &self.url, &headers, &payload).await?;
        log::info!("Alert sent to Datadog");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "datadog"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn event() {
        let (url, got) = capture(1, 200).await;
        let r = rule("datadog", &format!("datadog_api_key: k1\ndatadog_app_key: k2\ndatadog_api_url: {url}/events\nalert_subject: S\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Datadog::new(&r).unwrap().alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!((got[0].header("dd-api-key"), got[0].header("dd-application-key")), (Some("k1"), Some("k2")));
        assert_eq!(got[0].json(), json!({"title": "S", "text": "r\n\na: 1\n"}));
    }
}
