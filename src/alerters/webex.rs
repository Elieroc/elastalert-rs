//! `webex_webhook` alerter.

use super::http::Http;
use super::{Doc, View, required, s_or};
use crate::alert::create_alert_body;
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Webex {
    url: String,
    msgtype: String,
    http: Http,
}

impl Webex {
    pub(super) fn new(rule: &Rule) -> Result<Webex> {
        required(rule, "webex_webhook", "webex_webhook_id")?;
        Ok(Webex {
            url: format!("https://webexapis.com/v1/webhooks/incoming/{}", py_str(&rule.raw["webex_webhook_id"])),
            msgtype: s_or(rule, "webex_webhook_msgtype", "text"),
            http: Http::new(rule, "webex_webhook", 60)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = create_alert_body(v.rule, v.rtype, matches, v.ts_fmt);
        let payload = if self.msgtype == "markdown" { json!({"markdown": body}) } else { json!({"text": body}) };
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        self.http.post_json("to webex_webhook", &self.url, &headers, &payload).await?;
        log::info!("Trigger sent to webex_webhook");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "webex_webhook", "webex_webhook_msgtype": self.msgtype, "webex_webhook_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn text_and_markdown() {
        for (extra, key) in [("", "text"), ("webex_webhook_msgtype: markdown\n", "markdown")] {
            let (url, got) = capture(1, 200).await;
            let r = rule("webex_webhook", &format!("webex_webhook_id: abc\n{extra}")).unwrap();
            let mut w = Webex::new(&r).unwrap();
            assert_eq!(w.url, "https://webexapis.com/v1/webhooks/incoming/abc");
            w.url = format!("{url}/hook");
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None };
            w.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
            let got = got.await.unwrap();
            assert_eq!(got[0].json(), json!({ key: "r\n\na: 1\n" }));
            assert_eq!(got[0].header("accept"), Some("application/json;charset=utf-8"));
        }
    }
}
