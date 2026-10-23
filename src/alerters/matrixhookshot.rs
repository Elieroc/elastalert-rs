//! `matrixhookshot` alerter.

use super::http::Http;
use super::{Doc, View, list, required, s_or};
use crate::alert::create_alert_body_with;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct MatrixHookshot {
    urls: Vec<String>,
    username: String,
    text: String,
    html: String,
    http: Http,
}

impl MatrixHookshot {
    pub(super) fn new(rule: &Rule) -> Result<MatrixHookshot> {
        required(rule, "matrixhookshot", "matrixhookshot_webhook_url")?;
        Ok(MatrixHookshot {
            urls: list(rule, "matrixhookshot_webhook_url"),
            username: s_or(rule, "matrixhookshot_username", ""),
            text: s_or(rule, "matrixhookshot_text", ""),
            html: s_or(rule, "matrixhookshot_html", ""),
            http: Http::new(rule, "matrixhookshot", 10)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let mut payload = json!({"text": create_alert_body_with(v.rule, v.rtype, matches, v.ts_fmt, 75, true)});
        if !self.username.is_empty() {
            payload["username"] = json!(self.username);
        }
        if !self.html.is_empty() {
            payload["html"] = json!(self.html);
        }
        if !self.text.is_empty() {
            payload["text"] = json!(self.text);
        }
        for url in &self.urls {
            self.http.post_json("to matrixhookshot", url, &[], &payload).await?;
        }
        log::info!("Alert '{}' sent to MatrixHookshot", v.rule.name);
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "matrixhookshot"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn body_and_overrides() {
        let (url, got) = capture(2, 200).await;
        for extra in ["", "matrixhookshot_username: bot\nmatrixhookshot_html: <b>x</b>\nmatrixhookshot_text: fixed\n"] {
            let r = rule("matrixhookshot", &format!("matrixhookshot_webhook_url: {url}\n{extra}")).unwrap();
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None };
            MatrixHookshot::new(&r).unwrap().alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        }
        let got = got.await.unwrap();
        assert_eq!(got[0].json(), json!({"text": "r\n\na: 1\n"}));
        assert_eq!(got[1].json(), json!({"text": "fixed", "username": "bot", "html": "<b>x</b>"}));
    }
}
