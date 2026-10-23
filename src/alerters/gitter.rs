//! `gitter` alerter.

use super::http::Http;
use super::{Doc, View, required, s, s_or};
use crate::alert::create_alert_body;
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct Gitter {
    url: String,
    level: String,
    http: Http,
}

impl Gitter {
    pub(super) fn new(rule: &Rule) -> Result<Gitter> {
        required(rule, "gitter", "gitter_webhook_url")?;
        let Some(url) = s(rule, "gitter_webhook_url") else { bail!("gitter_webhook_url must be a single URL string") };
        Ok(Gitter { url, level: s_or(rule, "gitter_msg_level", "error"), http: Http::new(rule, "gitter", 60)? })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = json!({"message": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt), "level": self.level});
        self.http.post_json("to Gitter", &self.url, &[], &payload).await?;
        log::info!("Alert sent to Gitter");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "gitter", "gitter_webhook_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn payload() {
        let (url, got) = capture(1, 200).await;
        let r = rule("gitter", &format!("gitter_webhook_url: {url}\ngitter_msg_level: info\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Gitter::new(&r).unwrap().alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        assert_eq!(got.await.unwrap()[0].json(), json!({"message": "r\n\na: 1\n", "level": "info"}));
    }
}
