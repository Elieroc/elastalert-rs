//! `lark` (Feishu) alerter.

use super::http::Http;
use super::{Doc, View, required, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Lark {
    url: String,
    msg_type: String,
    http: Http,
}

impl Lark {
    pub(super) fn new(rule: &Rule) -> Result<Lark> {
        required(rule, "lark", "lark_bot_id")?;
        Ok(Lark {
            url: format!("https://open.feishu.cn/open-apis/bot/v2/hook/{}", py_str(&rule.raw["lark_bot_id"])),
            msg_type: s_or(rule, "lark_msgtype", "text"),
            http: Http::new(rule, "lark", 60)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = json!({
            "msg_type": self.msg_type,
            "content": {"title": create_title(v.rule, matches, || v.rule.name.clone()), "text": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)},
        });
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        self.http.post_json("to lark", &self.url, &headers, &payload).await?;
        log::info!("Trigger sent to lark");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "lark", "lark_webhook_url": self.url})
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
        let r = rule("lark", "lark_bot_id: bot1\nalert_subject: S\n").unwrap();
        let mut l = Lark::new(&r).unwrap();
        assert_eq!(l.url, "https://open.feishu.cn/open-apis/bot/v2/hook/bot1");
        l.url = format!("{url}/hook");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        l.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        assert_eq!(got.await.unwrap()[0].json(), json!({"msg_type": "text", "content": {"title": "S", "text": "r\n\na: 1\n"}}));
    }
}
