//! `workwechat` alerter.

use super::http::Http;
use super::{Doc, View, required, s_or};
use crate::alert::create_alert_body;
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct WorkWechat {
    url: String,
    msg_type: String,
    http: Http,
}

impl WorkWechat {
    pub(super) fn new(rule: &Rule) -> Result<WorkWechat> {
        required(rule, "workwechat", "work_wechat_bot_id")?;
        let msg_type = s_or(rule, "work_wechat_msgtype", "text");
        // Upstream has no payload for other types and fails at send time with an unbound variable.
        if msg_type != "text" && msg_type != "markdown" {
            bail!("work_wechat_msgtype must be text or markdown, got {msg_type:?}");
        }
        Ok(WorkWechat {
            url: format!("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={}", py_str(&rule.raw["work_wechat_bot_id"])),
            msg_type,
            http: Http::new(rule, "work_wechat", 60)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = create_alert_body(v.rule, v.rtype, matches, v.ts_fmt);
        let payload = json!({"msgtype": self.msg_type, self.msg_type.as_str(): {"content": body}});
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        self.http.post_json("to workwechat", &self.url, &headers, &payload).await?;
        log::info!("Trigger sent to workwechat");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "workwechat", "work_wechat_webhook_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn text_and_markdown() {
        assert!(WorkWechat::new(&rule("workwechat", "work_wechat_bot_id: k\nwork_wechat_msgtype: news\n").unwrap()).is_err());
        for kind in ["text", "markdown"] {
            let (url, got) = capture(1, 200).await;
            let r = rule("workwechat", &format!("work_wechat_bot_id: k\nwork_wechat_msgtype: {kind}\n")).unwrap();
            let mut w = WorkWechat::new(&r).unwrap();
            assert_eq!(w.url, "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=k");
            w.url = format!("{url}/send?key=k");
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None };
            w.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
            assert_eq!(got.await.unwrap()[0].json(), json!({"msgtype": kind, kind: {"content": "r\n\na: 1\n"}}));
        }
    }
}
