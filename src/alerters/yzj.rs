//! `yzj` (Yunzhijia) alerter.

use super::http::Http;
use super::{Doc, View, opt, required, s};
use crate::alert::create_alert_body;
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Yzj {
    url: String,
    http: Http,
}

impl Yzj {
    pub(super) fn new(rule: &Rule) -> Result<Yzj> {
        required(rule, "yzj", "yzj_token")?;
        let mut url = format!("https://www.yunzhijia.com/gateway/robot/webhook/send?yzjtype={}&yzjtoken={}", py_str(&opt(rule, "yzj_type", json!(0))), py_str(&rule.raw["yzj_token"]));
        // `yzj_custom_loc` replaces the host[:port] part of the URL.
        if let Some(loc) = s(rule, "yzj_custom_loc") {
            let rest = &url["https://".len()..];
            let path = rest.find(['/', '?']).map_or("", |i| &rest[i..]);
            url = format!("https://{loc}{path}");
        }
        Ok(Yzj { url, http: Http::new(rule, "yzj", 60)? })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = json!({"content": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)});
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        self.http.post_json("to yzj", &self.url, &headers, &payload).await?;
        log::info!("Trigger sent to YZJ");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "yzj", "yzj_webhook_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn url_custom_loc_and_payload() {
        let y = Yzj::new(&rule("yzj", "yzj_token: tk\n").unwrap()).unwrap();
        assert_eq!(y.url, "https://www.yunzhijia.com/gateway/robot/webhook/send?yzjtype=0&yzjtoken=tk");
        let custom = Yzj::new(&rule("yzj", "yzj_token: tk\nyzj_type: 2\nyzj_custom_loc: 127.0.0.1:8080\n").unwrap()).unwrap();
        assert_eq!(custom.url, "https://127.0.0.1:8080/gateway/robot/webhook/send?yzjtype=2&yzjtoken=tk");

        let (url, got) = capture(1, 200).await;
        let r = rule("yzj", "yzj_token: tk\n").unwrap();
        let mut y = Yzj::new(&r).unwrap();
        y.url = format!("{url}/send");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        y.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        assert_eq!(got.await.unwrap()[0].json(), json!({"content": "r\n\na: 1\n"}));
    }
}
