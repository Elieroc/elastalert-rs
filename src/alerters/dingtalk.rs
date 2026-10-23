//! `dingtalk` alerter: text, markdown and action cards, optional signed requests.

use super::crypto::{base64, hmac_sha256};
use super::http::Http;
use super::{Doc, View, opt, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::{py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct DingTalk {
    url: String,
    secret: Option<String>,
    msg_type: String,
    single_title: String,
    single_url: String,
    btn_orientation: String,
    btns: Value,
    http: Http,
}

/// `&timestamp=<ms>&sign=<url-quoted base64 HMAC-SHA256>` for a secret.
fn signature(secret: &str, timestamp: &str) -> String {
    let mac = hmac_sha256(secret.as_bytes(), format!("{timestamp}\n{secret}").as_bytes());
    let sign: String = url::form_urlencoded::byte_serialize(base64(&mac).as_bytes()).collect();
    format!("&timestamp={timestamp}&sign={sign}")
}

impl DingTalk {
    pub(super) fn new(rule: &Rule) -> Result<DingTalk> {
        required(rule, "dingtalk", "dingtalk_access_token")?;
        let msg_type = s_or(rule, "dingtalk_msgtype", "text");
        // Upstream has no payload for other types and fails at send time with an unbound variable.
        if !["text", "markdown", "single_action_card", "action_card"].contains(&msg_type.as_str()) {
            bail!("dingtalk_msgtype must be text, markdown, single_action_card or action_card, got {msg_type:?}");
        }
        Ok(DingTalk {
            url: format!("https://oapi.dingtalk.com/robot/send?access_token={}", py_str(&rule.raw["dingtalk_access_token"])),
            secret: s(rule, "dingtalk_sign").filter(|x| !x.is_empty()),
            msg_type,
            single_title: s_or(rule, "dingtalk_single_title", "elastalert"),
            single_url: s_or(rule, "dingtalk_single_url", ""),
            btn_orientation: s_or(rule, "dingtalk_btn_orientation", ""),
            btns: opt(rule, "dingtalk_btns", json!([])),
            http: Http::with_proxy_password_key(rule, "dingtalk", 60, "proxy_pass")?,
        })
    }

    fn payload(&self, title: String, body: String) -> Value {
        match self.msg_type.as_str() {
            "text" => json!({"msgtype": "text", "text": {"content": body}}),
            "markdown" => json!({"msgtype": "markdown", "markdown": {"title": title, "text": body}}),
            "single_action_card" => json!({"msgtype": "actionCard", "actionCard": {"title": title, "text": body, "singleTitle": self.single_title, "singleURL": self.single_url}}),
            _ => {
                let mut p = json!({"msgtype": "actionCard", "actionCard": {"title": title, "text": body}});
                if !self.btn_orientation.is_empty() {
                    p["actionCard"]["btnOrientation"] = json!(self.btn_orientation);
                }
                if truthy(Some(&self.btns)) {
                    p["actionCard"]["btns"] = self.btns.clone();
                }
                p
            }
        }
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = self.payload(create_title(v.rule, matches, || v.rule.name.clone()), create_alert_body(v.rule, v.rtype, matches, v.ts_fmt));
        let mut url = self.url.clone();
        if let Some(secret) = &self.secret {
            // Signed freshly for every request: upstream appends to its stored URL, so a second alert carries two signatures.
            let ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
            url.push_str(&signature(secret, &ms.to_string()));
        }
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        self.http.post_json("to dingtalk", &url, &headers, &payload).await?;
        log::info!("Trigger sent to dingtalk");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "dingtalk", "dingtalk_webhook_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[test]
    fn signature_matches_python() {
        // python: base64 -> quote_plus of hmac-sha256(key=secret, msg="1700000000000\nSECabc")
        assert_eq!(signature("SECabc", "1700000000000"), "&timestamp=1700000000000&sign=jcUpW0QmtKduN03n4JqQ0PBosVjqnM8gU7fIIvsDmCM%3D");
    }

    #[test]
    fn payload_shapes() {
        let mk = |extra: &str| DingTalk::new(&rule("dingtalk", &format!("dingtalk_access_token: t\n{extra}")).unwrap()).unwrap();
        assert_eq!(mk("").payload("T".into(), "B".into()), json!({"msgtype": "text", "text": {"content": "B"}}));
        assert_eq!(mk("dingtalk_msgtype: markdown\n").payload("T".into(), "B".into()), json!({"msgtype": "markdown", "markdown": {"title": "T", "text": "B"}}));
        assert_eq!(
            mk("dingtalk_msgtype: single_action_card\ndingtalk_single_url: http://u\n").payload("T".into(), "B".into()),
            json!({"msgtype": "actionCard", "actionCard": {"title": "T", "text": "B", "singleTitle": "elastalert", "singleURL": "http://u"}})
        );
        assert_eq!(
            mk("dingtalk_msgtype: action_card\ndingtalk_btn_orientation: '1'\ndingtalk_btns: [{title: a, actionURL: http://a}]\n").payload("T".into(), "B".into()),
            json!({"msgtype": "actionCard", "actionCard": {"title": "T", "text": "B", "btnOrientation": "1", "btns": [{"title": "a", "actionURL": "http://a"}]}})
        );
        assert!(DingTalk::new(&rule("dingtalk", "dingtalk_access_token: t\ndingtalk_msgtype: nope\n").unwrap()).is_err());
    }

    #[tokio::test]
    async fn signed_request_is_fresh_each_time() {
        let (url, got) = capture(2, 200).await;
        let r = rule("dingtalk", "dingtalk_access_token: t\ndingtalk_sign: SECabc\n").unwrap();
        let mut d = DingTalk::new(&r).unwrap();
        d.url = format!("{url}/robot/send?access_token=t");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let m = json!({"a": 1}).as_object().unwrap().clone();
        d.alert(&v, &[m.clone()]).await.unwrap();
        d.alert(&v, &[m]).await.unwrap();
        for g in got.await.unwrap() {
            assert_eq!(g.path.matches("sign=").count(), 1, "{}", g.path);
            assert_eq!(g.path.matches("timestamp=").count(), 1);
        }
    }
}
