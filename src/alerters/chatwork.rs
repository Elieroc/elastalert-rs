//! `chatwork` alerter: form-encoded message to a room.

use super::http::Http;
use super::{Doc, View, crop, per_match_text, required, s};
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Chatwork {
    url: String,
    api_key: String,
    room_id: Value,
    http: Http,
}

impl Chatwork {
    pub(super) fn new(rule: &Rule) -> Result<Chatwork> {
        required(rule, "chatwork", "chatwork_apikey")?;
        required(rule, "chatwork", "chatwork_room_id")?;
        Ok(Chatwork {
            url: format!("https://api.chatwork.com/v2/rooms/{}/messages", py_str(&rule.raw["chatwork_room_id"])),
            api_key: s(rule, "chatwork_apikey").unwrap_or_default(),
            room_id: rule.raw["chatwork_room_id"].clone(),
            http: Http::with_proxy_password_key(rule, "chatwork", 60, "proxy_pass")?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = crop(per_match_text(v, matches), 2047, 1950, "\n *message was cropped according to chatwork embed description limits!*");
        let headers = [
            ("accept".to_string(), "application/json".to_string()),
            ("content-type".into(), "application/x-www-form-urlencoded".into()),
            ("x-chatworktoken".into(), self.api_key.clone()),
        ];
        self.http.post_form_details("to Chatwork", &self.url, &headers, &[("self_unread", "0".into()), ("body", body)]).await?;
        log::info!("Alert sent to Chatwork room {}", py_str(&self.room_id));
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "chatwork", "chatwork_room_id": self.room_id})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn form_body_and_token() {
        let (url, got) = capture(1, 200).await;
        let r = rule("chatwork", "chatwork_apikey: key\nchatwork_room_id: 42\n").unwrap();
        let mut c = Chatwork::new(&r).unwrap();
        assert_eq!(c.url, "https://api.chatwork.com/v2/rooms/42/messages");
        c.url = format!("{url}/v2/rooms/42/messages");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        c.alert(&v, &[json!({"a": "x y"}).as_object().unwrap().clone()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].header("x-chatworktoken"), Some("key"));
        assert_eq!(got[0].header("content-type"), Some("application/x-www-form-urlencoded"));
        assert_eq!(got[0].body, "self_unread=0&body=r%0A%0Aa%3A+x+y%0A");
    }
}
