//! `smseagle` alerter: SMS or voice call through a SMSEagle device (API v2).

use super::http::Http;
use super::{Doc, View, opt, required, s, s_or};
use crate::alert::create_alert_body;
use crate::field::{py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct SmsEagle {
    url: String,
    token: String,
    message_type: String,
    text: String,
    to: Value,
    contacts: Value,
    groups: Value,
    duration: Value,
    voice_id: Value,
    http: Http,
}

impl SmsEagle {
    pub(super) fn new(rule: &Rule) -> Result<SmsEagle> {
        for k in ["smseagle_url", "smseagle_token", "smseagle_message_type"] {
            required(rule, "smseagle", k)?;
        }
        Ok(SmsEagle {
            url: py_str(&rule.raw["smseagle_url"]),
            token: s(rule, "smseagle_token").unwrap_or_default(),
            message_type: s_or(rule, "smseagle_message_type", ""),
            text: s_or(rule, "smseagle_text", ""),
            to: opt(rule, "smseagle_to", Value::Null),
            contacts: opt(rule, "smseagle_contacts", Value::Null),
            groups: opt(rule, "smseagle_groups", Value::Null),
            duration: opt(rule, "smseagle_duration", json!(10)),
            voice_id: opt(rule, "smseagle_voice_id", json!(1)),
            http: Http::raw(None, None, false, 60)?,
        })
    }

    fn endpoint(&self) -> &'static str {
        match self.message_type.as_str() {
            "ring" => "/api/v2/calls/ring",
            "tts" => "/api/v2/calls/tts",
            "tts_adv" => "/api/v2/calls/tts_advanced",
            _ => "/api/v2/messages/sms",
        }
    }

    fn payload(&self, body: String) -> Result<Value> {
        let recipients = [("to", &self.to), ("contacts", &self.contacts), ("groups", &self.groups)];
        if recipients.iter().all(|(_, v)| !truthy(Some(v))) {
            bail!("Error posting SMSEagle alert: Missing recipients");
        }
        let mut payload = json!({"text": body});
        for (key, value) in recipients {
            if truthy(Some(value)) {
                payload[key] = value.clone();
            }
        }
        if matches!(self.message_type.as_str(), "ring" | "tts" | "tts_adv") {
            payload["duration"] = self.duration.clone();
        }
        if self.message_type == "tts_adv" {
            payload["voice_id"] = self.voice_id.clone();
        }
        if !self.text.is_empty() {
            payload["text"] = json!(self.text);
        }
        Ok(payload)
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = self.payload(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt))?;
        let headers = [("content-type".to_string(), "application/json".to_string()), ("access-token".into(), self.token.clone())];
        self.http.post_json("SMSEagle alert", &format!("{}{}", self.url, self.endpoint()), &headers, &payload).await?;
        log::info!("Alert '{}' sent to SMSEagle", v.rule.name);
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "smseagle", "smseagle_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    fn eagle(extra: &str) -> SmsEagle {
        SmsEagle::new(&rule("smseagle", &format!("smseagle_url: http://eagle\nsmseagle_token: t\n{extra}")).unwrap()).unwrap()
    }

    #[test]
    fn endpoints_and_payloads() {
        assert_eq!(eagle("smseagle_message_type: sms\n").endpoint(), "/api/v2/messages/sms");
        assert_eq!(eagle("smseagle_message_type: whatever\n").endpoint(), "/api/v2/messages/sms");
        assert_eq!(eagle("smseagle_message_type: ring\n").endpoint(), "/api/v2/calls/ring");
        assert_eq!(eagle("smseagle_message_type: tts\n").endpoint(), "/api/v2/calls/tts");
        assert_eq!(eagle("smseagle_message_type: tts_adv\n").endpoint(), "/api/v2/calls/tts_advanced");
        assert_eq!(eagle("smseagle_message_type: sms\nsmseagle_to: ['+1']\n").payload("B".into()).unwrap(), json!({"text": "B", "to": ["+1"]}));
        assert_eq!(
            eagle("smseagle_message_type: tts_adv\nsmseagle_contacts: [1]\nsmseagle_groups: [2]\nsmseagle_duration: 20\nsmseagle_voice_id: 3\nsmseagle_text: fixed\n").payload("B".into()).unwrap(),
            json!({"text": "fixed", "contacts": [1], "groups": [2], "duration": 20, "voice_id": 3})
        );
        assert_eq!(eagle("smseagle_message_type: ring\nsmseagle_to: ['+1']\n").payload("B".into()).unwrap()["duration"], json!(10));
        assert_eq!(eagle("smseagle_message_type: sms\n").payload("B".into()).unwrap_err().to_string(), "Error posting SMSEagle alert: Missing recipients");
    }

    #[tokio::test]
    async fn posts_with_the_access_token() {
        let (url, got) = capture(1, 200).await;
        let r = rule("smseagle", &format!("smseagle_url: {url}\nsmseagle_token: tok\nsmseagle_message_type: sms\nsmseagle_to: ['+1']\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        SmsEagle::new(&r).unwrap().alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!((got[0].path.as_str(), got[0].header("access-token")), ("/api/v2/messages/sms", Some("tok")));
        assert_eq!(got[0].json(), json!({"text": "r\n\na: 1\n", "to": ["+1"]}));
    }
}
