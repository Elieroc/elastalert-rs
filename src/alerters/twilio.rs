//! `twilio` alerter: an SMS (or a Copilot messaging-service message) with the rule's name.

use super::http::Http;
use super::{Doc, View, opt, required, s};
use crate::field::{py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

pub struct Twilio {
    url: String,
    to: String,
    from: Option<String>,
    service_sid: Option<String>,
    copilot: bool,
    from_info: Value,
    http: Http,
}

impl Twilio {
    pub(super) fn new(rule: &Rule) -> Result<Twilio> {
        for k in ["twilio_account_sid", "twilio_auth_token", "twilio_to_number"] {
            required(rule, "twilio", k)?;
        }
        let sid = py_str(&rule.raw["twilio_account_sid"]);
        Ok(Twilio {
            url: format!("https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"),
            to: py_str(&rule.raw["twilio_to_number"]),
            from: s(rule, "twilio_from_number"),
            service_sid: s(rule, "twilio_message_service_sid"),
            copilot: rule.raw.get("twilio_use_copilot").is_some_and(|v| truthy(Some(v))),
            from_info: opt(rule, "twilio_from_number", Value::Null),
            http: Http::raw(None, None, false, 60)?.with_basic_auth(sid, py_str(&rule.raw["twilio_auth_token"])),
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, _matches: &[Doc]) -> Result<()> {
        let mut fields = vec![("Body", v.rule.name.clone()), ("To", self.to.clone())];
        if self.copilot {
            let Some(sid) = &self.service_sid else { bail!("Twilio Copilot requires the 'twilio_message_service_sid' option") };
            fields.push(("MessagingServiceSid", sid.clone()));
        } else {
            let Some(from) = &self.from else { bail!("Twilio SMS requires the 'twilio_from_number' option") };
            fields.push(("From", from.clone()));
        }
        self.http
            .post_form_details("to twilio", &self.url, &[("Accept".into(), "application/json".into())], &fields)
            .await
            .map_err(|e| anyhow!("{e:#}"))?;
        log::info!("Trigger sent to Twilio");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "twilio", "twilio_client_name": self.from_info})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    const BASE: &str = "twilio_account_sid: AC123\ntwilio_auth_token: tok\ntwilio_to_number: '+33600000000'\n";

    #[tokio::test]
    async fn sms_and_copilot() {
        for (extra, expected) in [
            ("twilio_from_number: '+33100000000'\n", "Body=r&To=%2B33600000000&From=%2B33100000000"),
            ("twilio_use_copilot: true\ntwilio_message_service_sid: MG1\n", "Body=r&To=%2B33600000000&MessagingServiceSid=MG1"),
        ] {
            let (url, got) = capture(1, 201).await;
            let r = rule("twilio", &format!("{BASE}{extra}")).unwrap();
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
            let mut t = Twilio::new(&r).unwrap();
            assert_eq!(t.url, "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json");
            t.url = format!("{url}/2010-04-01/Accounts/AC123/Messages.json");
            t.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
            let got = got.await.unwrap();
            assert_eq!(got[0].body, expected);
            assert_eq!(got[0].header("authorization"), Some("Basic QUMxMjM6dG9r"));
        }
    }

    #[tokio::test]
    async fn missing_sender_and_api_errors() {
        let r = rule("twilio", BASE).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let err = Twilio::new(&r).unwrap().alert(&v, &[]).await.unwrap_err();
        assert_eq!(err.to_string(), "Twilio SMS requires the 'twilio_from_number' option");
        let r = rule("twilio", &format!("{BASE}twilio_use_copilot: true\n")).unwrap();
        assert!(Twilio::new(&r).unwrap().alert(&v, &[]).await.unwrap_err().to_string().contains("twilio_message_service_sid"));

        let (url, _) = capture(1, 401).await;
        let r = rule("twilio", &format!("{BASE}twilio_from_number: '+1'\n")).unwrap();
        let mut t = Twilio::new(&r).unwrap();
        t.url = url;
        let err = t.alert(&v, &[]).await.unwrap_err().to_string();
        assert!(err.starts_with("Error posting to twilio:") && err.contains("401"), "{err}");
    }
}
