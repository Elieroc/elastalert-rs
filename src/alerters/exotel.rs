//! `exotel` alerter: an SMS with the rule's name followed by `exotel_message_body`.
//!
//! Upstream compares the `Response` object that `exotel` returns with the number 200, which is never equal: the SMS is sent
//! and the alert is then reported as failed (and sent again at every retry). Here the alert succeeds when Exotel answers 200.

use super::http::{Http, form_body};
use super::{Doc, View, required, s_or};
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::{Result, bail};
use reqwest::Method;
use serde_json::{Value, json};

pub struct Exotel {
    url: String,
    from: String,
    to: String,
    sid: String,
    suffix: String,
    http: Http,
}

impl Exotel {
    pub(super) fn new(rule: &Rule) -> Result<Exotel> {
        for k in ["exotel_account_sid", "exotel_auth_token", "exotel_to_number", "exotel_from_number"] {
            required(rule, "exotel", k)?;
        }
        let sid = py_str(&rule.raw["exotel_account_sid"]);
        Ok(Exotel {
            url: format!("https://twilix.exotel.in/v1/Accounts/{sid}/Sms/send.json"),
            from: py_str(&rule.raw["exotel_from_number"]),
            to: py_str(&rule.raw["exotel_to_number"]),
            suffix: s_or(rule, "exotel_message_body", ""),
            http: Http::raw(None, None, false, 60)?.with_basic_auth(sid.clone(), py_str(&rule.raw["exotel_auth_token"])),
            sid,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, _matches: &[Doc]) -> Result<()> {
        let body = form_body(&[("From", self.from.clone()), ("To", self.to.clone()), ("Body", format!("{}{}", v.rule.name, self.suffix)), ("EncodingType", "plain".into()), ("Priority", "normal".into())]);
        let headers = [("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())];
        let resp = self.http.request_text(Method::POST, "posting to Exotel", &self.url, &headers, body).await?;
        if resp.status().as_u16() != 200 {
            bail!("Error posting to Exotel, response code is {}", resp.status().as_u16());
        }
        log::info!("Trigger sent to Exotel");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "exotel", "exotel_account": self.sid})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn sends_the_sms_and_checks_the_status() {
        for (status, ok) in [(200, true), (400, false)] {
            let (url, got) = capture(1, status).await;
            let r = rule("exotel", "exotel_account_sid: sid\nexotel_auth_token: tok\nexotel_to_number: '+1'\nexotel_from_number: '+2'\nexotel_message_body: ' hi'\n").unwrap();
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
            let mut e = Exotel::new(&r).unwrap();
            assert_eq!(e.url, "https://twilix.exotel.in/v1/Accounts/sid/Sms/send.json");
            e.url = format!("{url}/v1/Accounts/sid/Sms/send.json");
            assert_eq!(e.alert(&v, &[]).await.is_ok(), ok);
            let got = got.await.unwrap();
            // same form as upstream's call (StatusCallback is None and not sent)
            assert_eq!(got[0].body, "From=%2B2&To=%2B1&Body=r+hi&EncodingType=plain&Priority=normal");
            assert_eq!(got[0].header("authorization"), Some("Basic c2lkOnRvaw=="));
        }
    }
}
