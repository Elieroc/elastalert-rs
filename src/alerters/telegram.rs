//! `telegram` alerter (Bot API `sendMessage`).

use super::http::Http;
use super::{Doc, View, crop, opt, per_match_text, required, s_or};
use crate::alert::create_title;
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Telegram {
    url: String,
    room_id: Value,
    html: bool,
    parse_mode: String,
    thread_id: Value,
    http: Http,
}

impl Telegram {
    pub(super) fn new(rule: &Rule) -> Result<Telegram> {
        required(rule, "telegram", "telegram_bot_token")?;
        required(rule, "telegram", "telegram_room_id")?;
        let parse_mode = s_or(rule, "telegram_parse_mode", "markdown");
        Ok(Telegram {
            url: format!("https://{}/bot{}/sendMessage", s_or(rule, "telegram_api_url", "api.telegram.org"), py_str(&rule.raw["telegram_bot_token"])),
            room_id: rule.raw["telegram_room_id"].clone(),
            html: parse_mode == "html",
            parse_mode,
            thread_id: opt(rule, "telegram_thread_id", Value::Null),
            http: Http::with_proxy_password_key(rule, "telegram", 60, "proxy_pass")?,
        })
    }

    fn payload(&self, title: &str, matches_text: String) -> Value {
        let mut body = if self.html { format!("⚠ {title} ⚠ \n") } else { format!("⚠ *{title}* ⚠ ```\n") };
        body.push_str(&matches_text);
        let mut body = crop(body, 4095, 4000, "\n⚠ *message was cropped according to telegram limits!* ⚠");
        if !self.html {
            body.push_str(" ```");
        }
        json!({
            "chat_id": self.room_id,
            "text": body,
            "parse_mode": self.parse_mode,
            "disable_web_page_preview": true,
            "message_thread_id": self.thread_id,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let title = create_title(v.rule, matches, || v.rule.name.clone());
        let payload = self.payload(&title, per_match_text(v, matches));
        self.http.post_json_details("to Telegram", &self.url, &[], &payload).await?;
        log::info!("Alert sent to Telegram room {}", py_str(&self.room_id));
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "telegram", "telegram_room_id": self.room_id})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[test]
    fn url_and_markdown_payload() {
        let t = Telegram::new(&rule("telegram", "telegram_bot_token: abc\ntelegram_room_id: 12345\n").unwrap()).unwrap();
        assert_eq!(t.url, "https://api.telegram.org/botabc/sendMessage");
        assert_eq!(
            t.payload("T", "m\n".into()),
            json!({"chat_id": 12345, "text": "⚠ *T* ⚠ ```\nm\n ```", "parse_mode": "markdown", "disable_web_page_preview": true, "message_thread_id": null})
        );
        let h = Telegram::new(&rule("telegram", "telegram_bot_token: abc\ntelegram_room_id: '@c'\ntelegram_parse_mode: html\ntelegram_thread_id: 7\n").unwrap()).unwrap();
        let p = h.payload("T", "m\n".into());
        assert_eq!((p["text"].as_str().unwrap(), &p["message_thread_id"]), ("⚠ T ⚠ \nm\n", &json!(7)));
        let long = t.payload("T", "x".repeat(5000));
        assert!(long["text"].as_str().unwrap().ends_with("telegram limits!* ⚠ ```"));
    }

    #[tokio::test]
    async fn posts_each_match_text() {
        let (url, got) = capture(1, 200).await;
        let r = rule("telegram", "telegram_bot_token: abc\ntelegram_room_id: 1\nalert_subject: S\n").unwrap();
        let mut t = Telegram::new(&r).unwrap();
        t.url = format!("{url}/botabc/sendMessage");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let m = json!({"a": 1}).as_object().unwrap().clone();
        t.alert(&v, &[m.clone(), m]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].path, "/botabc/sendMessage");
        let text = got[0].json()["text"].as_str().unwrap().to_string();
        assert_eq!(text, "⚠ *S* ⚠ ```\nr\n\na: 1\n\n----------------------------------------\nr\n\na: 1\n\n----------------------------------------\n ```");
    }
}
