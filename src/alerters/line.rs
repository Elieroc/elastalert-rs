//! `line` alerter (LINE Messaging API push message).

use super::http::Http;
use super::{Doc, View, crop, per_match_text, required};
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct Line {
    url: String,
    token: String,
    to: Value,
    http: Http,
}

impl Line {
    pub(super) fn new(rule: &Rule) -> Result<Line> {
        // Upstream misspells `required_options`, so it never checks these; a rule without them could never deliver.
        required(rule, "line", "line_channel_access_token")?;
        required(rule, "line", "line_to")?;
        Ok(Line {
            url: "https://api.line.me/v2/bot/message/push".into(),
            token: py_str(&rule.raw["line_channel_access_token"]),
            to: rule.raw["line_to"].clone(),
            http: Http::new(rule, "line", 60)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = crop(per_match_text(v, matches), 4800, 4700, "\n\n(message cropped due to LINE limit)");
        let payload = json!({"to": self.to, "messages": [{"type": "text", "text": body}]});
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Authorization".into(), format!("Bearer {}", self.token))];
        self.http.post_json("to LINE Messaging API", &self.url, &headers, &payload).await?;
        log::info!("Alert sent to LINE Messaging API");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "line", "line_to": self.to, "line_channel_access_token": self.token})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn push_message() {
        let (url, got) = capture(1, 200).await;
        let r = rule("line", "line_channel_access_token: tok\nline_to: U123\n").unwrap();
        let mut l = Line::new(&r).unwrap();
        l.url = format!("{url}/v2/bot/message/push");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        l.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].header("authorization"), Some("Bearer tok"));
        assert_eq!(got[0].json(), json!({"to": "U123", "messages": [{"type": "text", "text": "r\n\na: 1\n"}]}));
    }
}
