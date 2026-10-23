//! `googlechat` alerter: plain text or cards.

use super::http::Http;
use super::{Doc, View, list, opt, required, s_or};
use crate::alert::create_alert_body;
use crate::field::truthy;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct GoogleChat {
    urls: Vec<String>,
    card: bool,
    header_title: Value,
    header_subtitle: Value,
    header_image: Value,
    kibana_link: Value,
    http: Http,
}

impl GoogleChat {
    pub(super) fn new(rule: &Rule) -> Result<GoogleChat> {
        required(rule, "googlechat", "googlechat_webhook_url")?;
        Ok(GoogleChat {
            urls: list(rule, "googlechat_webhook_url"),
            card: s_or(rule, "googlechat_format", "basic") == "card",
            header_title: opt(rule, "googlechat_header_title", Value::Null),
            header_subtitle: opt(rule, "googlechat_header_subtitle", Value::Null),
            header_image: opt(rule, "googlechat_header_image", Value::Null),
            kibana_link: opt(rule, "googlechat_footer_kibanalink", Value::Null),
            http: Http::new(rule, "googlechat", 60)?,
        })
    }

    fn message(&self, body: String) -> Value {
        if !self.card {
            return json!({"text": body});
        }
        let mut card = json!({"cards": [{"sections": [{"widgets": [{"textParagraph": {"text": body}}]}]}]});
        if truthy(Some(&self.header_title)) {
            card["cards"][0]["header"] = json!({"title": self.header_title, "subtitle": self.header_subtitle, "imageUrl": self.header_image});
        }
        if truthy(Some(&self.kibana_link)) {
            let footer = json!({"widgets": [{"buttons": [{"textButton": {"text": "VISIT KIBANA", "onClick": {"openLink": {"url": self.kibana_link}}}}]}]});
            card["cards"][0]["sections"].as_array_mut().unwrap().push(footer);
        }
        card
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let message = self.message(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt));
        for url in &self.urls {
            self.http.post_json("to google chat", url, &[], &message).await?;
        }
        log::info!("Alert sent to Google Chat!");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "googlechat", "googlechat_webhook_url": self.urls})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;

    #[test]
    fn basic_and_card() {
        let basic = GoogleChat::new(&rule("googlechat", "googlechat_webhook_url: http://x\n").unwrap()).unwrap();
        assert_eq!(basic.message("hi".into()), json!({"text": "hi"}));
        let card = GoogleChat::new(
            &rule("googlechat", "googlechat_webhook_url: http://x\ngooglechat_format: card\ngooglechat_header_title: T\ngooglechat_footer_kibanalink: http://kb\n").unwrap(),
        )
        .unwrap();
        assert_eq!(
            card.message("hi".into()),
            json!({"cards": [{
                "header": {"title": "T", "subtitle": null, "imageUrl": null},
                "sections": [
                    {"widgets": [{"textParagraph": {"text": "hi"}}]},
                    {"widgets": [{"buttons": [{"textButton": {"text": "VISIT KIBANA", "onClick": {"openLink": {"url": "http://kb"}}}}]}]}
                ]
            }]})
        );
    }
}
