//! `discord` alerter.

use super::http::Http;
use super::{Doc, View, crop, opt, per_match_text, required, s};
use crate::alert::create_title;
use crate::field::truthy;
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct Discord {
    url: String,
    emoji_title: String,
    color: Value,
    footer: Value,
    icon_url: Value,
    http: Http,
}

impl Discord {
    pub(super) fn new(rule: &Rule) -> Result<Discord> {
        required(rule, "discord", "discord_webhook_url")?;
        let Some(url) = s(rule, "discord_webhook_url") else { bail!("discord_webhook_url must be a single URL string") };
        Ok(Discord {
            url,
            emoji_title: s(rule, "discord_emoji_title").unwrap_or_else(|| ":warning:".into()),
            color: opt(rule, "discord_embed_color", json!(0xffffff)),
            footer: opt(rule, "discord_embed_footer", Value::Null),
            icon_url: opt(rule, "discord_embed_icon_url", Value::Null),
            http: Http::new(rule, "discord", 60)?,
        })
    }

    fn payload(&self, title: &str, body: String) -> Value {
        let body = crop(body, 2047, 1950, "\n *message was cropped according to discord embed description limits!*");
        let mut embed = json!({"description": body, "color": self.color});
        if truthy(Some(&self.footer)) {
            embed["footer"] = json!({"text": self.footer, "icon_url": if truthy(Some(&self.icon_url)) { self.icon_url.clone() } else { Value::Null }});
        }
        json!({"content": format!("{0} {title} {0}", self.emoji_title), "embeds": [embed]})
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let title = create_title(v.rule, matches, || v.rule.name.clone());
        let payload = self.payload(&title, per_match_text(v, matches));
        self.http.post_json_details("to Discord", &self.url, &[], &payload).await?;
        log::info!("Alert sent to the webhook {}", self.url);
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "discord", "discord_webhook_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;

    #[test]
    fn payload_footer_and_crop() {
        let d = Discord::new(&rule("discord", "discord_webhook_url: http://x\ndiscord_embed_footer: foot\ndiscord_embed_color: 255\n").unwrap()).unwrap();
        assert_eq!(
            d.payload("T", "body".into()),
            json!({"content": ":warning: T :warning:", "embeds": [{"description": "body", "color": 255, "footer": {"text": "foot", "icon_url": null}}]})
        );
        let long = d.payload("T", "x".repeat(2048));
        let desc = long["embeds"][0]["description"].as_str().unwrap();
        assert!(desc.starts_with(&"x".repeat(1950)) && desc.ends_with("limits!*"), "{desc}");
        assert_eq!(d.payload("T", "x".repeat(2047))["embeds"][0]["description"].as_str().unwrap().len(), 2047);
    }
}
