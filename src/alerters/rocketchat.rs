//! `rocketchat` alerter.

use super::http::Http;
use super::{Doc, View, discover_url, list, required, s_or};
use crate::alert::{create_alert_body_with, create_title};
use crate::field::{lookup, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct RocketChat {
    urls: Vec<String>,
    pub(super) username: String,
    channels: Vec<String>,
    emoji: String,
    color: String,
    text: String,
    fields: Option<Vec<Value>>,
    discover: Vec<(&'static str, Value)>,
    http: Http,
}

impl RocketChat {
    pub(super) fn new(rule: &Rule) -> Result<RocketChat> {
        required(rule, "rocketchat", "rocket_chat_webhook_url")?;
        let mut channels = list(rule, "rocket_chat_channel_override");
        if channels.is_empty() {
            channels.push(String::new());
        }
        let text = |k: &str, d: &str| s_or(rule, &format!("rocket_chat_{k}"), d);
        let mut discover = vec![];
        for kind in ["kibana", "opensearch"] {
            if truthy(rule.raw.get(&format!("rocket_chat_attach_{kind}_discover_url"))) {
                let title = if kind == "kibana" { "Discover in Kibana" } else { "Discover in opensearch" };
                discover.push((kind, json!({"color": text(&format!("{kind}_discover_color"), "#ec4b98"), "title": text(&format!("{kind}_discover_title"), title)})));
            }
        }
        Ok(RocketChat {
            urls: list(rule, "rocket_chat_webhook_url"),
            username: text("username_override", "elastalert2"),
            channels,
            emoji: text("emoji_override", ":ghost:"),
            color: text("msg_color", "danger"),
            text: text("text_string", ""),
            fields: rule.raw.get("rocket_chat_alert_fields").and_then(Value::as_array).cloned(),
            discover,
            http: Http::new(rule, "rocket_chat", 10)?,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = create_alert_body_with(v.rule, v.rtype, matches, v.ts_fmt, 75, true);
        let mut payload = json!({
            "username": self.username,
            "text": self.text,
            "attachments": [{
                "color": self.color,
                "title": create_title(v.rule, matches, || v.rule.name.clone()),
                "text": body,
                "fields": [],
            }],
        });
        if let Some(fields) = &self.fields {
            let mut out = vec![];
            for f in fields {
                let mut f = f.clone();
                let Some(path) = f.get("value").and_then(Value::as_str) else { bail!("KeyError: 'value' in rocket_chat_alert_fields") };
                f["value"] = lookup(&matches[0], path).cloned().unwrap_or(Value::Null);
                out.push(f);
            }
            payload["attachments"][0]["fields"] = Value::Array(out);
        }
        if !self.emoji.is_empty() {
            payload["emoji"] = json!(self.emoji);
        }
        for (kind, base) in &self.discover {
            if let Some(url) = discover_url(matches, kind) {
                let mut a = base.clone();
                a["title_link"] = url.clone();
                payload["attachments"].as_array_mut().unwrap().push(a);
            }
        }
        for url in &self.urls {
            for channel in &self.channels {
                payload["channel"] = json!(channel);
                self.http.post_json("to Rocket.Chat", url, &[], &payload).await?;
            }
            log::info!("Alert sent to Rocket.Chat");
        }
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "rocketchat", "rocket_chat_username_override": self.username, "rocket_chat_webhook_url": self.urls})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn payload_fields_and_emoji() {
        let (url, got) = capture(1, 200).await;
        let r = rule(
            "rocketchat",
            &format!("alert_text_type: alert_text_only\nalert_subject: Subj\nrocket_chat_webhook_url: {url}\nrocket_chat_text_string: hello\nrocket_chat_alert_fields:\n- {{title: Host, value: host.name, short: true}}\n"),
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        let m = json!({"host": {"name": "web-1"}}).as_object().unwrap().clone();
        RocketChat::new(&r).unwrap().alert(&v, &[m]).await.unwrap();
        assert_eq!(
            got.await.unwrap()[0].json(),
            json!({
                "username": "elastalert2", "text": "hello", "channel": "", "emoji": ":ghost:",
                "attachments": [{"color": "danger", "title": "Subj", "text": "r\n\n", "fields": [{"title": "Host", "value": "web-1", "short": true}]}]
            })
        );
    }
}
