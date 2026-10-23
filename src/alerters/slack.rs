//! `slack` alerter.

use super::http::Http;
use super::{Doc, View, list, required, s_or};
use crate::alert::{create_alert_body_with, create_title};
use crate::field::lookup;
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub struct Slack {
    urls: Vec<String>,
    pub(super) username: String,
    channels: Vec<String>,
    http: Http,
    rule_opts: BTreeMap<&'static str, Value>,
}

impl Slack {
    pub(super) fn new(rule: &Rule) -> Result<Slack> {
        required(rule, "slack", "slack_webhook_url")?;
        let mut opts = BTreeMap::new();
        for (key, default) in [
            ("slack_emoji_override", json!(":ghost:")),
            ("slack_icon_url_override", json!("")),
            ("slack_msg_color", json!("danger")),
            ("slack_parse_override", json!("none")),
            ("slack_text_string", json!("")),
            ("slack_title", json!("")),
            ("slack_title_link", json!("")),
            ("slack_footer", json!("")),
            ("slack_footer_icon", json!("")),
            ("slack_image_url", json!("")),
            ("slack_thumb_url", json!("")),
            ("slack_author_name", json!("")),
            ("slack_author_link", json!("")),
            ("slack_author_icon", json!("")),
            ("slack_msg_pretext", json!("")),
            ("slack_alert_fields", json!("")),
            ("slack_kibana_discover_color", json!("#ec4b98")),
            ("slack_kibana_discover_title", json!("Discover in Kibana")),
            ("slack_opensearch_discover_color", json!("#ec4b98")),
            ("slack_opensearch_discover_title", json!("Discover in Opensearch")),
            ("slack_jira_ticket_color", json!("#ec4b98")),
            ("slack_jira_ticket_title", json!("Jira Ticket")),
        ] {
            opts.insert(key, rule.raw.get(key).cloned().unwrap_or(default));
        }
        let mut channels = list(rule, "slack_channel_override");
        if channels.is_empty() {
            channels.push(String::new());
        }
        Ok(Slack {
            urls: list(rule, "slack_webhook_url"),
            username: s_or(rule, "slack_username_override", "elastalert"),
            channels,
            http: Http::new(rule, "slack", 10)?,
            rule_opts: opts,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let o = |k: &str| self.rule_opts[k].as_str().unwrap_or("").to_string();
        let body = create_alert_body_with(v.rule, v.rtype, matches, v.ts_fmt, 75, true);
        let mut att = json!({
            "color": o("slack_msg_color"),
            "title": create_title(v.rule, matches, || v.rule.name.clone()),
            "text": body,
            "mrkdwn_in": ["text", "pretext"],
            "fields": [],
        });
        if let Some(fields) = self.rule_opts["slack_alert_fields"].as_array() {
            att["fields"] = Value::Array(
                fields
                    .iter()
                    .map(|f| {
                        let mut f = f.clone();
                        if let Some(path) = f["value"].as_str() {
                            f["value"] = lookup(&matches[0], path).cloned().unwrap_or(Value::Null);
                        }
                        f
                    })
                    .collect(),
            );
        }
        for (opt, key) in [
            ("slack_title", "title"),
            ("slack_title_link", "title_link"),
            ("slack_footer", "footer"),
            ("slack_footer_icon", "footer_icon"),
            ("slack_image_url", "image_url"),
            ("slack_thumb_url", "thumb_url"),
            ("slack_author_name", "author_name"),
            ("slack_author_link", "author_link"),
            ("slack_author_icon", "author_icon"),
            ("slack_msg_pretext", "pretext"),
        ] {
            if !o(opt).is_empty() {
                att[key] = json!(o(opt));
            }
        }
        let mut attachments = vec![att];
        for (flag, kind) in [("slack_attach_kibana_discover_url", "kibana"), ("slack_attach_opensearch_discover_url", "opensearch")] {
            if v.rule.raw.get(flag).and_then(Value::as_bool).unwrap_or(false)
                && let Some(url) = matches[0].get(&format!("{kind}_discover_url")).and_then(Value::as_str).filter(|u| !u.is_empty())
            {
                attachments.push(json!({"color": o(&format!("slack_{kind}_discover_color")), "title": o(&format!("slack_{kind}_discover_title")), "title_link": url}));
            }
        }
        if v.rule.raw.get("slack_attach_jira_ticket_url").and_then(Value::as_bool).unwrap_or(false)
            && let Some(url) = v.jira_url()
        {
            attachments.push(json!({"color": o("slack_jira_ticket_color"), "title": o("slack_jira_ticket_title"), "title_link": url}));
        }
        let mut payload = json!({
            "username": self.username,
            "parse": o("slack_parse_override"),
            "text": o("slack_text_string"),
            "attachments": attachments,
        });
        if o("slack_icon_url_override").is_empty() {
            payload["icon_emoji"] = json!(o("slack_emoji_override"));
        } else {
            payload["icon_url"] = json!(o("slack_icon_url_override"));
        }
        for url in &self.urls {
            for channel in &self.channels {
                payload["channel"] = json!(channel);
                self.http.post_json("to slack", url, &[], &payload).await?;
            }
        }
        log::info!("Alert '{}' sent to Slack", v.rule.name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::alerters::Pipeline;
    use crate::types::RuleType;

    #[tokio::test]
    async fn jira_ticket_is_attached_when_asked() {
        for (attach, ticket, expect) in [(true, Some("PROJ-3"), true), (true, None, false), (false, Some("PROJ-3"), false)] {
            let (url, got) = capture(1, 200).await;
            let flag = if attach { "slack_attach_jira_ticket_url: true\nslack_jira_ticket_title: Ticket\n" } else { "" };
            let r = rule("slack", &format!("slack_webhook_url: {url}\n{flag}")).unwrap();
            let rt = RuleType::new(&r).unwrap();
            let pipeline = Pipeline::default();
            if let Some(t) = ticket {
                let mut p = pipeline.lock().unwrap();
                p.insert("jira_ticket".into(), json!(t));
                p.insert("jira_server".into(), json!("https://jira.example"));
            }
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &pipeline };
            Slack::new(&r).unwrap().alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
            let attachments = got.await.unwrap()[0].json()["attachments"].clone();
            if expect {
                assert_eq!(attachments[1], json!({"color": "#ec4b98", "title": "Ticket", "title_link": "https://jira.example/browse/PROJ-3"}));
            } else {
                assert_eq!(attachments.as_array().unwrap().len(), 1);
            }
        }
    }
}
