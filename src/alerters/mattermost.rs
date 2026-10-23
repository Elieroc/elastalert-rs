//! `mattermost` alerter.

use super::http::Http;
use super::{Doc, View, discover_url, list, required, s_or};
use crate::alert::{create_alert_body_with, create_title, py_format};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Map, Value, json};

/// Attachment keys that are set only when their `mattermost_<key>` option is not empty.
const ATTACHMENT_KEYS: [&str; 9] = ["title", "title_link", "footer", "footer_icon", "image_url", "thumb_url", "author_name", "author_link", "author_icon"];

pub struct Mattermost {
    urls: Vec<String>,
    pub(super) username: String,
    channels: Vec<String>,
    emoji: String,
    icon_url: String,
    pretext: String,
    color: String,
    fields: Option<Vec<Value>>,
    attachment: Vec<(&'static str, String)>,
    discover: Vec<(&'static str, Value)>,
    http: Http,
}

impl Mattermost {
    pub(super) fn new(rule: &Rule) -> Result<Mattermost> {
        required(rule, "mattermost", "mattermost_webhook_url")?;
        let mut channels = list(rule, "mattermost_channel_override");
        if channels.is_empty() {
            channels.push(String::new());
        }
        let text = |k: &str, d: &str| s_or(rule, &format!("mattermost_{k}"), d);
        let mut discover = vec![];
        for kind in ["kibana", "opensearch"] {
            let flag = rule.raw.get(&format!("mattermost_attach_{kind}_discover_url"));
            if truthy(flag) {
                let title = if kind == "kibana" { "Discover in Kibana" } else { "Discover in opensearch" };
                discover.push((kind, json!({"color": text(&format!("{kind}_discover_color"), "#ec4b98"), "title": text(&format!("{kind}_discover_title"), title)})));
            }
        }
        Ok(Mattermost {
            urls: list(rule, "mattermost_webhook_url"),
            username: text("username_override", "elastalert"),
            channels,
            emoji: text("emoji_override", ":ghost:"),
            icon_url: text("icon_url_override", ""),
            pretext: text("msg_pretext", ""),
            color: text("msg_color", "danger"),
            fields: rule.raw.get("mattermost_msg_fields").and_then(Value::as_array).cloned(),
            attachment: ATTACHMENT_KEYS.iter().map(|k| (*k, text(k, ""))).filter(|(_, v)| !v.is_empty()).collect(),
            discover,
            http: Http::new(rule, "mattermost", 60)?,
        })
    }

    fn populate_fields(&self, v: &View<'_>, fields: &[Value], first: &Doc) -> Vec<Value> {
        let missing = v.rule.raw.get("alert_missing_value").and_then(Value::as_str).unwrap_or("<MISSING VALUE>");
        fields
            .iter()
            .map(|f| {
                let mut f = f.clone();
                if let Some(args) = f.get("args").and_then(Value::as_array).cloned() {
                    let vals: Vec<String> = args
                        .iter()
                        .map(|a| lookup(first, &py_str(a)).filter(|x| truthy(Some(x))).map(py_str).unwrap_or_else(|| missing.to_string()))
                        .collect();
                    let value = match f.get("value") {
                        Some(t) => py_format(&py_str(t), &vals, &Map::new()),
                        None => vals.join("\n"),
                    };
                    f["value"] = json!(value);
                    f.as_object_mut().map(|o| o.remove("args"));
                }
                f
            })
            .collect()
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = create_alert_body_with(v.rule, v.rtype, matches, v.ts_fmt, 75, true);
        let title = create_title(v.rule, matches, || v.rule.name.clone());
        let mut att = json!({
            "fallback": format!("{title}: {}", self.pretext),
            "color": self.color,
            "title": title,
            "pretext": self.pretext,
            "fields": [],
        });
        let mut payload = json!({"username": self.username, "attachments": []});
        if v.rule.raw.get("alert_text_type").and_then(Value::as_str) == Some("alert_text_only") {
            att["text"] = json!(body);
        } else {
            payload["text"] = json!(body);
        }
        if let Some(fields) = &self.fields {
            att["fields"] = Value::Array(self.populate_fields(v, fields, &matches[0]));
        }
        if self.icon_url.is_empty() {
            payload["icon_emoji"] = json!(self.emoji);
        } else {
            payload["icon_url"] = json!(self.icon_url);
        }
        for (key, value) in &self.attachment {
            att[*key] = json!(value);
        }
        let mut attachments = vec![att];
        for (kind, base) in &self.discover {
            if let Some(url) = discover_url(matches, kind) {
                let mut a = base.clone();
                a["title_link"] = url.clone();
                attachments.push(a);
            }
        }
        payload["attachments"] = Value::Array(attachments);
        for url in &self.urls {
            for channel in &self.channels {
                payload["channel"] = json!(channel);
                self.http.post_json("to Mattermost", url, &[], &payload).await?;
            }
        }
        log::info!("Alert sent to Mattermost");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "mattermost", "mattermost_username_override": self.username, "mattermost_webhook_url": self.urls})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    fn m() -> Doc {
        json!({"@timestamp": "2021-01-01T00:00:00", "somefield": "foobarbaz"}).as_object().unwrap().clone()
    }

    #[tokio::test]
    async fn alert_text_only_payload() {
        let (url, got) = capture(1, 200).await;
        let r = rule("mattermost", &format!("alert_text_type: alert_text_only\nalert_subject: Test Mattermost\nmattermost_webhook_url: {url}\nmattermost_msg_pretext: aaaaa\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        Mattermost::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(
            got[0].json(),
            json!({
                "attachments": [{"fallback": "Test Mattermost: aaaaa", "color": "danger", "title": "Test Mattermost", "pretext": "aaaaa", "fields": [], "text": "r\n\n"}],
                "username": "elastalert", "channel": "", "icon_emoji": ":ghost:"
            })
        );
    }

    #[tokio::test]
    async fn fields_channels_and_overrides() {
        let (url, got) = capture(2, 200).await;
        let extra = format!(
            "alert_subject: T\nmattermost_webhook_url: {url}\nmattermost_channel_override: ['#a', '#b']\nmattermost_icon_url_override: http://icon\nmattermost_title: Custom\nmattermost_footer: foot\nmattermost_msg_fields:\n- {{title: Host, value: 'is {{0}} ({{1}})', args: [somefield, nope], short: true}}\n- {{title: Plain, value: fixed}}\n- {{title: Joined, args: [somefield]}}\n"
        );
        let r = rule("mattermost", &extra).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        Mattermost::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[1].json()["channel"], json!("#b"));
        let p = got[0].json();
        assert_eq!(p["icon_url"], json!("http://icon"));
        assert!(p.get("icon_emoji").is_none());
        assert_eq!(p["attachments"][0]["title"], json!("Custom"));
        assert_eq!(p["attachments"][0]["footer"], json!("foot"));
        assert_eq!(
            p["attachments"][0]["fields"],
            json!([{"title": "Host", "value": "is foobarbaz (<MISSING VALUE>)", "short": true}, {"title": "Plain", "value": "fixed"}, {"title": "Joined", "value": "foobarbaz"}])
        );
        assert!(p["text"].as_str().unwrap().contains("somefield: foobarbaz"));
    }
}
