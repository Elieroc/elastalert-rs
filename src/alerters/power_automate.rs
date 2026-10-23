//! `ms_power_automate` alerter: an Adaptive Card posted to a Power Automate (Teams) workflow.

use super::http::Http;
use super::{Doc, View, discover_url, list, opt, required, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct PowerAutomate {
    urls: Vec<String>,
    url_from_field: Option<String>,
    summary: Value,
    summary_text_size: String,
    body_text_size: String,
    facts: Option<Vec<Value>>,
    width_full: bool,
    discover: Vec<(&'static str, String, String)>,
    http: Http,
}

impl PowerAutomate {
    pub(super) fn new(rule: &Rule) -> Result<PowerAutomate> {
        required(rule, "ms_power_automate", "ms_power_automate_webhook_url")?;
        let text = |k: &str, d: &str| s_or(rule, &format!("ms_power_automate_{k}"), d);
        let mut discover = vec![];
        for (kind, title) in [("kibana", "Discover in Kibana"), ("opensearch", "Discover in opensearch")] {
            if truthy(rule.raw.get(&format!("ms_power_automate_{kind}_discover_attach_url"))) {
                discover.push((kind, text(&format!("{kind}_discover_title"), title), text(&format!("{kind}_discover_color"), "default")));
            }
        }
        Ok(PowerAutomate {
            urls: list(rule, "ms_power_automate_webhook_url"),
            url_from_field: rule.raw.get("ms_power_automate_webhook_url_from_field").map(py_str),
            summary: opt(rule, "ms_power_automate_alert_summary", Value::Null),
            summary_text_size: text("summary_text_size", "large"),
            body_text_size: text("body_text_size", ""),
            facts: rule.raw.get("ms_power_automate_alert_facts").and_then(Value::as_array).cloned(),
            width_full: truthy(rule.raw.get("ms_power_automate_teams_card_width_full")),
            discover,
            http: Http::new(rule, "ms_power_automate", 60)?,
        })
    }

    fn payload(&self, title: String, body: String, matches: &[Doc]) -> Result<Value> {
        let summary = if self.summary.is_null() { json!(title) } else { self.summary.clone() };
        let mut body_block = json!({"type": "TextBlock", "text": body, "spacing": "Large", "wrap": true});
        if !self.body_text_size.is_empty() {
            body_block["size"] = json!(self.body_text_size);
        }
        let mut content = json!({
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [{"type": "TextBlock", "text": summary, "weight": "Bolder", "wrap": true, "size": self.summary_text_size}, body_block],
            "actions": [],
        });
        if self.width_full {
            content["msteams"] = json!({"width": "Full"});
        }
        if let Some(facts) = &self.facts {
            let mut out = vec![];
            for f in facts {
                let (Some(name), Some(value)) = (f.get("name"), f.get("value")) else { bail!("KeyError: ms_power_automate_alert_facts entries need name and value") };
                let matched = value.as_str().and_then(|k| lookup(&matches[0], k)).filter(|x| !x.is_null());
                out.push(json!({"title": name, "value": matched.unwrap_or(value)}));
            }
            content["body"].as_array_mut().unwrap().push(json!({"type": "FactSet", "facts": out}));
        }
        for (kind, title, style) in &self.discover {
            if let Some(url) = discover_url(matches, kind) {
                content["actions"].as_array_mut().unwrap().push(json!({"type": "Action.OpenUrl", "title": title, "url": url, "style": style}));
            }
        }
        Ok(json!({"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": content}]}))
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let title = create_title(v.rule, matches, || v.rule.name.clone());
        let payload = self.payload(title, create_alert_body(v.rule, v.rtype, matches, v.ts_fmt), matches)?;
        let mut urls = self.urls.clone();
        if let Some(Value::String(hook)) = self.url_from_field.as_deref().and_then(|f| lookup(&matches[0], f)) {
            urls = hook.split(',').map(String::from).collect();
        }
        for url in &urls {
            self.http.post_json("to Power Automate", url, &[], &payload).await?;
        }
        log::info!("Alert sent to Power Automate");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "ms_power_automate", "ms_power_automate_webhook_url": self.urls})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;

    #[test]
    fn card_with_facts_and_actions() {
        let r = rule(
            "ms_power_automate",
            "ms_power_automate_webhook_url: http://x\nms_power_automate_body_text_size: small\nms_power_automate_teams_card_width_full: true\nms_power_automate_kibana_discover_attach_url: true\nms_power_automate_alert_facts:\n- {name: Host, value: host}\n- {name: Const, value: nothere}\n",
        )
        .unwrap();
        let m = json!({"host": "web-1", "kibana_discover_url": "http://kb"}).as_object().unwrap().clone();
        let p = PowerAutomate::new(&r).unwrap().payload("Title".into(), "Body".into(), &[m]).unwrap();
        assert_eq!(
            p,
            json!({"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
                "msteams": {"width": "Full"},
                "body": [
                    {"type": "TextBlock", "text": "Title", "weight": "Bolder", "wrap": true, "size": "large"},
                    {"type": "TextBlock", "text": "Body", "spacing": "Large", "wrap": true, "size": "small"},
                    {"type": "FactSet", "facts": [{"title": "Host", "value": "web-1"}, {"title": "Const", "value": "nothere"}]}
                ],
                "actions": [{"type": "Action.OpenUrl", "title": "Discover in Kibana", "url": "http://kb", "style": "default"}]
            }}]})
        );
    }
}
