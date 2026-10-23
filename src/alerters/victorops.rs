//! `victorops` alerter.

use super::http::Http;
use super::{Doc, View, opt, required};
use crate::alert::{create_alert_body, create_title};
use crate::field::{py_str, truthy};
use crate::rule::Rule;
use anyhow::Result;
use serde_json::{Value, json};

pub struct VictorOps {
    url: String,
    routing_key: Value,
    message_type: Value,
    entity_id: Value,
    entity_display_name: Option<Value>,
    http: Http,
}

impl VictorOps {
    pub(super) fn new(rule: &Rule) -> Result<VictorOps> {
        for k in ["victorops_api_key", "victorops_routing_key", "victorops_message_type"] {
            required(rule, "victorops", k)?;
        }
        Ok(VictorOps {
            url: format!(
                "https://alert.victorops.com/integrations/generic/20131114/alert/{}/{}",
                py_str(&rule.raw["victorops_api_key"]),
                py_str(&rule.raw["victorops_routing_key"])
            ),
            routing_key: rule.raw["victorops_routing_key"].clone(),
            message_type: rule.raw["victorops_message_type"].clone(),
            entity_id: opt(rule, "victorops_entity_id", Value::Null),
            entity_display_name: rule.raw.get("victorops_entity_display_name").filter(|v| !v.is_null()).cloned(),
            http: Http::new(rule, "victorops", 60)?,
        })
    }

    fn payload(&self, title: String, body: String, first: &Doc) -> Value {
        // Computed per alert: upstream stores the first title on the alerter and reuses it for every later alert.
        let mut payload = json!({
            "message_type": self.message_type,
            "entity_display_name": self.entity_display_name.clone().unwrap_or(json!(title)),
            "monitoring_tool": "ElastAlert",
            "state_message": body,
        });
        // The first match's fields are merged on top, so a field named like a payload key wins.
        payload.as_object_mut().unwrap().extend(first.clone());
        if truthy(Some(&self.entity_id)) {
            payload["entity_id"] = self.entity_id.clone();
        }
        payload
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let title = create_title(v.rule, matches, || v.rule.name.clone());
        let payload = self.payload(title, create_alert_body(v.rule, v.rtype, matches, v.ts_fmt), &matches[0]);
        self.http.post_json("to VictorOps", &self.url, &[], &payload).await?;
        log::info!("Trigger sent to VictorOps");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "victorops", "victorops_routing_key": self.routing_key})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;

    #[test]
    fn payload_merges_match_fields() {
        let r = rule("victorops", "victorops_api_key: ak\nvictorops_routing_key: rk\nvictorops_message_type: CRITICAL\nvictorops_entity_id: e1\n").unwrap();
        let v = VictorOps::new(&r).unwrap();
        assert_eq!(v.url, "https://alert.victorops.com/integrations/generic/20131114/alert/ak/rk");
        let m = json!({"host": "web-1", "message_type": "INFO"}).as_object().unwrap().clone();
        assert_eq!(
            v.payload("T".into(), "B".into(), &m),
            json!({"message_type": "INFO", "entity_display_name": "T", "monitoring_tool": "ElastAlert", "state_message": "B", "host": "web-1", "entity_id": "e1"})
        );
        let named = VictorOps::new(&rule("victorops", "victorops_api_key: a\nvictorops_routing_key: r\nvictorops_message_type: WARNING\nvictorops_entity_display_name: Fixed\n").unwrap()).unwrap();
        assert_eq!(named.payload("T".into(), "B".into(), &Doc::new())["entity_display_name"], json!("Fixed"));
    }
}
