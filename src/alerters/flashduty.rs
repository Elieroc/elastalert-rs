//! `flashduty` alerter.

use super::http::Http;
use super::{Doc, View, opt, required, s};
use crate::alert::create_alert_body;
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

const LABELS: [&str; 8] = ["check", "service", "cluster", "resource", "metric", "group", "env", "app"];

pub struct Flashduty {
    url: String,
    /// Every `flashduty_*` option echoed in `alert_info`, plus the ones used for the payload.
    opts: Map<String, Value>,
    http: Http,
}

impl Flashduty {
    pub(super) fn new(rule: &Rule) -> Result<Flashduty> {
        required(rule, "flashduty", "flashduty_integration_key")?;
        let Some(key) = s(rule, "flashduty_integration_key") else { bail!("flashduty_integration_key must be a string") };
        let mut opts = Map::new();
        opts.insert("flashduty_title".into(), opt(rule, "flashduty_title", json!("ElastAlert Alert")));
        opts.insert("flashduty_event_status".into(), opt(rule, "flashduty_event_status", json!("Info")));
        for k in ["description", "alert_key"].into_iter().chain(LABELS) {
            opts.insert(format!("flashduty_{k}"), opt(rule, &format!("flashduty_{k}"), Value::Null));
        }
        Ok(Flashduty { url: format!("https://api.flashcat.cloud/event/push/alert/standard?integration_key={key}"), opts, http: Http::raw(None, None, false, 60)? })
    }

    fn payload(&self, body: String) -> Value {
        let mut labels = Map::new();
        for l in LABELS {
            labels.insert(l.into(), self.opts[&format!("flashduty_{l}")].clone());
        }
        labels.insert("information".into(), json!(body));
        json!({
            "title": self.opts["flashduty_title"],
            "description": self.opts["flashduty_description"],
            "event_status": self.opts["flashduty_event_status"],
            "alert_key": self.opts["flashduty_alert_key"],
            "labels": labels,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = self.payload(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt));
        self.http.post_json("to flashduty", &self.url, &[("Content-Type".into(), "application/json".into())], &payload).await?;
        log::info!("Trigger sent to flashduty");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        let mut info = self.opts.clone();
        info.insert("type".into(), json!("flashduty"));
        let key = self.url.rsplit_once('=').map(|(_, k)| k).unwrap_or_default();
        info.insert("flashduty_integration_key".into(), json!(key));
        Value::Object(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;

    #[test]
    fn payload_and_info() {
        let f = Flashduty::new(&rule("flashduty", "flashduty_integration_key: abc\nflashduty_service: svc\nflashduty_event_status: Critical\n").unwrap()).unwrap();
        assert_eq!(f.url, "https://api.flashcat.cloud/event/push/alert/standard?integration_key=abc");
        assert_eq!(
            f.payload("body".into()),
            json!({
                "title": "ElastAlert Alert", "description": null, "event_status": "Critical", "alert_key": null,
                "labels": {"check": null, "service": "svc", "cluster": null, "resource": null, "metric": null, "group": null, "env": null, "app": null, "information": "body"}
            })
        );
        let info = f.info();
        assert_eq!((&info["type"], &info["flashduty_integration_key"], &info["flashduty_service"]), (&json!("flashduty"), &json!("abc"), &json!("svc")));
    }
}
