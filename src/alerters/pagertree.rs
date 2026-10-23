//! `pagertree` alerter.

use super::http::Http;
use super::{Doc, View, required, s};
use crate::alert::{create_alert_body, create_title};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Value, json};

pub struct PagerTree {
    url: String,
    http: Http,
}

impl PagerTree {
    pub(super) fn new(rule: &Rule) -> Result<PagerTree> {
        required(rule, "pagertree", "pagertree_integration_url")?;
        let Some(url) = s(rule, "pagertree_integration_url") else { bail!("pagertree_integration_url must be a string") };
        Ok(PagerTree { url, http: Http::new(rule, "pagertree", 60)? })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let payload = json!({
            "event_type": "create",
            "Id": uuid::Uuid::new_v4().to_string(),
            "Title": create_title(v.rule, matches, || v.rule.name.clone()),
            "Description": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt),
        });
        self.http.post_json("to PagerTree", &self.url, &[], &payload).await?;
        log::info!("Trigger sent to PagerTree");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "pagertree", "pagertree_integration_url": self.url})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    #[tokio::test]
    async fn event_with_fresh_id() {
        let (url, got) = capture(2, 200).await;
        let r = rule("pagertree", &format!("pagertree_integration_url: {url}/i\nalert_subject: S\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None };
        let p = PagerTree::new(&r).unwrap();
        let m = json!({"a": 1}).as_object().unwrap().clone();
        p.alert(&v, &[m.clone()]).await.unwrap();
        p.alert(&v, &[m]).await.unwrap();
        let got = got.await.unwrap();
        let (a, b) = (got[0].json(), got[1].json());
        assert_eq!((&a["event_type"], &a["Title"], &a["Description"]), (&json!("create"), &json!("S"), &json!("r\n\na: 1\n")));
        assert_ne!(a["Id"], b["Id"]);
        assert_eq!(a["Id"].as_str().unwrap().len(), 36);
    }
}
