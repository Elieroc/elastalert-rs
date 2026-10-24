//! `sqs` alerter: sends the alert as a JSON message to an Amazon SQS queue.

use super::aws::{CredOptions, Provider, client, endpoint, query_call, xml_tag};
use super::{Doc, View, py_json_dumps, required, s};
use crate::alert::create_alert_body;
use crate::rule::Rule;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

pub struct Sqs {
    queue_url: String,
    region: String,
    creds: Provider,
    client: reqwest::Client,
    endpoint: Option<String>,
}

/// `https://sqs.<region>.amazonaws.com/<account>/<queue>` -> `<region>`.
fn region_from_queue_url(queue_url: &str) -> Option<String> {
    let host = url::Url::parse(queue_url).ok()?.host_str()?.to_string();
    let parts: Vec<&str> = host.split('.').collect();
    (parts.len() >= 3 && parts[0] == "sqs").then(|| parts[1].to_string())
}

impl Sqs {
    pub(super) fn new(rule: &Rule) -> Result<Sqs> {
        required(rule, "sqs", "sqs_queue_url")?;
        let queue_url = s(rule, "sqs_queue_url").unwrap_or_default();
        let opts = CredOptions { access_key_id: s(rule, "sqs_aws_access_key_id"), secret_access_key: s(rule, "sqs_aws_secret_access_key"), profile: s(rule, "sqs_aws_profile").filter(|p| !p.is_empty()) };
        Ok(Sqs {
            region: s(rule, "sqs_aws_region").filter(|r| !r.is_empty()).or_else(|| region_from_queue_url(&queue_url)).unwrap_or_else(|| "us-east-1".into()),
            queue_url,
            creds: Provider::new(opts),
            client: client()?,
            endpoint: None,
        })
    }

    /// `{"rule_name", "matches", "text"}` as JSON, with the text cropped to stay under the 1 MiB message limit.
    fn body(&self, v: &View<'_>, matches: &[Doc]) -> String {
        let mut text = create_alert_body(v.rule, v.rtype, matches, v.ts_fmt);
        // SQS messages may not exceed 1 MB: crop the text at ~800 KB to be safe
        if text.chars().count() > 800_000 {
            text = text.chars().take(800_000).collect::<String>() + "\n*message was cropped according to SQS limits!*";
        }
        let mut data = json!({"rule_name": v.rule.name, "matches": matches, "text": text});
        let mut body = py_json_dumps(&data);
        if body.chars().count() > 1_048_576 {
            data["text"] = json!("Text message omitted due to SQS size limit.");
            body = py_json_dumps(&data);
        }
        body
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = self.body(v, matches);
        let send = async {
            let creds = self.creds.get(&self.region).await?;
            let url = self.endpoint.clone().unwrap_or_else(|| endpoint(self.creds.env(), "SQS", "sqs", &self.region));
            let fields = [("Action", "SendMessage".to_string()), ("Version", "2012-11-05".into()), ("QueueUrl", self.queue_url.clone()), ("MessageBody", body)];
            query_call(&self.client, &creds, &self.region, "sqs", &url, &fields).await
        };
        let xml = send.await.map_err(|e| anyhow!("Error sending Amazon SQS: {e:#}"))?;
        log::info!("Sent Amazon SQS message to {}, MessageId: {}", self.queue_url, xml_tag(&xml, "MessageId").unwrap_or_default());
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "sqs"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{rule, serve};
    use crate::types::RuleType;

    #[test]
    fn region_comes_from_the_queue_url() {
        assert_eq!(region_from_queue_url("https://sqs.eu-central-1.amazonaws.com/123/q").as_deref(), Some("eu-central-1"));
        assert_eq!(region_from_queue_url("http://localhost:4566/000000000000/q"), None);
        let q = |extra: &str| Sqs::new(&rule("sqs", &format!("sqs_queue_url: https://sqs.eu-west-1.amazonaws.com/1/q\n{extra}")).unwrap()).unwrap().region;
        assert_eq!((q("").as_str(), q("sqs_aws_region: us-west-2\n").as_str()), ("eu-west-1", "us-west-2"));
        assert_eq!(Sqs::new(&rule("sqs", "sqs_queue_url: http://localhost/1/q\n").unwrap()).unwrap().region, "us-east-1");
    }

    #[tokio::test]
    async fn sends_the_json_body() {
        let (url, log) = serve(vec![("POST", "/", 200, "<SendMessageResponse><SendMessageResult><MessageId>abc</MessageId></SendMessageResult></SendMessageResponse>".into())]).await;
        let r = rule("sqs", "sqs_queue_url: https://sqs.eu-west-1.amazonaws.com/1/q\nsqs_aws_access_key_id: AK\nsqs_aws_secret_access_key: SK\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let mut sqs = Sqs::new(&r).unwrap();
        sqs.endpoint = Some(url);
        sqs.alert(&v, &[json!({"a": "é"}).as_object().unwrap().clone()]).await.unwrap();
        let log = log.lock().unwrap();
        let form: std::collections::HashMap<String, String> = url::form_urlencoded::parse(log[0].body.as_bytes()).into_owned().collect();
        assert_eq!((form["Action"].as_str(), form["QueueUrl"].as_str()), ("SendMessage", "https://sqs.eu-west-1.amazonaws.com/1/q"));
        assert_eq!(form["MessageBody"], r#"{"matches": [{"a": "@U00e9"}], "rule_name": "r", "text": "r\n\na: @U00e9\n"}"#.replace("@U", "\\u"));
        assert!(log[0].header("authorization").unwrap().contains("/eu-west-1/sqs/aws4_request"));
    }

    #[test]
    fn oversized_text_is_cropped_then_dropped() {
        let r = rule("sqs", "sqs_queue_url: http://localhost/1/q\nalert_text: 'x'\nalert_text_type: alert_text_only\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let sqs = Sqs::new(&r).unwrap();
        let big = json!({"f": "y".repeat(1_100_000)}).as_object().unwrap().clone();
        let body = sqs.body(&v, &[big]);
        assert!(body.contains("Text message omitted due to SQS size limit."), "{}", &body[body.len().saturating_sub(120)..]);
    }
}
