//! `sns` alerter: publishes to an Amazon SNS topic.

use super::aws::{self, CredOptions, Provider, client, endpoint, query_call};
use super::{Doc, View, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::rule::Rule;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

pub struct Sns {
    topic_arn: String,
    region: String,
    profile: Option<String>,
    creds: Provider,
    client: reqwest::Client,
    /// Test hook: where to send instead of the regional endpoint.
    endpoint: Option<String>,
}

impl Sns {
    pub(super) fn new(rule: &Rule) -> Result<Sns> {
        required(rule, "sns", "sns_topic_arn")?;
        let profile = s(rule, "sns_aws_profile").filter(|p| !p.is_empty());
        let opts = CredOptions { access_key_id: s(rule, "sns_aws_access_key_id"), secret_access_key: s(rule, "sns_aws_secret_access_key"), profile: profile.clone() };
        Ok(Sns {
            topic_arn: s(rule, "sns_topic_arn").unwrap_or_default(),
            region: s_or(rule, "sns_aws_region", "us-east-1"),
            profile,
            creds: Provider::new(opts),
            client: client()?,
            endpoint: None,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = create_alert_body(v.rule, v.rtype, matches, v.ts_fmt);
        let title = create_title(v.rule, matches, || format!("ElastAlert: {}", v.rule.name));
        let send = async {
            // with a profile, upstream ignores sns_aws_region and uses the profile's
            let region = match &self.profile {
                Some(p) => aws::region(None, Some(p), None, self.creds.env())?,
                None => self.region.clone(),
            };
            let creds = self.creds.get(&region).await?;
            let url = self.endpoint.clone().unwrap_or_else(|| endpoint(self.creds.env(), "SNS", "sns", &region));
            let fields = [("Action", "Publish".to_string()), ("Version", "2010-03-31".into()), ("TopicArn", self.topic_arn.clone()), ("Message", body), ("Subject", title)];
            query_call(&self.client, &creds, &region, "sns", &url, &fields).await
        };
        send.await.map_err(|e| anyhow!("Error sending Amazon SNS: {e:#}"))?;
        log::info!("Sent Amazon SNS notification to {}", self.topic_arn);
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "sns"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{rule, serve};
    use crate::types::RuleType;

    #[tokio::test]
    async fn publishes_a_signed_request() {
        let (url, log) = serve(vec![("POST", "/", 200, "<PublishResponse><PublishResult><MessageId>1</MessageId></PublishResult></PublishResponse>".into())]).await;
        let r = rule("sns", "sns_topic_arn: arn:aws:sns:eu-west-1:1:t\nsns_aws_access_key_id: AK\nsns_aws_secret_access_key: SK\nsns_aws_region: eu-west-1\nalert_subject: Subj\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let mut sns = Sns::new(&r).unwrap();
        sns.endpoint = Some(url);
        sns.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap();
        let log = log.lock().unwrap();
        assert_eq!(log[0].body, "Action=Publish&Version=2010-03-31&TopicArn=arn%3Aaws%3Asns%3Aeu-west-1%3A1%3At&Message=r%0A%0Aa%3A+1%0A&Subject=Subj");
        let auth = log[0].header("authorization").unwrap();
        assert!(auth.contains("Credential=AK/") && auth.contains("/eu-west-1/sns/aws4_request"), "{auth}");
    }

    #[tokio::test]
    async fn default_title_and_aws_errors() {
        let (url, log) = serve(vec![("POST", "/", 400, "<ErrorResponse><Error><Code>InvalidParameter</Code><Message>Invalid parameter: TopicArn</Message></Error></ErrorResponse>".into())]).await;
        let r = rule("sns", "sns_topic_arn: bad\nsns_aws_access_key_id: AK\nsns_aws_secret_access_key: SK\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let mut sns = Sns::new(&r).unwrap();
        sns.endpoint = Some(url);
        let err = sns.alert(&v, &[json!({"a": 1}).as_object().unwrap().clone()]).await.unwrap_err().to_string();
        assert_eq!(err, "Error sending Amazon SNS: An error occurred (InvalidParameter) when calling the Publish operation: Invalid parameter: TopicArn");
        assert!(log.lock().unwrap()[0].body.ends_with("Subject=ElastAlert%3A+r"));
    }
}
