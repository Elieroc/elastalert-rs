//! `ses` alerter: an email through the Amazon SES API (not SMTP).

use super::aws::{self, CredOptions, Provider, client, endpoint, query_call};
use super::{Doc, View, list, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};

pub struct Ses {
    from: String,
    to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    reply_to: Vec<String>,
    from_field: Option<String>,
    add_domain: Option<String>,
    region: String,
    profile: Option<String>,
    creds: Provider,
    client: reqwest::Client,
    endpoint: Option<String>,
}

impl Ses {
    pub(super) fn new(rule: &Rule) -> Result<Ses> {
        required(rule, "ses", "ses_email")?;
        required(rule, "ses", "ses_from_addr")?;
        let profile = s(rule, "ses_aws_profile").filter(|p| !p.is_empty());
        let opts = CredOptions { access_key_id: s(rule, "ses_aws_access_key_id"), secret_access_key: s(rule, "ses_aws_secret_access_key"), profile: profile.clone() };
        Ok(Ses {
            from: s(rule, "ses_from_addr").unwrap_or_default(),
            to: list(rule, "ses_email"),
            cc: list(rule, "ses_cc"),
            bcc: list(rule, "ses_bcc"),
            reply_to: list(rule, "ses_email_reply_to"),
            from_field: s(rule, "ses_email_from_field"),
            add_domain: s(rule, "ses_email_add_domain").filter(|d| !d.is_empty()).map(|d| if d.starts_with('@') { d } else { format!("@{d}") }),
            region: s_or(rule, "ses_aws_region", "us-east-1"),
            profile,
            creds: Provider::new(opts),
            client: client()?,
            endpoint: None,
        })
    }

    fn recipients(&self, first: &Doc) -> Vec<String> {
        let mut to = self.to.clone();
        if let Some(rec) = self.from_field.as_ref().and_then(|f| lookup(first, f)) {
            match rec {
                Value::String(r) if r.contains('@') => to = vec![r.clone()],
                Value::String(r) => {
                    if let Some(d) = &self.add_domain {
                        to = vec![format!("{r}{d}")];
                    }
                }
                Value::Array(a) => to = a.iter().map(|n| format!("{}{}", py_str(n), self.add_domain.as_deref().unwrap_or(""))).collect(),
                _ => {}
            }
        }
        to
    }

    fn fields(&self, v: &View<'_>, matches: &[Doc]) -> Vec<(String, String)> {
        let default_title = || {
            let mut subject = format!("ElastAlert 2: {}", v.rule.name);
            if let Some(qk) = v.rule.query_key.as_ref().and_then(|qk| matches[0].get(qk)).filter(|x| truthy(Some(x))) {
                subject.push_str(&format!(" - {}", py_str(qk)));
            }
            subject
        };
        let mut f: Vec<(String, String)> = vec![("Action".into(), "SendEmail".into()), ("Version".into(), "2010-12-01".into()), ("Source".into(), self.from.clone())];
        for (prefix, addrs) in [("Destination.ToAddresses", self.recipients(&matches[0])), ("Destination.CcAddresses", self.cc.clone()), ("Destination.BccAddresses", self.bcc.clone()), ("ReplyToAddresses", self.reply_to.clone())] {
            for (i, a) in addrs.iter().enumerate() {
                f.push((format!("{prefix}.member.{}", i + 1), a.clone()));
            }
        }
        f.push(("Message.Subject.Charset".into(), "UTF-8".into()));
        f.push(("Message.Subject.Data".into(), create_title(v.rule, matches, default_title)));
        f.push(("Message.Body.Text.Charset".into(), "UTF-8".into()));
        f.push(("Message.Body.Text.Data".into(), create_alert_body(v.rule, v.rtype, matches, v.ts_fmt)));
        f
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let fields = self.fields(v, matches);
        let to = self.recipients(&matches[0]);
        let send = async {
            let region = match &self.profile {
                Some(p) => aws::region(None, Some(p), None, self.creds.env())?,
                None => self.region.clone(),
            };
            let creds = self.creds.get(&region).await?;
            let url = self.endpoint.clone().unwrap_or_else(|| endpoint(self.creds.env(), "SES", "email", &region));
            let borrowed: Vec<(&str, String)> = fields.iter().map(|(k, x)| (k.as_str(), x.clone())).collect();
            query_call(&self.client, &creds, &region, "ses", &url, &borrowed).await
        };
        send.await.map_err(|e| anyhow!("Error sending Amazon SES: {e:#}"))?;
        log::info!("Sent Amazon SES to {to:?}");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "ses", "recipients": self.to})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{rule, serve};
    use crate::types::RuleType;

    const BASE: &str = "ses_email: [a@x.org, b@x.org]\nses_from_addr: me@x.org\nses_aws_access_key_id: AK\nses_aws_secret_access_key: SK\n";

    #[tokio::test]
    async fn send_email_fields() {
        let (url, log) = serve(vec![("POST", "/", 200, "<SendEmailResponse><SendEmailResult><MessageId>1</MessageId></SendEmailResult></SendEmailResponse>".into())]).await;
        let r = rule("ses", &format!("{BASE}ses_cc: c@x.org\nses_bcc: [d@x.org]\nses_email_reply_to: r@x.org\nquery_key: host\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let mut ses = Ses::new(&r).unwrap();
        ses.endpoint = Some(url);
        ses.alert(&v, &[json!({"host": "web-1"}).as_object().unwrap().clone()]).await.unwrap();
        let log = log.lock().unwrap();
        let form: Vec<(String, String)> = url::form_urlencoded::parse(log[0].body.as_bytes()).into_owned().collect();
        let get = |k: &str| form.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!((get("Action"), get("Source")), (Some("SendEmail"), Some("me@x.org")));
        assert_eq!((get("Destination.ToAddresses.member.1"), get("Destination.ToAddresses.member.2")), (Some("a@x.org"), Some("b@x.org")));
        assert_eq!((get("Destination.CcAddresses.member.1"), get("Destination.BccAddresses.member.1"), get("ReplyToAddresses.member.1")), (Some("c@x.org"), Some("d@x.org"), Some("r@x.org")));
        assert_eq!(get("Message.Subject.Data"), Some("ElastAlert 2: r - web-1"));
        assert_eq!((get("Message.Body.Text.Charset"), get("Message.Body.Text.Data")), (Some("UTF-8"), Some("r\n\nhost: web-1\n")));
        assert!(log[0].header("authorization").unwrap().contains("/ses/aws4_request"));
    }

    #[test]
    fn recipients_from_a_field() {
        let ses = |extra: &str| Ses::new(&rule("ses", &format!("{BASE}ses_email_from_field: owner\n{extra}")).unwrap()).unwrap();
        let m = |v: Value| json!({ "owner": v }).as_object().unwrap().clone();
        assert_eq!(ses("").recipients(&m(json!("z@y.org"))), ["z@y.org"]);
        assert_eq!(ses("").recipients(&m(json!("bob"))), ["a@x.org", "b@x.org"]);
        assert_eq!(ses("ses_email_add_domain: y.org\n").recipients(&m(json!("bob"))), ["bob@y.org"]);
        assert_eq!(ses("ses_email_add_domain: '@y.org'\n").recipients(&m(json!(["bob", "eve"]))), ["bob@y.org", "eve@y.org"]);
        assert_eq!(ses("").recipients(&m(json!(["p@q", "r@s"]))), ["p@q", "r@s"]);
    }
}
