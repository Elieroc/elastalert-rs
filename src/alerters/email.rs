//! `email` alerter and the SMTP helpers shared with `notify_email`.

use super::{Doc, View, b, list, required, s, s_or};
use crate::alert::{create_alert_body, create_title};
use crate::field::{lookup, py_str};
use crate::rule::Rule;
use anyhow::{Context, Result, bail};
use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::Value;

pub struct Email {
    host: String,
    port: Option<u16>,
    ssl: bool,
    from: String,
    creds: Option<Credentials>,
    pub to: Vec<String>,
    cc: Vec<String>,
    bcc: Vec<String>,
    reply_to: Option<String>,
    html: bool,
    from_field: Option<String>,
    add_domain: Option<String>,
}

/// `smtp_auth_file`: a YAML file with `user` and `password`, relative to the rule file.
fn read_account(rule: &Rule, file: &str) -> Result<Credentials> {
    let base = std::path::Path::new(rule.raw.get("rule_file").and_then(Value::as_str).unwrap_or("."));
    read_account_file(base, file)
}

/// `file` may be relative to the directory of `base` (a rule or config file).
pub fn read_account_file(base: &std::path::Path, file: &str) -> Result<Credentials> {
    let path = if std::path::Path::new(file).is_absolute() { file.into() } else { base.parent().unwrap_or(".".as_ref()).join(file) };
    let v = crate::config::read_yaml(&path)?;
    match (v["user"].as_str(), v["password"].as_str()) {
        (Some(u), Some(p)) => Ok(Credentials::new(u.into(), p.into())),
        _ => bail!("Account file must have user and password fields"),
    }
}

pub fn mailbox(addr: &str) -> Result<Mailbox> {
    addr.parse().or_else(|_| format!("{addr}@localhost").parse()).with_context(|| format!("invalid email address {addr:?}"))
}

impl Email {
    pub(super) fn new(rule: &Rule) -> Result<Email> {
        required(rule, "email", "email")?;
        for unsupported in ["smtp_cert_file", "email_image_keys", "assets_dir"] {
            if rule.raw.contains_key(unsupported) {
                log::warn!("rule {}: {unsupported} is not supported yet and is ignored", rule.name);
            }
        }
        let add_domain = s(rule, "email_add_domain").map(|d| if d.starts_with('@') { d } else { format!("@{d}") });
        Ok(Email {
            host: s_or(rule, "smtp_host", "localhost"),
            port: rule.raw.get("smtp_port").and_then(Value::as_u64).map(|p| p as u16),
            ssl: b(rule, "smtp_ssl"),
            from: s_or(rule, "from_addr", "ElastAlert"),
            creds: s(rule, "smtp_auth_file").map(|f| read_account(rule, &f)).transpose()?,
            to: list(rule, "email"),
            cc: list(rule, "cc"),
            bcc: list(rule, "bcc"),
            reply_to: s(rule, "email_reply_to"),
            html: s(rule, "email_format").as_deref() == Some("html"),
            from_field: s(rule, "email_from_field"),
            add_domain,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = create_alert_body(v.rule, v.rtype, matches, v.ts_fmt);
        let mut to = self.to.clone();
        if let Some(rec) = self.from_field.as_ref().and_then(|f| lookup(&matches[0], f)) {
            let with_domain = |n: &str| match &self.add_domain {
                Some(d) if !n.contains('@') => Some(format!("{n}{d}")),
                _ if n.contains('@') => Some(n.to_string()),
                _ => None,
            };
            match rec {
                Value::String(n) => to = with_domain(n).into_iter().collect::<Vec<_>>().pipe_or(&to),
                Value::Array(a) => to = a.iter().filter_map(|n| with_domain(&py_str(n))).collect(),
                _ => {}
            }
        }
        let subject = create_title(v.rule, matches, || {
            let mut subj = format!("ElastAlert: {}", v.rule.name);
            if let Some(qv) = v.rule.query_key.as_ref().and_then(|qk| matches[0].get(qk)).filter(|x| !x.is_null()) {
                subj.push_str(&format!(" - {}", py_str(qv)));
            }
            subj
        });
        let mut msg = Message::builder().from(mailbox(&self.from)?).subject(subject);
        for t in &to {
            msg = msg.to(mailbox(t)?);
        }
        for c in &self.cc {
            msg = msg.cc(mailbox(c)?);
        }
        for bc in &self.bcc {
            msg = msg.bcc(mailbox(bc)?);
        }
        msg = msg.reply_to(mailbox(self.reply_to.as_deref().or(to.first().map(String::as_str)).unwrap_or(&self.from))?);
        let email = if self.html { msg.header(ContentType::TEXT_HTML).body(body)? } else { msg.header(ContentType::TEXT_PLAIN).body(body)? };

        send_mail(&self.host, self.port, self.ssl, self.creds.as_ref(), email).await?;
        log::info!("Sent email to {to:?}");
        Ok(())
    }
}

/// Sends one message over SMTP: implicit TLS when `ssl`, else STARTTLS if the server offers it.
pub async fn send_mail(host: &str, port: Option<u16>, ssl: bool, creds: Option<&Credentials>, email: Message) -> Result<()> {
    let tls = TlsParameters::new(host.to_string())?;
    let mut t = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        .tls(if ssl { Tls::Wrapper(tls) } else { Tls::Opportunistic(tls) })
        .port(port.unwrap_or(if ssl { 465 } else { 25 }));
    if let Some(c) = creds {
        t = t.credentials(c.clone());
    }
    t.build().send(email).await.map_err(|e| anyhow::anyhow!("Error sending email via {host}: {e}"))?;
    Ok(())
}

trait PipeOr {
    fn pipe_or(self, fallback: &[String]) -> Vec<String>;
}
impl PipeOr for Vec<String> {
    fn pipe_or(self, fallback: &[String]) -> Vec<String> {
        if self.is_empty() { fallback.to_vec() } else { self }
    }
}
