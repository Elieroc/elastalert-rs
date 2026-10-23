//! Alerters: debug, email, slack, http post, command. Each is built once per rule from its keys.

use crate::alert::{self, create_alert_body, create_alert_body_with, create_title};
use crate::field::{lookup, py_str};
use crate::rule::Rule;
use crate::types::RuleType;
use anyhow::{Context, Result, bail};
use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::time::Duration;

pub type Doc = Map<String, Value>;

pub enum Alerter {
    Debug,
    Email(Email),
    Slack(Slack),
    Post(Post),
    Command(Command),
}

/// Read-only view the alerters need to produce text.
pub struct View<'a> {
    pub rule: &'a Rule,
    pub rtype: &'a RuleType,
    pub ts_fmt: Option<&'a str>,
}

pub const ALERT_TIMEOUT: Duration = Duration::from_secs(60);

impl Alerter {
    pub fn from_rule(kind: &str, rule: &Rule) -> Result<Alerter> {
        Ok(match kind {
            "debug" => Alerter::Debug,
            "email" => Alerter::Email(Email::new(rule)?),
            "slack" => Alerter::Slack(Slack::new(rule)?),
            "post" => Alerter::Post(Post::new(rule)?),
            "command" => Alerter::Command(Command::new(rule)?),
            other => bail!("alerter '{other}' is not supported yet"),
        })
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Alerter::Debug => "debug",
            Alerter::Email(_) => "email",
            Alerter::Slack(_) => "slack",
            Alerter::Post(_) => "post",
            Alerter::Command(_) => "command",
        }
    }

    /// The `alert_info` stored in the writeback doc.
    pub fn info(&self) -> Value {
        match self {
            Alerter::Debug => json!({"type": "debug"}),
            Alerter::Email(e) => json!({"type": "email", "recipients": e.to}),
            Alerter::Slack(s) => json!({"type": "slack", "slack_username_override": s.username}),
            Alerter::Post(p) => json!({"type": "http_post", "http_post_webhook_url": p.urls}),
            Alerter::Command(c) => json!({"type": "command", "command": c.argv.join(" ")}),
        }
    }

    pub async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        match tokio::time::timeout(ALERT_TIMEOUT, self.alert_inner(v, matches)).await {
            Ok(r) => r,
            Err(_) => bail!("timed out after {}s", ALERT_TIMEOUT.as_secs()),
        }
    }

    async fn alert_inner(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        match self {
            Alerter::Debug => {
                alert::debug_alert(v.rule, v.rtype, matches, v.ts_fmt);
                Ok(())
            }
            Alerter::Email(e) => e.alert(v, matches).await,
            Alerter::Slack(s) => s.alert(v, matches).await,
            Alerter::Post(p) => p.alert(matches).await,
            Alerter::Command(c) => c.alert(v, matches).await,
        }
    }
}

fn s(rule: &Rule, key: &str) -> Option<String> {
    rule.raw.get(key).and_then(Value::as_str).map(String::from)
}

fn s_or(rule: &Rule, key: &str, default: &str) -> String {
    s(rule, key).unwrap_or_else(|| default.into())
}

fn b(rule: &Rule, key: &str) -> bool {
    rule.raw.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A string-or-list option as a list.
fn list(rule: &Rule, key: &str) -> Vec<String> {
    match rule.raw.get(key) {
        Some(Value::String(x)) => vec![x.clone()],
        Some(Value::Array(a)) => a.iter().map(py_str).collect(),
        _ => vec![],
    }
}

fn required(rule: &Rule, kind: &str, key: &str) -> Result<()> {
    if !rule.raw.contains_key(key) {
        bail!("alerter {kind} needs the option {key}");
    }
    Ok(())
}

fn http_client(rule: &Rule, proxy: Option<String>, ca: Option<String>, ignore_ssl: bool, timeout: u64) -> Result<reqwest::Client> {
    let _ = rule;
    let mut c = reqwest::Client::builder().timeout(Duration::from_secs(timeout.max(1)));
    if let Some(p) = proxy {
        c = c.proxy(reqwest::Proxy::https(p)?);
    }
    if let Some(ca) = ca {
        let pem = std::fs::read(&ca).with_context(|| format!("reading CA file {ca}"))?;
        for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
            c = c.add_root_certificate(cert);
        }
    }
    if ignore_ssl {
        c = c.danger_accept_invalid_certs(true);
    }
    Ok(c.build()?)
}

/// Replaces `%(name)s`, `{name}` and `{match[name]}` with values from the match (dotted keys work).
pub fn resolve_string(text: &str, m: &Doc) -> String {
    let get = |name: &str| lookup(m, name).map(py_str).unwrap_or_else(|| "<MISSING VALUE>".into());
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(pos) = rest.find(['%', '{', '}']) {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos..];
        let (name, used) = if let Some(t) = tail.strip_prefix("%(") {
            match t.find(")s") {
                Some(e) => (Some(&t[..e]), e + 4),
                None => (None, 0),
            }
        } else if tail.starts_with("{{") {
            out.push('{');
            rest = &tail[2..];
            continue;
        } else if let Some(t) = tail.strip_prefix('{') {
            match t.find('}') {
                Some(e) => (Some(t[..e].strip_prefix("match[").and_then(|x| x.strip_suffix(']')).unwrap_or(&t[..e])), e + 2),
                None => (None, 0),
            }
        } else if tail.starts_with("}}") {
            out.push('}');
            rest = &tail[2..];
            continue;
        } else if tail.starts_with("%%") {
            out.push('%');
            rest = &tail[2..];
            continue;
        } else {
            (None, 0)
        };
        match name {
            Some(n) => {
                out.push_str(&get(n.trim_matches(['\'', '"'])));
                rest = &tail[used..];
            }
            None => {
                out.push_str(&tail[..1]);
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

// ---- email ----

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
    fn new(rule: &Rule) -> Result<Email> {
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

    async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
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

// ---- slack ----

pub struct Slack {
    urls: Vec<String>,
    username: String,
    channels: Vec<String>,
    client: reqwest::Client,
    rule_opts: BTreeMap<&'static str, Value>,
}

impl Slack {
    fn new(rule: &Rule) -> Result<Slack> {
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
            client: http_client(
                rule,
                s(rule, "slack_proxy"),
                s(rule, "slack_ca_certs"),
                b(rule, "slack_ignore_ssl_errors"),
                rule.raw.get("slack_timeout").and_then(Value::as_u64).unwrap_or(10),
            )?,
            rule_opts: opts,
        })
    }

    async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
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
                let resp = self.client.post(url).json(&payload).send().await.map_err(|e| anyhow::anyhow!("Error posting to slack: {e}"))?;
                resp.error_for_status().map_err(|e| anyhow::anyhow!("Error posting to slack: {e}"))?;
            }
        }
        log::info!("Alert '{}' sent to Slack", v.rule.name);
        Ok(())
    }
}

// ---- http post ----

pub struct Post {
    urls: Vec<String>,
    payload: Doc,
    static_payload: Doc,
    all_values: bool,
    headers: Vec<(String, String)>,
    client: reqwest::Client,
}

impl Post {
    fn new(rule: &Rule) -> Result<Post> {
        required(rule, "post", "http_post_url")?;
        let obj = |k: &str| rule.raw.get(k).and_then(Value::as_object).cloned().unwrap_or_default();
        let payload = obj("http_post_payload");
        Ok(Post {
            urls: list(rule, "http_post_url"),
            all_values: rule.raw.get("http_post_all_values").and_then(Value::as_bool).unwrap_or(payload.is_empty()),
            static_payload: obj("http_post_static_payload"),
            headers: obj("http_post_headers").iter().map(|(k, v)| (k.clone(), py_str(v))).collect(),
            client: http_client(
                rule,
                s(rule, "http_post_proxy"),
                s(rule, "http_post_ca_certs"),
                b(rule, "http_post_ignore_ssl_errors"),
                rule.raw.get("http_post_timeout").and_then(Value::as_u64).unwrap_or(10),
            )?,
            payload,
        })
    }

    async fn alert(&self, matches: &[Doc]) -> Result<()> {
        for m in matches {
            let mut body = if self.all_values { m.clone() } else { Doc::new() };
            body.extend(self.static_payload.clone());
            for (post_key, es_key) in &self.payload {
                body.insert(post_key.clone(), es_key.as_str().and_then(|k| lookup(m, k)).cloned().unwrap_or(Value::Null));
            }
            for url in &self.urls {
                let mut req = self.client.post(url).header("Accept", "application/json;charset=utf-8").json(&body);
                for (k, v) in &self.headers {
                    req = req.header(k, v);
                }
                let resp = req.send().await.map_err(|e| anyhow::anyhow!("Error posting HTTP Post alert: {e}"))?;
                resp.error_for_status().map_err(|e| anyhow::anyhow!("Error posting HTTP Post alert: {e}"))?;
            }
            log::info!("HTTP Post alert sent.");
        }
        Ok(())
    }
}

// ---- command ----

pub struct Command {
    argv: Vec<String>,
    shell: bool,
    pipe_json: bool,
    pipe_text: bool,
    fail_on_non_zero: bool,
}

impl Command {
    fn new(rule: &Rule) -> Result<Command> {
        required(rule, "command", "command")?;
        let (argv, shell) = match &rule.raw["command"] {
            Value::String(c) => {
                if c.contains('%') {
                    log::warn!("Warning! You could be vulnerable to shell injection!");
                }
                (vec![c.clone()], true)
            }
            Value::Array(a) => (a.iter().map(py_str).collect(), false),
            _ => bail!("command must be a string or a list"),
        };
        Ok(Command {
            argv,
            shell,
            pipe_json: b(rule, "pipe_match_json"),
            pipe_text: b(rule, "pipe_alert_text"),
            fail_on_non_zero: b(rule, "fail_on_non_zero_exit"),
        })
    }

    async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let argv: Vec<String> = self.argv.iter().map(|a| resolve_string(a, &matches[0])).collect();
        let mut cmd = if self.shell {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(&argv[0]);
            c
        } else {
            let mut c = tokio::process::Command::new(argv.first().context("empty command")?);
            c.args(&argv[1..]);
            c
        };
        let stdin_data = if self.pipe_json {
            Some(format!("{}\n", serde_json::to_string(matches)?))
        } else if self.pipe_text {
            Some(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt))
        } else {
            None
        };
        cmd.stdin(if stdin_data.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() });
        let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!("Error while running command {}: {e}", argv.join(" ")))?;
        if let (Some(data), Some(mut stdin)) = (stdin_data, child.stdin.take()) {
            let _ = stdin.write_all(data.as_bytes()).await;
        }
        if self.fail_on_non_zero {
            let status = child.wait().await?;
            if !status.success() {
                bail!("Non-zero exit code while running command {}", argv.join(" "));
            }
        } else {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
        log::info!("Alert sent to Command");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_string_forms() {
        let m = json!({"user": {"name": "bob"}, "n": 3}).as_object().unwrap().clone();
        assert_eq!(resolve_string("hi {user.name} %(n)s {match[n]} {nope}", &m), "hi bob 3 3 <MISSING VALUE>");
        assert_eq!(resolve_string("100%% {{x}}", &m), "100% {x}");
    }
}
