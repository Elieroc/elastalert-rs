//! Alerters. Each is built once per rule from its keys; one submodule per alerter or family.

mod alerta;
mod alertmanager;
mod chatwork;
mod command;
mod crypto;
mod datadog;
mod dingtalk;
mod discord;
mod email;
mod flashduty;
mod gelf;
mod gitter;
mod googlechat;
mod hivealerter;
pub mod http;
mod indexer;
mod iris;
mod jira;
mod lark;
mod line;
mod matrixhookshot;
mod mattermost;
mod opsgenie;
mod pagerduty;
mod pagertree;
mod post;
mod post2;
mod power_automate;
mod rocketchat;
mod servicenow;
mod slack;
mod telegram;
mod victorops;
mod webex;
mod workwechat;
mod yzj;
mod zabbix;

pub use email::{mailbox, read_account_file, send_mail};

use crate::alert;
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use crate::types::RuleType;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use std::time::Duration;

pub type Doc = Map<String, Value>;

pub enum Alerter {
    Debug,
    Email(email::Email),
    Slack(slack::Slack),
    Post(post::Post),
    Command(command::Command),
    Post2(post2::Post2),
    Mattermost(mattermost::Mattermost),
    PowerAutomate(power_automate::PowerAutomate),
    Discord(discord::Discord),
    Telegram(telegram::Telegram),
    GoogleChat(googlechat::GoogleChat),
    RocketChat(rocketchat::RocketChat),
    Webex(webex::Webex),
    MatrixHookshot(matrixhookshot::MatrixHookshot),
    Chatwork(chatwork::Chatwork),
    DingTalk(dingtalk::DingTalk),
    Gitter(gitter::Gitter),
    Lark(lark::Lark),
    Line(line::Line),
    WorkWechat(workwechat::WorkWechat),
    Yzj(yzj::Yzj),
    Alerta(alerta::Alerta),
    Alertmanager(alertmanager::Alertmanager),
    Datadog(datadog::Datadog),
    Flashduty(flashduty::Flashduty),
    OpsGenie(opsgenie::OpsGenie),
    PagerDuty(pagerduty::PagerDuty),
    PagerTree(pagertree::PagerTree),
    VictorOps(victorops::VictorOps),
    Zabbix(zabbix::Zabbix),
    Gelf(gelf::Gelf),
    Iris(iris::Iris),
    ServiceNow(servicenow::ServiceNow),
    Hive(hivealerter::Hive),
    Indexer(indexer::Indexer),
    Jira(jira::Jira),
}

/// Read-only view the alerters need to produce text.
pub struct View<'a> {
    pub rule: &'a Rule,
    pub rtype: &'a RuleType,
    pub ts_fmt: Option<&'a str>,
    /// Shared by the alerters of one delivery, like upstream's `Alerter.pipeline`: `jira` leaves `jira_ticket` and
    /// `jira_server` for the `email` and `slack` alerters that run after it.
    pub pipeline: &'a Pipeline,
}

pub type Pipeline = std::sync::Mutex<Doc>;

impl View<'_> {
    /// `<server>/browse/<ticket>` when an earlier alerter opened or found a Jira ticket.
    fn jira_url(&self) -> Option<String> {
        let p = self.pipeline.lock().ok()?;
        let ticket = p.get("jira_ticket")?.as_str()?;
        Some(format!("{}/browse/{ticket}", p.get("jira_server")?.as_str()?))
    }
}

pub const ALERT_TIMEOUT: Duration = Duration::from_secs(60);

impl Alerter {
    pub fn from_rule(kind: &str, rule: &Rule) -> Result<Alerter> {
        Ok(match kind {
            "debug" => Alerter::Debug,
            "email" => Alerter::Email(email::Email::new(rule)?),
            "slack" => Alerter::Slack(slack::Slack::new(rule)?),
            "post" => Alerter::Post(post::Post::new(rule)?),
            "command" => Alerter::Command(command::Command::new(rule)?),
            "post2" => Alerter::Post2(post2::Post2::new(rule)?),
            "mattermost" => Alerter::Mattermost(mattermost::Mattermost::new(rule)?),
            "ms_power_automate" => Alerter::PowerAutomate(power_automate::PowerAutomate::new(rule)?),
            "discord" => Alerter::Discord(discord::Discord::new(rule)?),
            "telegram" => Alerter::Telegram(telegram::Telegram::new(rule)?),
            "googlechat" => Alerter::GoogleChat(googlechat::GoogleChat::new(rule)?),
            "rocketchat" => Alerter::RocketChat(rocketchat::RocketChat::new(rule)?),
            "webex_webhook" => Alerter::Webex(webex::Webex::new(rule)?),
            "matrixhookshot" => Alerter::MatrixHookshot(matrixhookshot::MatrixHookshot::new(rule)?),
            "chatwork" => Alerter::Chatwork(chatwork::Chatwork::new(rule)?),
            "dingtalk" => Alerter::DingTalk(dingtalk::DingTalk::new(rule)?),
            "gitter" => Alerter::Gitter(gitter::Gitter::new(rule)?),
            "lark" => Alerter::Lark(lark::Lark::new(rule)?),
            "line" => Alerter::Line(line::Line::new(rule)?),
            "workwechat" => Alerter::WorkWechat(workwechat::WorkWechat::new(rule)?),
            "yzj" => Alerter::Yzj(yzj::Yzj::new(rule)?),
            "alerta" => Alerter::Alerta(alerta::Alerta::new(rule)?),
            "alertmanager" => Alerter::Alertmanager(alertmanager::Alertmanager::new(rule)?),
            "datadog" => Alerter::Datadog(datadog::Datadog::new(rule)?),
            "flashduty" => Alerter::Flashduty(flashduty::Flashduty::new(rule)?),
            "opsgenie" => Alerter::OpsGenie(opsgenie::OpsGenie::new(rule)?),
            "pagerduty" => Alerter::PagerDuty(pagerduty::PagerDuty::new(rule)?),
            "pagertree" => Alerter::PagerTree(pagertree::PagerTree::new(rule)?),
            "victorops" => Alerter::VictorOps(victorops::VictorOps::new(rule)?),
            "zabbix" => Alerter::Zabbix(zabbix::Zabbix::new(rule)?),
            "gelf" => Alerter::Gelf(gelf::Gelf::new(rule)?),
            "iris" => Alerter::Iris(iris::Iris::new(rule)?),
            "servicenow" => Alerter::ServiceNow(servicenow::ServiceNow::new(rule)?),
            "hivealerter" => Alerter::Hive(hivealerter::Hive::new(rule)?),
            "indexer" => Alerter::Indexer(indexer::Indexer::new(rule)?),
            "jira" => Alerter::Jira(jira::Jira::new(rule)?),
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
            Alerter::Post2(_) => "post2",
            Alerter::Mattermost(_) => "mattermost",
            Alerter::PowerAutomate(_) => "ms_power_automate",
            Alerter::Discord(_) => "discord",
            Alerter::Telegram(_) => "telegram",
            Alerter::GoogleChat(_) => "googlechat",
            Alerter::RocketChat(_) => "rocketchat",
            Alerter::Webex(_) => "webex_webhook",
            Alerter::MatrixHookshot(_) => "matrixhookshot",
            Alerter::Chatwork(_) => "chatwork",
            Alerter::DingTalk(_) => "dingtalk",
            Alerter::Gitter(_) => "gitter",
            Alerter::Lark(_) => "lark",
            Alerter::Line(_) => "line",
            Alerter::WorkWechat(_) => "workwechat",
            Alerter::Yzj(_) => "yzj",
            Alerter::Alerta(_) => "alerta",
            Alerter::Alertmanager(_) => "alertmanager",
            Alerter::Datadog(_) => "datadog",
            Alerter::Flashduty(_) => "flashduty",
            Alerter::OpsGenie(_) => "opsgenie",
            Alerter::PagerDuty(_) => "pagerduty",
            Alerter::PagerTree(_) => "pagertree",
            Alerter::VictorOps(_) => "victorops",
            Alerter::Zabbix(_) => "zabbix",
            Alerter::Gelf(_) => "gelf",
            Alerter::Iris(_) => "iris",
            Alerter::ServiceNow(_) => "servicenow",
            Alerter::Hive(_) => "hivealerter",
            Alerter::Indexer(_) => "indexer",
            Alerter::Jira(_) => "jira",
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
            Alerter::Post2(a) => a.info(),
            Alerter::Mattermost(a) => a.info(),
            Alerter::PowerAutomate(a) => a.info(),
            Alerter::Discord(a) => a.info(),
            Alerter::Telegram(a) => a.info(),
            Alerter::GoogleChat(a) => a.info(),
            Alerter::RocketChat(a) => a.info(),
            Alerter::Webex(a) => a.info(),
            Alerter::MatrixHookshot(a) => a.info(),
            Alerter::Chatwork(a) => a.info(),
            Alerter::DingTalk(a) => a.info(),
            Alerter::Gitter(a) => a.info(),
            Alerter::Lark(a) => a.info(),
            Alerter::Line(a) => a.info(),
            Alerter::WorkWechat(a) => a.info(),
            Alerter::Yzj(a) => a.info(),
            Alerter::Alerta(a) => a.info(),
            Alerter::Alertmanager(a) => a.info(),
            Alerter::Datadog(a) => a.info(),
            Alerter::Flashduty(a) => a.info(),
            Alerter::OpsGenie(a) => a.info(),
            Alerter::PagerDuty(a) => a.info(),
            Alerter::PagerTree(a) => a.info(),
            Alerter::VictorOps(a) => a.info(),
            Alerter::Zabbix(a) => a.info(),
            Alerter::Gelf(a) => a.info(),
            Alerter::Iris(a) => a.info(),
            Alerter::ServiceNow(a) => a.info(),
            Alerter::Hive(a) => a.info(),
            Alerter::Indexer(a) => a.info(),
            Alerter::Jira(a) => a.info(),
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
            Alerter::Post2(a) => a.alert(matches).await,
            Alerter::Mattermost(a) => a.alert(v, matches).await,
            Alerter::PowerAutomate(a) => a.alert(v, matches).await,
            Alerter::Discord(a) => a.alert(v, matches).await,
            Alerter::Telegram(a) => a.alert(v, matches).await,
            Alerter::GoogleChat(a) => a.alert(v, matches).await,
            Alerter::RocketChat(a) => a.alert(v, matches).await,
            Alerter::Webex(a) => a.alert(v, matches).await,
            Alerter::MatrixHookshot(a) => a.alert(v, matches).await,
            Alerter::Chatwork(a) => a.alert(v, matches).await,
            Alerter::DingTalk(a) => a.alert(v, matches).await,
            Alerter::Gitter(a) => a.alert(v, matches).await,
            Alerter::Lark(a) => a.alert(v, matches).await,
            Alerter::Line(a) => a.alert(v, matches).await,
            Alerter::WorkWechat(a) => a.alert(v, matches).await,
            Alerter::Yzj(a) => a.alert(v, matches).await,
            Alerter::Alerta(a) => a.alert(v, matches).await,
            Alerter::Alertmanager(a) => a.alert(v, matches).await,
            Alerter::Datadog(a) => a.alert(v, matches).await,
            Alerter::Flashduty(a) => a.alert(v, matches).await,
            Alerter::OpsGenie(a) => a.alert(v, matches).await,
            Alerter::PagerDuty(a) => a.alert(v, matches).await,
            Alerter::PagerTree(a) => a.alert(v, matches).await,
            Alerter::VictorOps(a) => a.alert(v, matches).await,
            Alerter::Zabbix(a) => a.alert(v, matches).await,
            Alerter::Gelf(a) => a.alert(v, matches).await,
            Alerter::Iris(a) => a.alert(v, matches).await,
            Alerter::ServiceNow(a) => a.alert(v, matches).await,
            Alerter::Hive(a) => a.alert(v, matches).await,
            Alerter::Indexer(a) => a.alert(v, matches).await,
            Alerter::Jira(a) => a.alert(v, matches).await,
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

/// The option as set, else `default`.
fn opt(rule: &Rule, key: &str, default: Value) -> Value {
    rule.raw.get(key).cloned().unwrap_or(default)
}

/// Text of `matches` as upstream's `str(BasicMatchString)` loop builds it (Discord, Telegram): no aggregation summary.
fn per_match_text(v: &View<'_>, matches: &[Doc]) -> String {
    let mut body = String::new();
    for m in matches {
        body.push_str(&alert::match_body(v.rule, v.rtype, m, v.ts_fmt));
        if matches.len() > 1 {
            body.push_str("\n----------------------------------------\n");
        }
    }
    body
}

/// Python `text[:keep] + suffix` when `text` is longer than `limit` characters.
fn crop(text: String, limit: usize, keep: usize, suffix: &str) -> String {
    if text.chars().count() > limit { text.chars().take(keep).collect::<String>() + suffix } else { text }
}

/// `kibana_discover_url` / `opensearch_discover_url` of the first match, when set.
fn discover_url<'a>(matches: &'a [Doc], kind: &str) -> Option<&'a Value> {
    lookup(&matches[0], &format!("{kind}_discover_url")).filter(|u| truthy(Some(u)))
}

/// `template.format(*values)` where each value is the match field named in `args`, else the rule option of that name, else `missing`.
fn format_with_args(rule: &Rule, template: &str, args: &[Value], m: &Doc, missing: &str) -> String {
    let values: Vec<String> = args
        .iter()
        .map(|a| {
            let name = py_str(a);
            let found = lookup(m, &name).filter(|v| !v.is_null()).or_else(|| rule.raw.get(&name).filter(|v| truthy(Some(v))));
            found.map(py_str).unwrap_or_else(|| missing.to_string())
        })
        .collect();
    alert::py_format(template, &values, &Map::new())
}

/// Match field `name`, else the rule option of that name, else `default` (upstream's `lookup_field`).
fn lookup_field(rule: &Rule, m: &Doc, name: &str, default: Value) -> Value {
    match lookup(m, name).filter(|v| !v.is_null()) {
        Some(v) => v.clone(),
        None => rule.raw.get(name).cloned().unwrap_or(default),
    }
}

/// `json.dumps(value)` as Python prints it: `", "` and `": "` separators, non-ASCII escaped.
fn py_json_dumps(v: &Value) -> String {
    match v {
        Value::String(s) => {
            let mut out = String::from("\"");
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            out.push_str(&format!("\\u{unit:04x}"));
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
            out
        }
        Value::Array(a) => format!("[{}]", a.iter().map(py_json_dumps).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!("{{{}}}", o.iter().map(|(k, x)| format!("{}: {}", py_json_dumps(&json!(k)), py_json_dumps(x))).collect::<Vec<_>>().join(", ")),
        other => other.to_string(),
    }
}

fn missing_text(rule: &Rule) -> &str {
    rule.raw.get("alert_missing_value").and_then(Value::as_str).unwrap_or("<MISSING VALUE>")
}

fn required(rule: &Rule, kind: &str, key: &str) -> Result<()> {
    if !rule.raw.contains_key(key) {
        bail!("alerter {kind} needs the option {key}");
    }
    Ok(())
}

/// Replaces `%(name)s`, `{name}` and `{match[name]}` with values from the match (dotted keys work).
pub fn resolve_string(text: &str, m: &Doc) -> String {
    resolve_string_with(text, m, "<MISSING VALUE>")
}

/// `resolve_string` with the rule's `alert_missing_value` as the text for unknown fields.
pub fn resolve_string_with(text: &str, m: &Doc, missing: &str) -> String {
    let get = |name: &str| lookup(m, name).map(py_str).unwrap_or_else(|| missing.to_string());
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

#[cfg(test)]
pub(crate) mod testutil {
    //! Rule builder and an in-process HTTP capture server for alerter tests.
    use crate::config::Config;
    use crate::rule::{self, Rule};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Loads a minimal `any` rule with `alert: <alert>` followed by `extra` YAML lines.
    pub fn rule(alert: &str, extra: &str) -> anyhow::Result<Rule> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ea-alerter-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("r.yaml");
        std::fs::write(&file, format!("name: r\ntype: any\nindex: logs-*\nalert: {alert}\n{extra}")).unwrap();
        let conf = Config::load_with_defaults(&dir.join("none.yaml")).unwrap();
        let r = rule::load(&file, &conf);
        std::fs::remove_dir_all(&dir).ok();
        r
    }

    pub struct Captured {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    impl Captured {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
        pub fn json(&self) -> serde_json::Value {
            serde_json::from_str(&self.body).unwrap()
        }
    }

    async fn read_request(sock: &mut tokio::net::TcpStream) -> Captured {
        let mut buf = vec![];
        let (head_end, len) = loop {
            let mut chunk = [0u8; 4096];
            let k = sock.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..k]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).to_lowercase();
                let len = head.lines().find_map(|l| l.strip_prefix("content-length:")).map(|v| v.trim().parse().unwrap()).unwrap_or(0usize);
                break (i + 4, len);
            }
            assert!(k > 0, "connection closed before headers");
        };
        while buf.len() < head_end + len {
            let mut chunk = [0u8; 4096];
            let k = sock.read(&mut chunk).await.unwrap();
            buf.extend_from_slice(&chunk[..k]);
        }
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let mut lines = head.lines();
        let mut first = lines.next().unwrap().split(' ');
        let (method, path) = (first.next().unwrap().to_string(), first.next().unwrap().to_string());
        let headers = lines.filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Captured { method, path, headers, body: String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned() }
    }

    async fn respond(sock: &mut tokio::net::TcpStream, status: u16, body: &str) {
        let resp = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        sock.write_all(resp.as_bytes()).await.unwrap();
    }

    /// Serves `n` requests with `status` and returns the base URL and a handle yielding what was received.
    pub async fn capture(n: usize, status: u16) -> (String, tokio::task::JoinHandle<Vec<Captured>>) {
        capture_with(n, status, "ok").await
    }

    /// Like `capture`, answering every request with `body`.
    pub async fn capture_with(n: usize, status: u16, body: &'static str) -> (String, tokio::task::JoinHandle<Vec<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut out = vec![];
            for _ in 0..n {
                let (mut sock, _) = listener.accept().await.unwrap();
                out.push(read_request(&mut sock).await);
                respond(&mut sock, status, body).await;
            }
            out
        });
        (url, task)
    }

    /// `(method, path prefix, status, body)`: the first route that matches answers; no match is a 404.
    pub type Route = (&'static str, &'static str, u16, String);

    /// A mock server for a multi-call API. Returns its URL and the log of requests (in arrival order).
    pub async fn serve(routes: Vec<Route>) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Captured>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let log = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let seen = log.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                let req = read_request(&mut sock).await;
                let (status, body) = routes
                    .iter()
                    .find(|(m, p, _, _)| *m == req.method && req.path.starts_with(p))
                    .map_or((404, "{}".to_string()), |(_, _, s, b)| (*s, b.clone()));
                seen.lock().unwrap().push(req);
                respond(&mut sock, status, &body).await;
            }
        });
        (url, log)
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

    #[tokio::test]
    async fn http_helper_posts_json_and_maps_status() {
        let rule = testutil::rule("debug", "x_timeout: 5\n").unwrap();
        let http = http::Http::new(&rule, "x", 10).unwrap();
        let (url, got) = testutil::capture(1, 200).await;
        http.post_json("test", &format!("{url}/hook"), &[("X-Token".into(), "t".into())], &json!({"a": 1})).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!((got[0].method.as_str(), got[0].path.as_str()), ("POST", "/hook"));
        assert_eq!(got[0].header("x-token"), Some("t"));
        assert_eq!(got[0].json(), json!({"a": 1}));

        let (url, _) = testutil::capture(1, 500).await;
        let err = http.post_json("test", &url, &[], &json!({})).await.err().unwrap();
        assert!(err.to_string().starts_with("Error posting test:"), "{err}");
    }
}
