//! Alerters. Each is built once per rule from its keys; one submodule per alerter or family.

mod command;
mod email;
pub mod http;
mod post;
mod slack;

pub use email::{mailbox, read_account_file, send_mail};

use crate::alert;
use crate::field::{lookup, py_str};
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
            "email" => Alerter::Email(email::Email::new(rule)?),
            "slack" => Alerter::Slack(slack::Slack::new(rule)?),
            "post" => Alerter::Post(post::Post::new(rule)?),
            "command" => Alerter::Command(command::Command::new(rule)?),
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

    /// Serves `n` requests with `status` and returns the base URL and a handle yielding what was received.
    pub async fn capture(n: usize, status: u16) -> (String, tokio::task::JoinHandle<Vec<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut out = vec![];
            for _ in 0..n {
                let (mut sock, _) = listener.accept().await.unwrap();
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
                out.push(Captured { method, path, headers, body: String::from_utf8_lossy(&buf[head_end..head_end + len]).into_owned() });
                let resp = format!("HTTP/1.1 {status} X\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
            out
        });
        (url, task)
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
