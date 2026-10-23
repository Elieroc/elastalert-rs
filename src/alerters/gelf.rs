//! `gelf` alerter: a GELF message over HTTP or TCP.

use super::http::Http;
use super::{Doc, View, opt, py_json_dumps, required, s};
use crate::rule::Rule;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

enum Transport {
    Http { endpoint: String, headers: Vec<(String, String)>, http: Http },
    Tcp { host: String, port: u16, timeout: Duration },
}

pub struct Gelf {
    kind: &'static str,
    transport: Transport,
    fields: Map<String, Value>,
    version: Value,
    level: Value,
}

/// The machine's host name (upstream sends `socket.getfqdn()`; no DNS lookup here).
fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "localhost".into())
}

impl Gelf {
    pub(super) fn new(rule: &Rule) -> Result<Gelf> {
        required(rule, "gelf", "gelf_type")?;
        let kind = s(rule, "gelf_type").unwrap_or_default();
        let timeout = rule.raw.get("gelf_timeout").and_then(Value::as_u64).unwrap_or(30);
        let transport = match kind.as_str() {
            "http" => {
                let Some(endpoint) = s(rule, "gelf_endpoint") else { bail!("Error! Gelf http required \"gelf_endpoint\" variable") };
                let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
                if let Some(extra) = rule.raw.get("gelf_http_headers").and_then(Value::as_object) {
                    headers.extend(extra.iter().map(|(k, v)| (k.clone(), crate::field::py_str(v))));
                }
                let ignore = rule.raw.get("gelf_http_ignore_ssl_errors").is_some_and(|v| crate::field::truthy(Some(v)));
                Transport::Http { endpoint, headers, http: Http::raw(None, s(rule, "gelf_ca_cert").as_deref(), ignore, timeout)? }
            }
            "tcp" => {
                let (Some(host), Some(port)) = (s(rule, "gelf_host"), rule.raw.get("gelf_port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok())) else {
                    bail!("Error! Gelf tcp required \"gelf_host\" and \"gelf_port\" variables")
                };
                // Upstream wraps the socket with a server-side TLS context, which cannot work.
                if rule.raw.contains_key("gelf_ca_cert") {
                    bail!("gelf_ca_cert is not supported with gelf_type: tcp (TLS over TCP does not work upstream either)");
                }
                Transport::Tcp { host, port, timeout: Duration::from_secs(timeout) }
            }
            // Upstream accepts other values at load and then sends nothing.
            other => bail!("gelf_type must be http or tcp, got {other:?}"),
        };
        Ok(Gelf {
            kind: if kind == "http" { "http" } else { "tcp" },
            transport,
            fields: rule.raw.get("gelf_payload").and_then(Value::as_object).cloned().unwrap_or_default(),
            version: opt(rule, "gelf_version", json!("1.1")),
            level: opt(rule, "gelf_log_level", json!(5)),
        })
    }

    fn message(&self, v: &View<'_>, matches: &[Doc]) -> Value {
        let mut alert_message = Map::new();
        alert_message.insert("Title".into(), json!(v.rule.name));
        for m in matches {
            for (key, field) in &self.fields {
                alert_message.insert(key.clone(), field.as_str().and_then(|f| m.get(f)).cloned().unwrap_or(Value::Null));
            }
        }
        json!({
            "version": self.version,
            "host": host_name(),
            "short_message": py_json_dumps(&Value::Object(alert_message)),
            "level": self.level,
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let msg = self.message(v, matches);
        match &self.transport {
            Transport::Http { endpoint, headers, http } => {
                // Upstream ignores the HTTP status; only transport errors fail.
                http.request(reqwest::Method::POST, "posting GELF message via HTTP", endpoint, headers, Some(&msg)).await?;
                log::info!("GELF message sent via HTTP.");
            }
            Transport::Tcp { host, port, timeout } => {
                let mut bytes = serde_json::to_vec(&msg)?;
                bytes.push(0);
                let send = async {
                    let mut sock = tokio::net::TcpStream::connect((host.as_str(), *port)).await.with_context(|| format!("connecting to {host}:{port}"))?;
                    sock.write_all(&bytes).await?;
                    sock.shutdown().await.ok();
                    anyhow::Ok(())
                };
                tokio::time::timeout(*timeout, send).await.map_err(|_| anyhow!("Error posting GELF message via TCP: timed out"))?.map_err(|e| anyhow!("Error posting GELF message via TCP: {e:#}"))?;
                log::info!("GELF message sent via TCP.");
            }
        }
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "gelf", "gelf_type": self.kind})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;
    use tokio::io::AsyncReadExt;

    fn m() -> Doc {
        json!({"host": "web-1", "user": "bob", "n": 2}).as_object().unwrap().clone()
    }

    #[test]
    fn option_validation() {
        assert!(Gelf::new(&rule("gelf", "gelf_type: http\n").unwrap()).is_err());
        assert!(Gelf::new(&rule("gelf", "gelf_type: tcp\ngelf_host: h\n").unwrap()).is_err());
        assert!(Gelf::new(&rule("gelf", "gelf_type: udp\ngelf_host: h\ngelf_port: 1\n").unwrap()).is_err());
        assert!(Gelf::new(&rule("gelf", "gelf_type: tcp\ngelf_host: h\ngelf_port: 1\ngelf_ca_cert: /x\n").unwrap()).is_err());
    }

    #[tokio::test]
    async fn http_message_ignores_status() {
        let (url, got) = capture(1, 500).await;
        let r = rule("gelf", &format!("gelf_type: http\ngelf_endpoint: {url}/gelf\ngelf_payload: {{who: user, gone: absent}}\ngelf_http_headers: {{X-Token: t}}\ngelf_log_level: 3\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Gelf::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].header("x-token"), Some("t"));
        let body = got[0].json();
        assert_eq!((&body["version"], &body["level"]), (&json!("1.1"), &json!(3)));
        assert_eq!(body["short_message"], json!(r#"{"Title": "r", "gone": null, "who": "bob"}"#));
        assert!(body["host"].as_str().is_some_and(|h| !h.is_empty()));
    }

    #[tokio::test]
    async fn tcp_message_is_nul_terminated() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![];
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });
        let r = rule("gelf", &format!("gelf_type: tcp\ngelf_host: 127.0.0.1\ngelf_port: {port}\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Gelf::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let buf = task.await.unwrap();
        assert_eq!(buf.last(), Some(&0));
        let msg: Value = serde_json::from_slice(&buf[..buf.len() - 1]).unwrap();
        assert_eq!(msg["short_message"], json!(r#"{"Title": "r"}"#));
    }
}
