//! `stomp` alerter: publishes the alert as JSON to a STOMP broker (ActiveMQ and the like).

use super::{Doc, View, opt, py_json_dumps, required, s_or};
use crate::alert::{create_alert_body, match_body};
use crate::field::{lookup, py_str};
use crate::rule::Rule;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(10);

pub struct Stomp {
    host: String,
    port: String,
    login: String,
    password: String,
    destination: String,
}

fn frame(command: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("{command}\n").into_bytes();
    for (k, v) in headers {
        out.extend(format!("{k}:{v}\n").bytes());
    }
    out.push(b'\n');
    out.extend(body);
    out.push(0);
    out
}

/// Reads one frame: its command and headers (the body is dropped).
async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R) -> Result<(String, Map<String, Value>)> {
    let mut raw = vec![];
    loop {
        raw.clear();
        if r.read_until(0, &mut raw).await? == 0 {
            bail!("the broker closed the connection");
        }
        // heart-beats are bare newlines between frames
        if raw.iter().any(|b| !matches!(b, b'\n' | b'\r' | 0)) {
            break;
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let head = text.trim_start_matches(['\n', '\r']);
    let (head, _body) = head.split_once("\n\n").unwrap_or((head.trim_end_matches('\0'), ""));
    let mut lines = head.lines();
    let command = lines.next().unwrap_or_default().trim().to_string();
    let headers = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.to_string(), json!(v))).collect();
    Ok((command, headers))
}

impl Stomp {
    pub(super) fn new(rule: &Rule) -> Result<Stomp> {
        for k in ["stomp_hostname", "stomp_hostport", "stomp_login", "stomp_password"] {
            required(rule, "stomp", k)?;
        }
        Ok(Stomp {
            host: s_or(rule, "stomp_hostname", "localhost"),
            port: py_str(&opt(rule, "stomp_hostport", json!("61613"))),
            login: py_str(&opt(rule, "stomp_login", json!("admin"))),
            password: py_str(&opt(rule, "stomp_password", json!("admin"))),
            destination: s_or(rule, "stomp_destination", "/queue/ALERT"),
        })
    }

    /// The message upstream publishes. `now` is the local time as `%Y-%m-%d %H:%M:%S`.
    fn message(&self, v: &View<'_>, matches: &[Doc], now: &str) -> Value {
        let ts = |m: &Doc| lookup(m, &v.rule.timestamp_field).map(py_str).unwrap_or_else(|| "None".into());
        let mut alerts = vec![];
        let mut last_match = Value::Null;
        for m in matches {
            let qk = v.rule.query_key.as_deref().and_then(|qk| lookup(m, qk)).filter(|x| !x.is_null());
            match qk {
                Some(q) => {
                    alerts.push(format!("Alert for {}, {} at {}:", v.rule.name, py_str(q), ts(m)));
                    last_match = q.clone();
                }
                None => {
                    alerts.push(format!("Rule {} generated an alert at {}:", v.rule.name, ts(m)));
                    last_match = lookup(m, &v.rule.timestamp_field).cloned().unwrap_or(Value::Null);
                }
            }
        }
        json!({
            "match": last_match,
            "alerts": alerts,
            "rule": v.rule.name,
            "rule_file": v.rule.raw.get("rule_file").cloned().unwrap_or(Value::Null),
            // upstream's loop variable: only the last match is described here
            "matching": matches.last().map(|m| match_body(v.rule, v.rtype, m, v.ts_fmt)).unwrap_or_default(),
            "alertDate": now,
            "body": create_alert_body(v.rule, v.rtype, matches, v.ts_fmt),
            "matches": matches,
        })
    }

    async fn publish(&self, body: &str) -> Result<()> {
        let port: u16 = self.port.parse().with_context(|| format!("invalid stomp_hostport {:?}", self.port))?;
        let sock = TcpStream::connect((self.host.as_str(), port)).await.with_context(|| format!("connecting to {}:{port}", self.host))?;
        let (read, mut write) = sock.into_split();
        let mut read = BufReader::new(read);
        write
            .write_all(&frame("CONNECT", &[("accept-version", "1.0,1.1,1.2".into()), ("host", self.host.clone()), ("login", self.login.clone()), ("passcode", self.password.clone())], b""))
            .await?;
        let (command, headers) = read_frame(&mut read).await?;
        if command != "CONNECTED" {
            bail!("the broker answered {command} {}", headers.get("message").map(py_str).unwrap_or_default());
        }
        write.write_all(&frame("SEND", &[("destination", self.destination.clone()), ("content-length", body.len().to_string())], body.as_bytes())).await?;
        let receipt = uuid::Uuid::new_v4().to_string();
        write.write_all(&frame("DISCONNECT", &[("receipt", receipt)], b"")).await?;
        // wait for the broker to take the message; a closed connection is as good as a receipt
        let mut rest = vec![];
        let _ = tokio::time::timeout(Duration::from_secs(2), read.read_to_end(&mut rest)).await;
        Ok(())
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let message = self.message(v, matches, &chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string());
        let body = py_json_dumps(&message);
        let r = tokio::time::timeout(TIMEOUT, self.publish(&body)).await.map_err(|_| anyhow!("timed out"))?;
        r.map_err(|e| anyhow!("Error posting to Stomp: {e:#}"))?;
        log::info!("Alert sent to Stomp");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "stomp"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;
    use crate::types::RuleType;
    use tokio::net::TcpListener;

    /// A broker that accepts one client, answers CONNECTED and a RECEIPT, and returns the frames it read.
    async fn broker(reply: &'static str) -> (u16, tokio::task::JoinHandle<Vec<(String, Map<String, Value>, String)>>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (sock, _) = l.accept().await.unwrap();
            let (r, mut w) = sock.into_split();
            let mut r = BufReader::new(r);
            let mut seen = vec![];
            for _ in 0..3 {
                let mut raw = vec![];
                r.read_until(0, &mut raw).await.unwrap();
                let text = String::from_utf8_lossy(&raw[..raw.len() - 1]).into_owned();
                let (head, body) = text.split_once("\n\n").unwrap_or((&text, ""));
                let mut lines = head.lines();
                let command = lines.next().unwrap().to_string();
                let headers: Map<String, Value> = lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.to_string(), json!(v))).collect();
                seen.push((command.clone(), headers.clone(), body.to_string()));
                match command.as_str() {
                    "CONNECT" => {
                        w.write_all(reply.as_bytes()).await.unwrap();
                        if !reply.starts_with("CONNECTED") {
                            break;
                        }
                    }
                    "DISCONNECT" => {
                        w.write_all(format!("RECEIPT\nreceipt-id:{}\n\n\0", headers["receipt"].as_str().unwrap()).as_bytes()).await.unwrap();
                    }
                    _ => {}
                }
            }
            seen
        });
        (port, task)
    }

    fn m() -> Doc {
        json!({"@timestamp": "2024-01-01T10:00:00Z", "host": "web-1"}).as_object().unwrap().clone()
    }

    #[tokio::test]
    async fn connect_send_disconnect() {
        let (port, seen) = broker("CONNECTED\nversion:1.2\n\n\0").await;
        let r = rule("stomp", &format!("stomp_hostname: 127.0.0.1\nstomp_hostport: {port}\nstomp_login: me\nstomp_password: pw\nstomp_destination: /topic/x\nquery_key: host\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Stomp::new(&r).unwrap().alert(&v, &[m(), m()]).await.unwrap();
        let seen = seen.await.unwrap();
        assert_eq!(seen[0].0, "CONNECT");
        assert_eq!((seen[0].1["login"].as_str(), seen[0].1["passcode"].as_str()), (Some("me"), Some("pw")));
        assert_eq!(seen[1].0, "SEND");
        assert_eq!((seen[1].1["destination"].as_str(), seen[1].1["content-length"].as_str()), (Some("/topic/x"), Some(seen[1].2.len().to_string().as_str())));
        let msg: Value = serde_json::from_str(&seen[1].2).unwrap();
        assert_eq!(msg["rule"], json!("r"));
        assert_eq!(msg["match"], json!("web-1"));
        assert_eq!(msg["alerts"], json!(["Alert for r, web-1 at 2024-01-01T10:00:00Z:", "Alert for r, web-1 at 2024-01-01T10:00:00Z:"]));
        assert_eq!(msg["matches"].as_array().unwrap().len(), 2);
        assert!(msg["body"].as_str().unwrap().starts_with("r\n\n"));
        assert_eq!(msg["alertDate"].as_str().unwrap().len(), 19);
        assert_eq!(seen[2].0, "DISCONNECT");
    }

    #[test]
    fn message_without_query_key_uses_the_timestamp() {
        let r = rule("stomp", "stomp_hostname: h\nstomp_hostport: 1\nstomp_login: l\nstomp_password: p\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let msg = Stomp::new(&r).unwrap().message(&v, &[m()], "NOW");
        assert_eq!(msg["alerts"], json!(["Rule r generated an alert at 2024-01-01T10:00:00Z:"]));
        assert_eq!((&msg["match"], &msg["alertDate"]), (&json!("2024-01-01T10:00:00Z"), &json!("NOW")));
    }

    #[tokio::test]
    async fn broker_errors_are_reported() {
        let (port, _) = broker("ERROR\nmessage:bad credentials\n\n\0").await;
        let r = rule("stomp", &format!("stomp_hostname: 127.0.0.1\nstomp_hostport: {port}\nstomp_login: l\nstomp_password: p\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let err = Stomp::new(&r).unwrap().alert(&v, &[m()]).await.unwrap_err().to_string();
        assert_eq!(err, "Error posting to Stomp: the broker answered ERROR bad credentials");
        assert!(Stomp::new(&rule("stomp", "stomp_hostname: h\n").unwrap()).is_err());
    }
}
