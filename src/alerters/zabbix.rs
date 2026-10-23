//! `zabbix` alerter: one `sender data` trapper request per alert (the `zabbix_sender` protocol, without TLS).

use super::{Doc, View, opt, required, s, s_or};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use crate::time;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_FORMAT: &str = "%Y-%m-%dT%H:%M:%S.%f%z";

pub struct Zabbix {
    host: String,
    port: u16,
    host_from_field: bool,
    zbx_host: Value,
    key: String,
    timestamp_field: String,
    strptime: String,
}

/// Python `strptime` format -> chrono (`.%f` becomes a flexible fraction).
fn chrono_format(py: &str) -> String {
    py.replace(".%f", "%.f").replace("%f", "%.f")
}

/// Epoch seconds of a match timestamp, as upstream reads it: plain numbers are epochs, anything with `:` and `-` is parsed with
/// `timestamp_strptime`, falling back to ISO without fraction.
fn epoch(value: &str, strptime: &str) -> Result<i64> {
    if !value.contains(':') || !value.contains('-') {
        return value.trim().parse::<i64>().with_context(|| format!("invalid literal for int(): {value:?}"));
    }
    let parsed = chrono::DateTime::parse_from_str(value, &chrono_format(strptime))
        .map(|d| d.timestamp())
        .ok()
        .or_else(|| chrono::DateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%z").map(|d| d.timestamp()).ok())
        .or_else(|| time::parse_iso(value).map(|t| t.div_euclid(1_000_000)));
    parsed.ok_or_else(|| anyhow!("time data {value:?} does not match format {strptime:?}"))
}

impl Zabbix {
    pub(super) fn new(rule: &Rule) -> Result<Zabbix> {
        required(rule, "zabbix", "zbx_host")?;
        required(rule, "zabbix", "zbx_key")?;
        let port = opt(rule, "zbx_sender_port", json!(10051)).as_u64().and_then(|p| u16::try_from(p).ok());
        let Some(port) = port else { bail!("zbx_sender_port must be a port number") };
        Ok(Zabbix {
            host: s_or(rule, "zbx_sender_host", "localhost"),
            port,
            host_from_field: rule.raw.get("zbx_host_from_field").is_some_and(|v| truthy(Some(v))),
            zbx_host: rule.raw["zbx_host"].clone(),
            key: s(rule, "zbx_key").unwrap_or_default(),
            timestamp_field: rule.timestamp_field.clone(),
            strptime: s_or(rule, "timestamp_strptime", DEFAULT_FORMAT),
        })
    }

    fn items(&self, matches: &[Doc]) -> Result<Vec<Value>> {
        matches
            .iter()
            .map(|m| {
                let raw = m.get(&self.timestamp_field).ok_or_else(|| anyhow!("KeyError: '{}'", self.timestamp_field))?;
                let clock = match raw {
                    Value::Number(n) => n.as_f64().unwrap_or(0.0) as i64,
                    other => epoch(&py_str(other), &self.strptime)?,
                };
                let host = if self.host_from_field { self.zbx_host.as_str().and_then(|f| lookup(m, f)).cloned().unwrap_or(Value::Null) } else { self.zbx_host.clone() };
                Ok(json!({"host": host, "key": self.key, "value": "1", "clock": clock}))
            })
            .collect()
    }

    /// Sends the items and returns the `failed` count the server reports.
    async fn send(&self, items: Vec<Value>) -> Result<u64> {
        let body = serde_json::to_vec(&json!({"request": "sender data", "data": items}))?;
        let mut packet = b"ZBXD\x01".to_vec();
        packet.extend((body.len() as u64).to_le_bytes());
        packet.extend(body);
        let exchange = async {
            let mut sock = TcpStream::connect((self.host.as_str(), self.port)).await.with_context(|| format!("connecting to {}:{}", self.host, self.port))?;
            sock.write_all(&packet).await?;
            let mut head = [0u8; 13];
            sock.read_exact(&mut head).await.context("reading the response header")?;
            if &head[..4] != b"ZBXD" {
                bail!("invalid response header from the Zabbix server");
            }
            let len = u64::from_le_bytes(head[5..13].try_into().unwrap()) as usize;
            let mut resp = vec![0u8; len];
            sock.read_exact(&mut resp).await.context("reading the response")?;
            Ok(resp)
        };
        let resp = tokio::time::timeout(TIMEOUT, exchange).await.map_err(|_| anyhow!("timed out"))??;
        let resp: Value = serde_json::from_slice(&resp).context("invalid response from the Zabbix server")?;
        if resp["response"] != json!("success") {
            bail!("the Zabbix server answered {}", resp["response"]);
        }
        let info = resp["info"].as_str().unwrap_or("");
        Ok(info.split("failed:").nth(1).and_then(|t| t.trim_start().split(|c: char| !c.is_ascii_digit()).next()).and_then(|n| n.parse().ok()).unwrap_or(0))
    }

    pub(super) async fn alert(&self, _v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let items = self.items(matches)?;
        let last_host = items.last().map(|i| i["host"].clone()).unwrap_or(Value::Null);
        let failed = self.send(items).await.map_err(|e| anyhow!("Error sending alert to Zabbix: {e}"))?;
        let host = py_str(&last_host);
        if failed > 0 {
            if self.host_from_field && last_host.is_null() {
                log::warn!("Missing term '{}' or host's item '{}', alert will be discarded", py_str(&self.zbx_host), self.key);
            } else {
                log::warn!("Missing zabbix host '{host}' or host's item '{}', alert will be discarded", self.key);
            }
        } else {
            log::info!("Alert sent to '{}:{}' zabbix server, '{host}' zabbix host, '{}' zabbix host key", self.host, self.port, self.key);
        }
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "zabbix Alerter"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::rule;
    use crate::types::RuleType;
    use tokio::net::TcpListener;

    #[test]
    fn timestamps() {
        assert_eq!(epoch("1700000000", DEFAULT_FORMAT).unwrap(), 1_700_000_000);
        assert_eq!(epoch("2023-11-14T22:13:20.123456+0000", DEFAULT_FORMAT).unwrap(), 1_700_000_000);
        assert_eq!(epoch("2023-11-14T22:13:20+0000", DEFAULT_FORMAT).unwrap(), 1_700_000_000);
        assert_eq!(epoch("2023-11-14T22:13:20Z", DEFAULT_FORMAT).unwrap(), 1_700_000_000);
        assert_eq!(epoch("2023-11-14 22:13:20 +0000", "%Y-%m-%d %H:%M:%S %z").unwrap(), 1_700_000_000);
        assert!(epoch("not-a:time", DEFAULT_FORMAT).is_err());
    }

    #[test]
    fn items_use_host_or_field() {
        let z = Zabbix::new(&rule("zabbix", "zbx_host: hostfield\nzbx_key: k\nzbx_host_from_field: true\n").unwrap()).unwrap();
        let m = json!({"@timestamp": "2023-11-14T22:13:20Z", "hostfield": "web-1"}).as_object().unwrap().clone();
        let lonely = json!({"@timestamp": 1_700_000_001}).as_object().unwrap().clone();
        assert_eq!(
            z.items(&[m, lonely]).unwrap(),
            vec![json!({"host": "web-1", "key": "k", "value": "1", "clock": 1_700_000_000}), json!({"host": null, "key": "k", "value": "1", "clock": 1_700_000_001})]
        );
    }

    /// Fake trapper: reads one request, answers with `info`, hands back the decoded request.
    async fn fake_server(info: &'static str) -> (u16, tokio::task::JoinHandle<Value>) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut sock, _) = l.accept().await.unwrap();
            let mut head = [0u8; 13];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[..5], b"ZBXD\x01");
            let mut body = vec![0u8; u64::from_le_bytes(head[5..].try_into().unwrap()) as usize];
            sock.read_exact(&mut body).await.unwrap();
            let resp = serde_json::to_vec(&json!({"response": "success", "info": info})).unwrap();
            let mut out = b"ZBXD\x01".to_vec();
            out.extend((resp.len() as u64).to_le_bytes());
            out.extend(resp);
            sock.write_all(&out).await.unwrap();
            serde_json::from_slice(&body).unwrap()
        });
        (port, task)
    }

    #[tokio::test]
    async fn sends_trapper_request() {
        for (info, ok) in [("processed: 1; failed: 0; total: 1; seconds spent: 0.000050", true), ("processed: 0; failed: 1; total: 1; seconds spent: 0.000050", false)] {
            let (port, got) = fake_server(info).await;
            let r = rule("zabbix", &format!("zbx_host: web-1\nzbx_key: elastalert.hit\nzbx_sender_host: 127.0.0.1\nzbx_sender_port: {port}\n")).unwrap();
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
            let z = Zabbix::new(&r).unwrap();
            let m = json!({"@timestamp": "2023-11-14T22:13:20Z"}).as_object().unwrap().clone();
            z.alert(&v, &[m]).await.unwrap(); // a failed item only warns, as upstream
            assert_eq!(got.await.unwrap(), json!({"request": "sender data", "data": [{"host": "web-1", "key": "elastalert.hit", "value": "1", "clock": 1_700_000_000}]}), "{ok}");
        }
    }

    #[tokio::test]
    async fn connection_error_is_an_alert_error() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let r = rule("zabbix", &format!("zbx_host: h\nzbx_key: k\nzbx_sender_host: 127.0.0.1\nzbx_sender_port: {port}\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let m = json!({"@timestamp": 1}).as_object().unwrap().clone();
        let err = Zabbix::new(&r).unwrap().alert(&v, &[m]).await.unwrap_err();
        assert!(err.to_string().starts_with("Error sending alert to Zabbix:"), "{err}");
    }
}
