//! Minimal Elasticsearch / OpenSearch REST client: only the endpoints the daemon uses.

use anyhow::{Context, Result, bail};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde_json::{Map, Value, json};
use std::time::Duration;

#[derive(Clone)]
pub struct Es {
    http: reqwest::Client,
    base: String,
}

fn conf_str<'a>(c: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    c.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn conf_bool(c: &Map<String, Value>, k: &str) -> Option<bool> {
    match c.get(k)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => Some(matches!(s.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")),
        _ => None,
    }
}

/// Truncate gigantic ES error bodies the way upstream does (1024 chars).
fn clip(s: &str) -> String {
    match s.char_indices().nth(1024) {
        Some((i, _)) => format!("{}... ({} characters removed)", &s[..i], s.len() - i),
        None => s.to_string(),
    }
}

impl Es {
    /// Builds a client from config.yaml / rule keys (`es_host`, `es_port`, `use_ssl`, auth, TLS files).
    pub fn from_conf(c: &Map<String, Value>) -> Result<Es> {
        let host = conf_str(c, "es_host").context("es_host missing")?;
        let port = match c.get("es_port") {
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::String(s)) => s.clone(),
            _ => "9200".into(),
        };
        let scheme = if conf_bool(c, "use_ssl").unwrap_or(false) { "https" } else { "http" };
        let prefix = conf_str(c, "es_url_prefix").map(|p| format!("/{}", p.trim_matches('/'))).unwrap_or_default();
        let base = format!("{scheme}://{host}:{port}{prefix}");

        let mut headers = HeaderMap::new();
        let auth = if let Some(k) = conf_str(c, "es_api_key") {
            Some(format!("ApiKey {k}"))
        } else if let Some(t) = conf_str(c, "es_bearer") {
            Some(format!("Bearer {t}"))
        } else {
            conf_str(c, "es_username").map(|u| {
                let p = conf_str(c, "es_password").unwrap_or("");
                format!("Basic {}", base64(format!("{u}:{p}").as_bytes()))
            })
        };
        if let Some(a) = auth {
            let mut v = HeaderValue::from_str(&a).context("invalid auth header")?;
            v.set_sensitive(true);
            headers.insert(AUTHORIZATION, v);
        }

        let timeout = c.get("es_conn_timeout").and_then(Value::as_u64).unwrap_or(20);
        let mut b = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(timeout.max(1) * 3))
            .connect_timeout(Duration::from_secs(timeout.max(1)))
            .pool_max_idle_per_host(32);
        if conf_bool(c, "verify_certs") == Some(false) {
            b = b.danger_accept_invalid_certs(true);
        }
        if let Some(ca) = conf_str(c, "ca_certs") {
            let pem = std::fs::read(ca).with_context(|| format!("reading ca_certs {ca}"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
                b = b.add_root_certificate(cert);
            }
        }
        if let Some(cert) = conf_str(c, "client_cert") {
            let mut pem = std::fs::read(cert).with_context(|| format!("reading client_cert {cert}"))?;
            if let Some(key) = conf_str(c, "client_key") {
                pem.extend(std::fs::read(key).with_context(|| format!("reading client_key {key}"))?);
            }
            b = b.identity(reqwest::Identity::from_pem(&pem)?);
        }
        Ok(Es { http: b.build()?, base })
    }

    async fn send(&self, req: reqwest::RequestBuilder) -> Result<Value> {
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.text().await?;
        if !status.is_success() {
            bail!("HTTP {status}: {}", clip(&body));
        }
        Ok(serde_json::from_str(&body).unwrap_or(Value::Null))
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base, path.trim_start_matches('/'))
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.send(self.http.post(self.url(path)).json(body)).await
    }

    pub async fn exists(&self, index: &str) -> Result<bool> {
        let resp = self.http.head(self.url(index)).send().await?;
        Ok(resp.status().is_success())
    }

    /// First page of a search, opening a scroll context.
    pub async fn search_scroll(&self, index: &str, body: &Value, size: u64, keepalive: &str) -> Result<Value> {
        let path = format!("{index}/_search?scroll={keepalive}&size={size}&ignore_unavailable=true");
        self.post(&path, body).await
    }

    pub async fn scroll(&self, id: &str, keepalive: &str) -> Result<Value> {
        self.post("_search/scroll", &json!({"scroll": keepalive, "scroll_id": id})).await
    }

    pub async fn clear_scroll(&self, id: &str) {
        let _ = self.send(self.http.delete(self.url("_search/scroll")).json(&json!({"scroll_id": id}))).await;
    }

    pub async fn search(&self, index: &str, body: &Value) -> Result<Value> {
        self.post(&format!("{index}/_search?ignore_unavailable=true"), body).await
    }

    /// `_bulk` with an NDJSON body. Returns the parsed response.
    pub async fn bulk(&self, ndjson: String) -> Result<Value> {
        let req = self.http.post(self.url("_bulk")).header(CONTENT_TYPE, "application/x-ndjson").body(ndjson);
        self.send(req).await
    }
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_basic_auth() {
        assert_eq!(super::base64(b"elastic:changeme"), "ZWxhc3RpYzpjaGFuZ2VtZQ==");
        assert_eq!(super::base64(b"a"), "YQ==");
        assert_eq!(super::base64(b"ab"), "YWI=");
    }
}
