//! Webhook client shared by the HTTP alerters: `<prefix>_proxy`, `_ca_certs`, `_ignore_ssl_errors` and `_timeout`.

use super::{b, s};
use crate::rule::Rule;
use anyhow::{Context, Result};
use serde_json::Value;
use std::time::Duration;

pub struct Http {
    client: reqwest::Client,
}

impl Http {
    /// `prefix` is the option prefix upstream uses for this alerter, e.g. `slack` or `http_post`.
    pub fn new(rule: &Rule, prefix: &str, default_timeout: u64) -> Result<Http> {
        let key = |suffix: &str| format!("{prefix}_{suffix}");
        let timeout = rule.raw.get(&key("timeout")).and_then(Value::as_u64).unwrap_or(default_timeout);
        let mut c = reqwest::Client::builder().timeout(Duration::from_secs(timeout.max(1)));
        if let Some(p) = s(rule, &key("proxy")) {
            c = c.proxy(reqwest::Proxy::https(p)?);
        }
        if let Some(ca) = s(rule, &key("ca_certs")) {
            let pem = std::fs::read(&ca).with_context(|| format!("reading CA file {ca}"))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)? {
                c = c.add_root_certificate(cert);
            }
        }
        if b(rule, &key("ignore_ssl_errors")) {
            c = c.danger_accept_invalid_certs(true);
        }
        Ok(Http { client: c.build()? })
    }

    /// POSTs `body` as JSON; any HTTP error status is an error. `what` completes "Error posting ...".
    pub async fn post_json(&self, what: &str, url: &str, headers: &[(String, String)], body: &Value) -> Result<reqwest::Response> {
        let mut req = self.client.post(url).json(body);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req.send().await.map_err(|e| anyhow::anyhow!("Error posting {what}: {e}"))?;
        resp.error_for_status().map_err(|e| anyhow::anyhow!("Error posting {what}: {e}"))
    }
}
