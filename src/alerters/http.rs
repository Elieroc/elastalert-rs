//! Webhook client shared by the HTTP alerters: `<prefix>_proxy`, `_ca_certs`, `_ignore_ssl_errors` and `_timeout`.

use super::{b, s};
use crate::rule::Rule;
use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::time::Duration;

enum Body<'a> {
    Json(&'a Value),
    Form(String),
}

pub struct Http {
    client: reqwest::Client,
}

impl Http {
    /// `prefix` is the option prefix upstream uses for this alerter, e.g. `slack` or `http_post`.
    /// A proxy login comes from `<prefix>_proxy_login` and `<prefix>_proxy_password`.
    pub fn new(rule: &Rule, prefix: &str, default_timeout: u64) -> Result<Http> {
        Http::with_proxy_password_key(rule, prefix, default_timeout, "proxy_password")
    }

    /// Like `new`, for alerters whose proxy password option has another suffix (telegram: `proxy_pass`).
    pub fn with_proxy_password_key(rule: &Rule, prefix: &str, default_timeout: u64, password_suffix: &str) -> Result<Http> {
        let key = |suffix: &str| format!("{prefix}_{suffix}");
        let timeout = rule.raw.get(&key("timeout")).and_then(Value::as_u64).unwrap_or(default_timeout);
        let mut c = reqwest::Client::builder().timeout(Duration::from_secs(timeout.max(1)));
        if let Some(p) = s(rule, &key("proxy")) {
            let mut proxy = reqwest::Proxy::https(p)?;
            if let Some(login) = s(rule, &key("proxy_login")) {
                proxy = proxy.basic_auth(&login, &s(rule, &key(password_suffix)).unwrap_or_default());
            }
            c = c.proxy(proxy);
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
    /// `headers` replace the defaults of the same name (like merging dicts upstream).
    pub async fn post_json(&self, what: &str, url: &str, headers: &[(String, String)], body: &Value) -> Result<reqwest::Response> {
        self.send(what, url, headers, Body::Json(body), false).await
    }

    /// POSTs `fields` as `application/x-www-form-urlencoded` with the error details of `post_json_details`.
    pub async fn post_form_details(&self, what: &str, url: &str, headers: &[(String, String)], fields: &[(&str, String)]) -> Result<reqwest::Response> {
        let encoded = {
            let mut enc = url::form_urlencoded::Serializer::new(String::new());
            for (k, v) in fields {
                enc.append_pair(k, v);
            }
            enc.finish()
        };
        self.send(what, url, headers, Body::Form(encoded), true).await
    }

    /// Like `post_json`, and the error carries the response text ("... Details: ..."), as upstream's Discord and Telegram do.
    pub async fn post_json_details(&self, what: &str, url: &str, headers: &[(String, String)], body: &Value) -> Result<reqwest::Response> {
        self.send(what, url, headers, Body::Json(body), true).await
    }

    async fn send(&self, what: &str, url: &str, headers: &[(String, String)], body: Body<'_>, details: bool) -> Result<reqwest::Response> {
        let mut map = HeaderMap::new();
        for (k, v) in headers {
            map.insert(
                HeaderName::from_bytes(k.as_bytes()).with_context(|| format!("invalid header name {k:?}"))?,
                HeaderValue::from_str(v).with_context(|| format!("invalid value for header {k}"))?,
            );
        }
        let fail = |e: reqwest::Error, text: &str| {
            if details { anyhow::anyhow!("Error posting {what}: {e}. Details: {text}") } else { anyhow::anyhow!("Error posting {what}: {e}") }
        };
        let req = match body {
            Body::Json(v) => self.client.post(url).json(v),
            Body::Form(s) => self.client.post(url).header("Content-Type", "application/x-www-form-urlencoded").body(s),
        };
        let resp = req.headers(map).send().await.map_err(|e| fail(e, ""))?;
        if let Err(e) = resp.error_for_status_ref() {
            let text = if details { resp.text().await.unwrap_or_default() } else { String::new() };
            bail!(fail(e, &text));
        }
        Ok(resp)
    }
}
