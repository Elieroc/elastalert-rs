//! `post2` (http_post2) alerter: like `post`, with Jinja templates for payload and headers.

use super::http::Http;
use super::{Doc, list, opt, required, s};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};

pub struct Post2 {
    urls: Vec<String>,
    payload: Value,
    raw_fields: Map<String, Value>,
    all_values: bool,
    headers: Value,
    root_name: Option<String>,
    http: Http,
}

/// Escapes a string for the inside of a JSON string literal (`json.encoder.encode_basestring(s)[1:-1]`).
fn json_escape(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_default();
    quoted[1..quoted.len() - 1].to_string()
}

fn escape_all_values(v: &Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), escape_all_values(x))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(escape_all_values).collect()),
        Value::String(s) => Value::String(json_escape(s)),
        other => other.clone(),
    }
}

/// Renders `template` (a string, or any JSON value dumped to text) with the match fields as variables and parses the result as a JSON object.
fn render_json_template(template: &Value, args: &Value, field: &str) -> Result<Map<String, Value>> {
    let source = match template {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other)?,
    };
    let check = "Please check your template syntax";
    let rendered = minijinja::Environment::new().render_str(&source, minijinja::value::Serde(args.clone())).map_err(|e| {
        if e.kind() == minijinja::ErrorKind::SyntaxError {
            anyhow::anyhow!("HTTP Post 2: The value of 'http_post2_{field}' has an invalid Jinja2 syntax. {check}: {e}")
        } else {
            anyhow::anyhow!("HTTP Post 2: An unexpected error occurred with the 'http_post2_{field}' value. {check}: {e}")
        }
    })?;
    match serde_json::from_str::<Value>(&rendered) {
        Ok(Value::Object(o)) => Ok(o),
        Ok(_) => bail!("HTTP Post 2: An unexpected error occurred with the 'http_post2_{field}' value. {check}: the rendered JSON is not an object"),
        Err(e) => bail!("HTTP Post 2: The rendered value for 'http_post2_{field}' contains invalid JSON. {check}: {e}"),
    }
}

impl Post2 {
    pub(super) fn new(rule: &Rule) -> Result<Post2> {
        required(rule, "post2", "http_post2_url")?;
        let payload = opt(rule, "http_post2_payload", json!({}));
        Ok(Post2 {
            urls: list(rule, "http_post2_url"),
            all_values: rule.raw.get("http_post2_all_values").map(|v| truthy(Some(v))).unwrap_or(!truthy(Some(&payload))),
            raw_fields: rule.raw.get("http_post2_raw_fields").and_then(Value::as_object).cloned().unwrap_or_default(),
            headers: opt(rule, "http_post2_headers", json!({})),
            root_name: s(rule, "jinja_root_name"),
            payload,
            http: Http::new(rule, "http_post2", 10)?,
        })
    }

    /// The JSON body and headers for one match.
    fn request(&self, m: &Doc) -> Result<(Value, Vec<(String, String)>)> {
        let escaped = escape_all_values(&Value::Object(m.clone()));
        let mut args = escaped.as_object().cloned().unwrap_or_default();
        if let Some(root) = &self.root_name {
            args.insert(root.clone(), escaped.clone());
        }
        let args = Value::Object(args);
        let mut payload = if self.all_values { m.clone() } else { Map::new() };
        payload.extend(render_json_template(&self.payload, &args, "payload")?);
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string()), ("Accept".into(), "application/json;charset=utf-8".into())];
        for (k, v) in render_json_template(&self.headers, &args, "headers")? {
            if matches!(v, Value::Null | Value::Array(_) | Value::Object(_)) {
                bail!("HTTP Post 2: Can't send a header value which is not a string! Forbidden header {k}: {}", py_str(&v));
            }
            headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&k));
            headers.push((k, py_str(&v)));
        }
        for (post_key, es_key) in &self.raw_fields {
            payload.insert(post_key.clone(), es_key.as_str().and_then(|k| lookup(m, k)).cloned().unwrap_or(Value::Null));
        }
        Ok((Value::Object(payload), headers))
    }

    pub(super) async fn alert(&self, matches: &[Doc]) -> Result<()> {
        for m in matches {
            let (payload, headers) = self.request(m)?;
            for url in &self.urls {
                self.http.post_json("HTTP Post 2 alert", url, &headers, &payload).await?;
            }
            log::info!("HTTP Post 2 alert sent.");
        }
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "http_post2", "http_post2_webhook_url": self.urls})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};

    fn m() -> Doc {
        json!({"user": {"name": "a\"b"}, "n": 3, "other": 1}).as_object().unwrap().clone()
    }

    #[test]
    fn templates_are_escaped_and_merged() {
        let r = rule(
            "post2",
            "http_post2_url: http://x\nhttp_post2_payload:\n  who: '{{ user.name }}'\n  n: '{{ n }}'\n  root: '{{ r.other }}'\nhttp_post2_headers: {X-Who: '{{ user.name }}'}\nhttp_post2_raw_fields: {raw_n: n}\njinja_root_name: r\n",
        )
        .unwrap();
        let (payload, headers) = Post2::new(&r).unwrap().request(&m()).unwrap();
        assert_eq!(payload, json!({"who": "a\"b", "n": "3", "root": "1", "raw_n": 3}));
        assert!(headers.contains(&("X-Who".to_string(), "a\"b".to_string())));
        assert!(headers.contains(&("Content-Type".to_string(), "application/json".to_string())));
    }

    #[test]
    fn all_values_default_and_errors() {
        let all = Post2::new(&rule("post2", "http_post2_url: http://x\n").unwrap()).unwrap();
        assert_eq!(all.request(&m()).unwrap().0, Value::Object(m()));
        let bad_syntax = Post2::new(&rule("post2", "http_post2_url: http://x\nhttp_post2_payload: '{{ oops'\n").unwrap()).unwrap();
        assert!(bad_syntax.request(&m()).unwrap_err().to_string().contains("invalid Jinja2 syntax"));
        let bad_json = Post2::new(&rule("post2", "http_post2_url: http://x\nhttp_post2_payload: 'not json'\n").unwrap()).unwrap();
        assert!(bad_json.request(&m()).unwrap_err().to_string().contains("contains invalid JSON"));
        let bad_header = Post2::new(&rule("post2", "http_post2_url: http://x\nhttp_post2_headers: {A: [1]}\n").unwrap()).unwrap();
        assert!(bad_header.request(&m()).unwrap_err().to_string().contains("Forbidden header A"));
    }

    #[tokio::test]
    async fn posts_per_match() {
        let (url, got) = capture(2, 200).await;
        let r = rule("post2", &format!("http_post2_url: {url}\nhttp_post2_payload: {{n: '{{{{ n }}}}'}}\n")).unwrap();
        Post2::new(&r).unwrap().alert(&[m(), m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].json(), json!({"n": "3"}));
    }
}
