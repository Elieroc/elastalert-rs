//! `post` (http_post) alerter.

use super::http::Http;
use super::{Doc, list, required};
use crate::field::{lookup, py_str};
use crate::rule::Rule;
use anyhow::Result;
use serde_json::Value;

pub struct Post {
    pub(super) urls: Vec<String>,
    payload: Doc,
    static_payload: Doc,
    all_values: bool,
    headers: Vec<(String, String)>,
    http: Http,
}

impl Post {
    pub(super) fn new(rule: &Rule) -> Result<Post> {
        required(rule, "post", "http_post_url")?;
        let obj = |k: &str| rule.raw.get(k).and_then(Value::as_object).cloned().unwrap_or_default();
        let payload = obj("http_post_payload");
        Ok(Post {
            urls: list(rule, "http_post_url"),
            all_values: rule.raw.get("http_post_all_values").and_then(Value::as_bool).unwrap_or(payload.is_empty()),
            static_payload: obj("http_post_static_payload"),
            headers: obj("http_post_headers").iter().map(|(k, v)| (k.clone(), py_str(v))).collect(),
            http: Http::new(rule, "http_post", 10)?,
            payload,
        })
    }

    pub(super) async fn alert(&self, matches: &[Doc]) -> Result<()> {
        for m in matches {
            let mut body = if self.all_values { m.clone() } else { Doc::new() };
            body.extend(self.static_payload.clone());
            for (post_key, es_key) in &self.payload {
                body.insert(post_key.clone(), es_key.as_str().and_then(|k| lookup(m, k)).cloned().unwrap_or(Value::Null));
            }
            for url in &self.urls {
                let mut headers = vec![("Accept".to_string(), "application/json;charset=utf-8".to_string())];
                headers.extend(self.headers.iter().cloned());
                self.http.post_json("HTTP Post alert", url, &headers, &Value::Object(body.clone())).await?;
            }
            log::info!("HTTP Post alert sent.");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use serde_json::json;

    #[tokio::test]
    async fn payload_map_static_payload_and_headers() {
        let (url, got) = capture(1, 200).await;
        let r = rule(
            "post",
            &format!(
                "http_post_url: {url}/h\nhttp_post_payload: {{who: user.name}}\nhttp_post_static_payload: {{env: prod}}\nhttp_post_headers: {{X-Key: k}}\n"
            ),
        )
        .unwrap();
        let m = json!({"user": {"name": "bob"}, "other": 1}).as_object().unwrap().clone();
        Post::new(&r).unwrap().alert(&[m]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].path, "/h");
        assert_eq!(got[0].header("x-key"), Some("k"));
        assert_eq!(got[0].header("accept"), Some("application/json;charset=utf-8"));
        assert_eq!(got[0].json(), json!({"who": "bob", "env": "prod"}));
    }
}
