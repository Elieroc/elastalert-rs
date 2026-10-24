//! `tencent_sms` alerter: `SendSms` on the Tencent Cloud API 3.0, signed with TC3-HMAC-SHA256.

use super::crypto::{hex, hmac_sha256, sha256_hex};
use super::http::Http;
use super::{Doc, View, opt, required, s_or};
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::{Result, anyhow, bail};
use reqwest::Method;
use serde_json::{Value, json};

const HOST: &str = "sms.tencentcloudapi.com";

pub struct TencentSms {
    secret_id: String,
    secret_key: String,
    region: String,
    sdk_appid: Value,
    to_numbers: Value,
    sign_name: Option<Value>,
    template_id: Value,
    template_params: Vec<String>,
    to_info: Value,
    url: String,
    http: Http,
}

/// `Authorization` value for a POST of `body` to `host`, as the Tencent Cloud SDK computes it (signed headers: content-type and host).
fn authorization(secret_id: &str, secret_key: &str, service: &str, host: &str, timestamp: i64, body: &str) -> String {
    let date = chrono::DateTime::from_timestamp(timestamp, 0).unwrap_or_default().format("%Y-%m-%d").to_string();
    let canonical = format!("POST\n/\n\ncontent-type:application/json\nhost:{host}\n\ncontent-type;host\n{}", sha256_hex(body.as_bytes()));
    let scope = format!("{date}/{service}/tc3_request");
    let to_sign = format!("TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let mut key = hmac_sha256(format!("TC3{secret_key}").as_bytes(), date.as_bytes());
    for part in [service, "tc3_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    format!("TC3-HMAC-SHA256 Credential={secret_id}/{scope}, SignedHeaders=content-type;host, Signature={signature}")
}

/// RFC 6901 JSON Pointer, like `jsonpointer.resolve_pointer`.
fn resolve_pointer<'a>(doc: &'a Value, pointer: &str) -> Result<&'a Value> {
    if pointer.is_empty() {
        return Ok(doc);
    }
    let Some(path) = pointer.strip_prefix('/') else { bail!("Location must start with /") };
    let mut cur = doc;
    for raw in path.split('/') {
        let part = raw.replace("~1", "/").replace("~0", "~");
        cur = match cur {
            Value::Object(o) => o.get(&part),
            Value::Array(a) => part.parse::<usize>().ok().and_then(|i| a.get(i)),
            _ => None,
        }
        .ok_or_else(|| anyhow!("member '{part}' not found in {cur}"))?;
    }
    Ok(cur)
}

impl TencentSms {
    pub(super) fn new(rule: &Rule) -> Result<TencentSms> {
        for k in ["tencent_sms_secret_id", "tencent_sms_secret_key", "tencent_sms_sdk_appid", "tencent_sms_to_number", "tencent_sms_template_id"] {
            required(rule, "tencent_sms", k)?;
        }
        Ok(TencentSms {
            secret_id: py_str(&rule.raw["tencent_sms_secret_id"]),
            secret_key: py_str(&rule.raw["tencent_sms_secret_key"]),
            region: s_or(rule, "tencent_sms_region", "ap-guangzhou"),
            sdk_appid: rule.raw["tencent_sms_sdk_appid"].clone(),
            to_numbers: rule.raw["tencent_sms_to_number"].clone(),
            // required for Mainland China SMS
            sign_name: rule.raw.get("tencent_sms_sign_name").filter(|v| !v.is_null()).cloned(),
            template_id: rule.raw["tencent_sms_template_id"].clone(),
            template_params: rule.raw.get("tencent_sms_template_parm").and_then(Value::as_array).into_iter().flatten().map(py_str).collect(),
            to_info: opt(rule, "tencent_sms_to_number", json!([])),
            url: format!("https://{HOST}/"),
            http: Http::raw(None, None, false, 30)?,
        })
    }

    fn request_body(&self, first: &Doc) -> Result<String> {
        let doc = Value::Object(first.clone());
        let params = self.template_params.iter().map(|p| resolve_pointer(&doc, p).cloned()).collect::<Result<Vec<_>>>()?;
        let mut body = json!({"SmsSdkAppId": self.sdk_appid, "ExtendCode": "", "PhoneNumberSet": self.to_numbers, "TemplateId": self.template_id, "TemplateParamSet": params});
        if let Some(name) = &self.sign_name {
            body["SignName"] = name.clone();
        }
        Ok(body.to_string())
    }

    pub(super) async fn alert(&self, _v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let body = self.request_body(&matches[0])?;
        let timestamp = chrono::Utc::now().timestamp();
        let headers = [
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Host".into(), HOST.into()),
            ("X-TC-Action".into(), "SendSms".into()),
            ("X-TC-Timestamp".into(), timestamp.to_string()),
            ("X-TC-Version".into(), "2021-01-11".into()),
            ("X-TC-Region".into(), self.region.clone()),
            ("X-TC-Language".into(), "en-US".into()),
            ("Authorization".into(), authorization(&self.secret_id, &self.secret_key, "sms", HOST, timestamp, &body)),
        ];
        let fail = |code: &str, message: &str, request_id: &str| anyhow!("Error posting to TencentSMS: [TencentCloudSDKException] code:{code} message:{message} requestId:{request_id}");
        let resp = self.http.request_text(Method::POST, "posting to TencentSMS", &self.url, &headers, body).await.map_err(|e| anyhow!("{e:#}"))?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let parsed: Value = serde_json::from_str(&text).map_err(|_| fail("ServerNetworkError", &format!("HTTP {status}: {}", text.chars().take(200).collect::<String>()), ""))?;
        let r = &parsed["Response"];
        let request_id = r["RequestId"].as_str().unwrap_or_default();
        if let Some(e) = r.get("Error") {
            return Err(fail(e["Code"].as_str().unwrap_or_default(), e["Message"].as_str().unwrap_or_default(), request_id));
        }
        for item in r["SendStatusSet"].as_array().into_iter().flatten() {
            if item["Code"].as_str() != Some("Ok") {
                return Err(fail(item["Code"].as_str().unwrap_or_default(), item["Message"].as_str().unwrap_or_default(), request_id));
            }
        }
        log::info!("Alert sent to TencentSMS");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "tencent sms", "to_number": self.to_info})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture_with, rule};
    use crate::types::RuleType;

    // Reference: tencentcloud-sdk-python 3.1.193 `_build_req_with_tc3_signature` with time.time() = 1700000000.
    #[test]
    fn signature_matches_the_sdk() {
        let body = r#"{"SmsSdkAppId": "1400006666", "PhoneNumberSet": ["+8613711112222"], "TemplateId": "123", "TemplateParamSet": ["a", "@U00e9"], "ExtendCode": ""}"#.replace("@U", "\\u");
        assert_eq!(
            authorization("AKIDexample", "secretKEYexample", "sms", HOST, 1_700_000_000, &body),
            "TC3-HMAC-SHA256 Credential=AKIDexample/2023-11-14/sms/tc3_request, SignedHeaders=content-type;host, Signature=0cd49a88c11722bd735bc7a57a4fc4f64efd46abc9f9a415aa2b0f8e5f2379a0"
        );
    }

    // Reference: jsonpointer 3.4.
    #[test]
    fn json_pointers() {
        let d = json!({"a": {"b/c": [1, {"x~y": "z"}]}, "n": 5});
        assert_eq!(resolve_pointer(&d, "/a/b~1c/1/x~0y").unwrap(), &json!("z"));
        assert_eq!(resolve_pointer(&d, "/n").unwrap(), &json!(5));
        assert_eq!(resolve_pointer(&d, "").unwrap(), &d);
        assert_eq!(resolve_pointer(&d, "/nope").unwrap_err().to_string(), format!("member 'nope' not found in {d}"));
        assert_eq!(resolve_pointer(&d, "a/b").unwrap_err().to_string(), "Location must start with /");
    }

    const CFG: &str = "tencent_sms_secret_id: id\ntencent_sms_secret_key: key\ntencent_sms_sdk_appid: '1400006666'\ntencent_sms_to_number: ['+8613711112222']\ntencent_sms_template_id: '123'\ntencent_sms_template_parm: [/user/name, /n]\n";

    #[tokio::test]
    async fn sends_a_signed_request() {
        let (url, got) = capture_with(1, 200, r#"{"Response": {"SendStatusSet": [{"Code": "Ok"}], "RequestId": "r1"}}"#).await;
        let r = rule("tencent_sms", &format!("{CFG}tencent_sms_sign_name: MySign\ntencent_sms_region: ap-singapore\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let mut t = TencentSms::new(&r).unwrap();
        t.url = url;
        t.alert(&v, &[json!({"user": {"name": "bob"}, "n": 3}).as_object().unwrap().clone()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(
            got[0].json(),
            json!({"SmsSdkAppId": "1400006666", "ExtendCode": "", "PhoneNumberSet": ["+8613711112222"], "TemplateId": "123", "TemplateParamSet": ["bob", 3], "SignName": "MySign"})
        );
        assert_eq!(got[0].header("x-tc-action"), Some("SendSms"));
        assert_eq!(got[0].header("x-tc-version"), Some("2021-01-11"));
        assert_eq!(got[0].header("x-tc-region"), Some("ap-singapore"));
        assert_eq!(got[0].header("content-type"), Some("application/json"));
        let auth = got[0].header("authorization").unwrap();
        let ts: i64 = got[0].header("x-tc-timestamp").unwrap().parse().unwrap();
        assert_eq!(auth, authorization("id", "key", "sms", HOST, ts, &got[0].body));
    }

    #[tokio::test]
    async fn api_and_item_errors() {
        for (body, expected) in [
            (r#"{"Response": {"Error": {"Code": "AuthFailure.SignatureFailure", "Message": "bad signature"}, "RequestId": "r2"}}"#, "Error posting to TencentSMS: [TencentCloudSDKException] code:AuthFailure.SignatureFailure message:bad signature requestId:r2"),
            (r#"{"Response": {"SendStatusSet": [{"Code": "Ok"}, {"Code": "FailedOperation.TemplateIncorrectOrUnapproved", "Message": "no template"}], "RequestId": "r3"}}"#, "Error posting to TencentSMS: [TencentCloudSDKException] code:FailedOperation.TemplateIncorrectOrUnapproved message:no template requestId:r3"),
        ] {
            let (url, _) = capture_with(1, 200, body).await;
            let r = rule("tencent_sms", CFG).unwrap();
            let rt = RuleType::new(&r).unwrap();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
            let mut t = TencentSms::new(&r).unwrap();
            t.url = url;
            let err = t.alert(&v, &[json!({"user": {"name": "bob"}, "n": 3}).as_object().unwrap().clone()]).await.unwrap_err();
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn missing_pointer_target_fails_before_sending() {
        let r = rule("tencent_sms", CFG).unwrap();
        let t = TencentSms::new(&r).unwrap();
        assert!(t.request_body(&json!({"n": 1}).as_object().unwrap().clone()).unwrap_err().to_string().contains("member 'user' not found"));
    }
}
