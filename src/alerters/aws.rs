//! What the AWS alerters (SNS, SQS, SES) share: credentials the way boto3 finds them, SigV4 signing, and Query-protocol calls.
//!
//! Credentials, in boto3's order: the rule's key pair, or its profile; else the environment, a web identity token
//! (`AWS_WEB_IDENTITY_TOKEN_FILE`, EKS), the shared credentials file, the ECS task role, the EC2 instance role.
//! Not supported: profiles that assume a role, use SSO or run `credential_process`.

use super::crypto::{hex, hmac_sha256, sha256_hex};
use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone, Debug, PartialEq)]
pub struct Creds {
    pub access_key: String,
    pub secret: String,
    pub token: Option<String>,
}

/// Where the rule says to take credentials from.
#[derive(Clone, Default)]
pub struct CredOptions {
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub profile: Option<String>,
}

pub type EnvFn = Box<dyn Fn(&str) -> Option<String> + Send + Sync>;

pub fn process_env() -> EnvFn {
    Box::new(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

// ---- ini files ----

type Ini = HashMap<String, HashMap<String, String>>;

fn parse_ini(text: &str) -> Ini {
    let mut out: Ini = HashMap::new();
    let mut section = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.trim().to_string();
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.entry(section.clone()).or_default().insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

fn read_ini(env: &EnvFn, var: &str, default_name: &str) -> Ini {
    let path = env(var).or_else(|| env("HOME").map(|h| format!("{h}/.aws/{default_name}")));
    path.and_then(|p| std::fs::read_to_string(p).ok()).map(|t| parse_ini(&t)).unwrap_or_default()
}

fn section_creds(section: &HashMap<String, String>, what: &str) -> Result<Option<Creds>> {
    for unsupported in ["role_arn", "sso_start_url", "sso_session", "credential_process"] {
        if section.contains_key(unsupported) {
            bail!("{what} uses {unsupported}, which is not supported; give the rule an access key pair or run with the role's credentials in the environment");
        }
    }
    Ok(match (section.get("aws_access_key_id"), section.get("aws_secret_access_key")) {
        (Some(k), Some(s)) => Some(Creds { access_key: k.clone(), secret: s.clone(), token: section.get("aws_session_token").cloned() }),
        _ => None,
    })
}

/// The `region` of a profile in `~/.aws/config`.
pub fn profile_region(profile: &str, env: &EnvFn) -> Option<String> {
    let config = read_ini(env, "AWS_CONFIG_FILE", "config");
    let section = if profile == "default" { "default".to_string() } else { format!("profile {profile}") };
    config.get(&section).and_then(|s| s.get("region")).cloned()
}

/// Region for a call: the rule's option, else the profile's, else the environment, else `default`.
pub fn region(explicit: Option<&str>, profile: Option<&str>, default: Option<&str>, env: &EnvFn) -> Result<String> {
    explicit
        .map(String::from)
        .or_else(|| profile.and_then(|p| profile_region(p, env)))
        .or_else(|| env("AWS_REGION").or_else(|| env("AWS_DEFAULT_REGION")))
        .or_else(|| default.map(String::from))
        .context("You must specify a region")
}

// ---- credential sources ----

fn short_client(secs: u64) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(Duration::from_secs(secs)).no_proxy().build()?)
}

fn expiry(v: &Value) -> Option<DateTime<Utc>> {
    v["Expiration"].as_str().and_then(|e| DateTime::parse_from_rfc3339(e).ok()).map(|d| d.with_timezone(&Utc))
}

fn json_creds(v: &Value) -> Result<(Creds, Option<DateTime<Utc>>)> {
    let (Some(k), Some(s)) = (v["AccessKeyId"].as_str(), v["SecretAccessKey"].as_str()) else { bail!("the credentials answer has no AccessKeyId / SecretAccessKey") };
    Ok((Creds { access_key: k.into(), secret: s.into(), token: v["Token"].as_str().map(String::from) }, expiry(v)))
}

/// The text of the first `<name>` element.
pub fn xml_tag(xml: &str, name: &str) -> Option<String> {
    let start = xml.find(&format!("<{name}>"))? + name.len() + 2;
    let end = xml[start..].find(&format!("</{name}>"))? + start;
    Some(xml[start..end].replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&"))
}

async fn web_identity(env: &EnvFn, region: &str) -> Result<Option<(Creds, Option<DateTime<Utc>>)>> {
    let (Some(file), Some(role)) = (env("AWS_WEB_IDENTITY_TOKEN_FILE"), env("AWS_ROLE_ARN")) else { return Ok(None) };
    let token = std::fs::read_to_string(&file).with_context(|| format!("reading AWS_WEB_IDENTITY_TOKEN_FILE {file}"))?;
    let endpoint = env("AWS_ENDPOINT_URL_STS").unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com/"));
    let session = env("AWS_ROLE_SESSION_NAME").unwrap_or_else(|| "elastalert".into());
    let form = super::http::form_body(&[
        ("Action", "AssumeRoleWithWebIdentity".into()),
        ("Version", "2011-06-15".into()),
        ("RoleArn", role),
        ("RoleSessionName", session),
        ("WebIdentityToken", token.trim().into()),
    ]);
    let resp = short_client(30)?.post(endpoint).header("Content-Type", "application/x-www-form-urlencoded").body(form).send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        bail!("AssumeRoleWithWebIdentity failed ({status}): {}", xml_tag(&text, "Message").unwrap_or(text));
    }
    let field = |n: &str| xml_tag(&text, n).with_context(|| format!("AssumeRoleWithWebIdentity answer has no {n}"));
    let exp = xml_tag(&text, "Expiration").and_then(|e| DateTime::parse_from_rfc3339(&e).ok()).map(|d| d.with_timezone(&Utc));
    Ok(Some((Creds { access_key: field("AccessKeyId")?, secret: field("SecretAccessKey")?, token: Some(field("SessionToken")?) }, exp)))
}

async fn container(env: &EnvFn) -> Result<Option<(Creds, Option<DateTime<Utc>>)>> {
    let url = match (env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"), env("AWS_CONTAINER_CREDENTIALS_FULL_URI")) {
        (Some(rel), _) => format!("{}{rel}", env("AWS_CONTAINER_CREDENTIALS_HOST").unwrap_or_else(|| "http://169.254.170.2".into())),
        (None, Some(full)) => full,
        _ => return Ok(None),
    };
    let mut req = short_client(5)?.get(url);
    let auth = env("AWS_CONTAINER_AUTHORIZATION_TOKEN").or_else(|| env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE").and_then(|f| std::fs::read_to_string(f).ok()).map(|t| t.trim().to_string()));
    if let Some(a) = auth {
        req = req.header("Authorization", a);
    }
    let v: Value = req.send().await?.error_for_status()?.json().await?;
    json_creds(&v).map(Some)
}

async fn instance_role(env: &EnvFn) -> Result<Option<(Creds, Option<DateTime<Utc>>)>> {
    if env("AWS_EC2_METADATA_DISABLED").is_some_and(|v| v.eq_ignore_ascii_case("true")) {
        return Ok(None);
    }
    let base = env("AWS_EC2_METADATA_SERVICE_ENDPOINT").unwrap_or_else(|| "http://169.254.169.254".into());
    let client = short_client(2)?;
    let Ok(token) = client.put(format!("{base}/latest/api/token")).header("X-aws-ec2-metadata-token-ttl-seconds", "21600").send().await else { return Ok(None) };
    let token = token.error_for_status()?.text().await?;
    let get = |path: String| client.get(format!("{base}/latest/meta-data/{path}")).header("X-aws-ec2-metadata-token", token.clone()).send();
    let roles = get("iam/security-credentials/".into()).await?.error_for_status()?.text().await?;
    let Some(role) = roles.lines().next().filter(|r| !r.trim().is_empty()) else { return Ok(None) };
    let v: Value = get(format!("iam/security-credentials/{}", role.trim())).await?.error_for_status()?.json().await?;
    json_creds(&v).map(Some)
}

/// Resolves credentials once; `expires` says when to ask again (`None` = never).
async fn resolve(opts: &CredOptions, env: &EnvFn, region: &str) -> Result<(Creds, Option<DateTime<Utc>>)> {
    if let (Some(k), Some(s)) = (&opts.access_key_id, &opts.secret_access_key) {
        return Ok((Creds { access_key: k.clone(), secret: s.clone(), token: None }, None));
    }
    let credentials = read_ini(env, "AWS_SHARED_CREDENTIALS_FILE", "credentials");
    let config = read_ini(env, "AWS_CONFIG_FILE", "config");
    let from_profile = |name: &str| -> Result<Option<Creds>> {
        let config_name = if name == "default" { "default".to_string() } else { format!("profile {name}") };
        for (ini, section) in [(&credentials, name.to_string()), (&config, config_name)] {
            if let Some(s) = ini.get(&section)
                && let Some(c) = section_creds(s, &format!("the AWS profile {name:?}"))?
            {
                return Ok(Some(c));
            }
        }
        Ok(None)
    };
    if let Some(profile) = &opts.profile {
        let c = from_profile(profile)?.with_context(|| format!("The config profile ({profile}) could not be found"))?;
        return Ok((c, None));
    }
    if let (Some(k), Some(s)) = (env("AWS_ACCESS_KEY_ID").or_else(|| env("AWS_ACCESS_KEY")), env("AWS_SECRET_ACCESS_KEY").or_else(|| env("AWS_SECRET_KEY"))) {
        return Ok((Creds { access_key: k, secret: s, token: env("AWS_SESSION_TOKEN").or_else(|| env("AWS_SECURITY_TOKEN")) }, None));
    }
    if let Some(found) = web_identity(env, region).await? {
        return Ok(found);
    }
    let profile = env("AWS_PROFILE").or_else(|| env("AWS_DEFAULT_PROFILE")).unwrap_or_else(|| "default".into());
    if let Some(c) = from_profile(&profile)? {
        return Ok((c, None));
    }
    if let Some(found) = container(env).await? {
        return Ok(found);
    }
    if let Some(found) = instance_role(env).await? {
        return Ok(found);
    }
    bail!("Unable to locate credentials")
}

/// Credentials that renew themselves when their expiry is near.
pub struct Provider {
    opts: CredOptions,
    env: EnvFn,
    cache: Mutex<Option<(Creds, Option<DateTime<Utc>>)>>,
}

impl Provider {
    pub fn new(opts: CredOptions) -> Provider {
        Provider::with_env(opts, process_env())
    }

    pub fn with_env(opts: CredOptions, env: EnvFn) -> Provider {
        Provider { opts, env, cache: Mutex::new(None) }
    }

    pub fn env(&self) -> &EnvFn {
        &self.env
    }

    pub async fn get(&self, region: &str) -> Result<Creds> {
        let mut cache = self.cache.lock().await;
        if let Some((c, exp)) = cache.as_ref()
            && exp.is_none_or(|e| e - chrono::Duration::minutes(5) > Utc::now())
        {
            return Ok(c.clone());
        }
        let fresh = resolve(&self.opts, &self.env, region).await?;
        *cache = Some(fresh.clone());
        Ok(fresh.0)
    }
}

// ---- SigV4 ----

/// The headers to add to a request so that AWS accepts it: `x-amz-date`, `x-amz-security-token` (if any) and `authorization`.
/// `(region, service)` is the credential scope; `headers` are the other headers to sign (normally just `content-type`); `host` comes from `url`.
pub fn sign_v4(creds: &Creds, (region, service): (&str, &str), method: &str, url: &url::Url, headers: &[(String, String)], body: &[u8], now: DateTime<Utc>) -> Vec<(String, String)> {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = &amz_date[..8];
    let host = match (url.host_str(), url.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => String::new(),
    };
    let mut signed: Vec<(String, String)> = headers.iter().map(|(k, v)| (k.to_lowercase(), v.trim().to_string())).collect();
    signed.push(("host".into(), host));
    signed.push(("x-amz-date".into(), amz_date.clone()));
    if let Some(t) = &creds.token {
        signed.push(("x-amz-security-token".into(), t.clone()));
    }
    signed.sort();
    let canonical_headers: String = signed.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_names = signed.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
    let canonical = format!("{method}\n{}\n{}\n{canonical_headers}\n{signed_names}\n{}", url.path(), url.query().unwrap_or(""), sha256_hex(body));
    let scope = format!("{date}/{region}/{service}/aws4_request");
    let to_sign = format!("AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}", sha256_hex(canonical.as_bytes()));
    let mut key = hmac_sha256(format!("AWS4{}", creds.secret).as_bytes(), date.as_bytes());
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes());
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    let mut out = vec![("X-Amz-Date".to_string(), amz_date)];
    if let Some(t) = &creds.token {
        out.push(("X-Amz-Security-Token".into(), t.clone()));
    }
    out.push(("Authorization".into(), format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_names}, Signature={signature}", creds.access_key)));
    out
}

/// `https://<prefix>.<region>.amazonaws.com/`, or the endpoint override boto3 reads from the environment.
pub fn endpoint(env: &EnvFn, service_env: &str, prefix: &str, region: &str) -> String {
    env(&format!("AWS_ENDPOINT_URL_{service_env}")).or_else(|| env("AWS_ENDPOINT_URL")).unwrap_or_else(|| {
        let suffix = if region.starts_with("cn-") { "amazonaws.com.cn" } else { "amazonaws.com" };
        format!("https://{prefix}.{region}.{suffix}/")
    })
}

/// One AWS Query-protocol call (form-encoded POST, XML answer), signed with SigV4. Returns the XML text.
pub async fn query_call(client: &reqwest::Client, creds: &Creds, region: &str, signing_name: &str, endpoint: &str, fields: &[(&str, String)]) -> Result<String> {
    let action = fields.iter().find(|(k, _)| *k == "Action").map(|(_, v)| v.as_str()).unwrap_or("?");
    let body = super::http::form_body(fields);
    let content_type = "application/x-www-form-urlencoded; charset=utf-8".to_string();
    let url = url::Url::parse(endpoint).with_context(|| format!("invalid AWS endpoint {endpoint:?}"))?;
    let signed = sign_v4(creds, (region, signing_name), "POST", &url, &[("content-type".into(), content_type.clone())], body.as_bytes(), Utc::now());
    let mut req = client.post(url).header("Content-Type", content_type).body(body);
    for (k, v) in signed {
        req = req.header(k, v);
    }
    let resp = req.send().await.map_err(|e| anyhow!("Could not connect to the endpoint URL: {endpoint:?}: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status.is_success() {
        return Ok(text);
    }
    let code = xml_tag(&text, "Code").unwrap_or_else(|| status.as_u16().to_string());
    let message = xml_tag(&text, "Message").unwrap_or_else(|| text.chars().take(300).collect());
    bail!("An error occurred ({code}) when calling the {action} operation: {message}")
}

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(Duration::from_secs(60)).build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::serve;
    use chrono::TimeZone;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32, s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, s).unwrap()
    }

    fn auth(headers: &[(String, String)]) -> &str {
        &headers.iter().find(|(k, _)| k == "Authorization").unwrap().1
    }

    // References: botocore's SigV4Auth (1.43.118) at the same clock.
    #[test]
    fn sigv4_matches_botocore() {
        let creds = Creds { access_key: "AKIDEXAMPLE".into(), secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(), token: None };
        // the AWS test suite's get-vanilla case
        let h = sign_v4(&creds, ("us-east-1", "service"), "GET", &url::Url::parse("https://example.amazonaws.com/").unwrap(), &[], b"", at(2015, 8, 30, 12, 36, 0));
        assert_eq!(
            auth(&h),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        let body = "Action=Publish&Message=hello+%C3%A9&Subject=S&TopicArn=arn%3Aaws%3Asns%3Aus-east-1%3A123%3At&Version=2010-03-31";
        let ct = vec![("content-type".to_string(), "application/x-www-form-urlencoded; charset=utf-8".to_string())];
        let sns = url::Url::parse("https://sns.us-east-1.amazonaws.com/").unwrap();
        let h = sign_v4(&creds, ("us-east-1", "sns"), "POST", &sns, &ct, body.as_bytes(), at(2024, 1, 2, 3, 4, 5));
        assert_eq!(
            auth(&h),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/sns/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ada175922ae53fb7ba5529da0f07d0d137cff846eb11e8abc04d660e68731c24"
        );
        assert_eq!(h[0], ("X-Amz-Date".to_string(), "20240102T030405Z".to_string()));
        let with_token = Creds { token: Some("SESSIONTOKEN".into()), ..creds };
        let h = sign_v4(&with_token, ("us-east-1", "sns"), "POST", &sns, &ct, body.as_bytes(), at(2024, 1, 2, 3, 4, 5));
        assert_eq!(
            auth(&h),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20240102/us-east-1/sns/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=65a85ffbf788062381f452377be33c72b70efdefe3c9dd3ca6021e109778c19c"
        );
        assert!(h.contains(&("X-Amz-Security-Token".to_string(), "SESSIONTOKEN".to_string())));
    }

    fn env_of(pairs: &[(&str, String)]) -> EnvFn {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        Box::new(move |k| map.get(k).cloned())
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ea-aws-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn rule_keys_env_and_shared_files() {
        let opts = CredOptions { access_key_id: Some("K".into()), secret_access_key: Some("S".into()), profile: None };
        let (c, exp) = resolve(&opts, &env_of(&[]), "us-east-1").await.unwrap();
        assert_eq!((c.access_key.as_str(), c.token.as_deref(), exp), ("K", None, None));

        let env = env_of(&[("AWS_ACCESS_KEY_ID", "EK".into()), ("AWS_SECRET_ACCESS_KEY", "ES".into()), ("AWS_SESSION_TOKEN", "ET".into())]);
        let (c, _) = resolve(&CredOptions::default(), &env, "us-east-1").await.unwrap();
        assert_eq!((c.access_key.as_str(), c.secret.as_str(), c.token.as_deref()), ("EK", "ES", Some("ET")));

        let dir = temp_dir("files");
        std::fs::write(dir.join("credentials"), "[default]\naws_access_key_id = DK\naws_secret_access_key = DS\n\n# note\n[ops]\naws_access_key_id=OK\naws_secret_access_key=OS\naws_session_token=OT\n").unwrap();
        std::fs::write(dir.join("config"), "[default]\nregion = eu-west-3\n[profile ops]\nregion = ap-south-1\n[profile boss]\nrole_arn = arn:aws:iam::1:role/x\n").unwrap();
        let env = |extra: &[(&str, String)]| {
            let mut v = vec![("AWS_SHARED_CREDENTIALS_FILE", dir.join("credentials").to_string_lossy().into_owned()), ("AWS_CONFIG_FILE", dir.join("config").to_string_lossy().into_owned())];
            v.extend(extra.iter().map(|(k, x)| (*k, x.clone())));
            env_of(&v)
        };
        let (c, _) = resolve(&CredOptions::default(), &env(&[]), "us-east-1").await.unwrap();
        assert_eq!(c.access_key, "DK");
        let ops = CredOptions { profile: Some("ops".into()), ..Default::default() };
        let (c, _) = resolve(&ops, &env(&[]), "us-east-1").await.unwrap();
        assert_eq!((c.access_key.as_str(), c.token.as_deref()), ("OK", Some("OT")));
        let (c, _) = resolve(&CredOptions::default(), &env(&[("AWS_PROFILE", "ops".into())]), "us-east-1").await.unwrap();
        assert_eq!(c.access_key, "OK");
        let missing = CredOptions { profile: Some("nope".into()), ..Default::default() };
        assert!(resolve(&missing, &env(&[]), "us-east-1").await.unwrap_err().to_string().contains("could not be found"));
        let boss = CredOptions { profile: Some("boss".into()), ..Default::default() };
        assert!(resolve(&boss, &env(&[]), "us-east-1").await.unwrap_err().to_string().contains("role_arn"));
        assert_eq!(region(None, Some("ops"), Some("us-east-1"), &env(&[])).unwrap(), "ap-south-1");
        assert_eq!(region(Some("x"), Some("ops"), None, &env(&[])).unwrap(), "x");
        assert_eq!(region(None, None, None, &env(&[("AWS_DEFAULT_REGION", "sa-east-1".into())])).unwrap(), "sa-east-1");
        assert!(region(None, None, None, &env(&[])).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn instance_ecs_and_web_identity_roles() {
        let creds = |k: &str| json!({"AccessKeyId": k, "SecretAccessKey": "S", "Token": "T", "Expiration": "2999-01-01T00:00:00Z"}).to_string();
        // EC2 instance role (IMDSv2)
        let (url, log) = serve(vec![
            ("PUT", "/latest/api/token", 200, "TOK".into()),
            ("GET", "/latest/meta-data/iam/security-credentials/web-role", 200, creds("IMDS")),
            ("GET", "/latest/meta-data/iam/security-credentials/", 200, "web-role\n".into()),
        ])
        .await;
        let env = env_of(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", url.clone())]);
        let (c, exp) = resolve(&CredOptions::default(), &env, "us-east-1").await.unwrap();
        assert_eq!((c.access_key.as_str(), c.token.as_deref()), ("IMDS", Some("T")));
        assert!(exp.is_some());
        assert!(log.lock().unwrap().iter().skip(1).all(|r| r.header("x-aws-ec2-metadata-token") == Some("TOK")));
        assert!(resolve(&CredOptions::default(), &env_of(&[("AWS_EC2_METADATA_SERVICE_ENDPOINT", url), ("AWS_EC2_METADATA_DISABLED", "true".into())]), "r").await.is_err());

        // ECS task role
        let (url, log) = serve(vec![("GET", "/creds/task", 200, creds("ECS"))]).await;
        let env = env_of(&[("AWS_CONTAINER_CREDENTIALS_HOST", url), ("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/creds/task".into()), ("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Bearer x".into())]);
        let (c, _) = resolve(&CredOptions::default(), &env, "us-east-1").await.unwrap();
        assert_eq!(c.access_key, "ECS");
        assert_eq!(log.lock().unwrap()[0].header("authorization"), Some("Bearer x"));

        // EKS web identity
        let xml = "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>WEB</AccessKeyId><SecretAccessKey>S&amp;1</SecretAccessKey><SessionToken>ST</SessionToken><Expiration>2999-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>";
        let (url, log) = serve(vec![("POST", "/", 200, xml.into())]).await;
        let dir = temp_dir("web");
        std::fs::write(dir.join("token"), "jwt-token\n").unwrap();
        let env = env_of(&[("AWS_WEB_IDENTITY_TOKEN_FILE", dir.join("token").to_string_lossy().into_owned()), ("AWS_ROLE_ARN", "arn:aws:iam::1:role/r".into()), ("AWS_ENDPOINT_URL_STS", url)]);
        let (c, _) = resolve(&CredOptions::default(), &env, "us-east-1").await.unwrap();
        assert_eq!((c.access_key.as_str(), c.secret.as_str(), c.token.as_deref()), ("WEB", "S&1", Some("ST")));
        let sent = log.lock().unwrap()[0].body.clone();
        assert!(sent.contains("Action=AssumeRoleWithWebIdentity") && sent.contains("WebIdentityToken=jwt-token") && sent.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fr"), "{sent}");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn provider_caches_until_expiry() {
        let provider = Provider::with_env(CredOptions { access_key_id: Some("K".into()), secret_access_key: Some("S".into()), profile: None }, env_of(&[]));
        assert_eq!(provider.get("us-east-1").await.unwrap(), provider.get("us-east-1").await.unwrap());
    }

    #[tokio::test]
    async fn query_call_signs_and_parses_errors() {
        let (url, log) = serve(vec![("POST", "/ok", 200, "<R><MessageId>m-1</MessageId></R>".into()), ("POST", "/bad", 403, "<ErrorResponse><Error><Code>AuthorizationError</Code><Message>not allowed</Message></Error></ErrorResponse>".into())]).await;
        let creds = Creds { access_key: "AK".into(), secret: "SK".into(), token: Some("T".into()) };
        let c = client().unwrap();
        let ok = query_call(&c, &creds, "eu-west-1", "sns", &format!("{url}/ok"), &[("Action", "Publish".into()), ("Message", "é x".into())]).await.unwrap();
        assert_eq!(xml_tag(&ok, "MessageId").as_deref(), Some("m-1"));
        let req = log.lock().unwrap()[0].body.clone();
        assert_eq!(req, "Action=Publish&Message=%C3%A9+x");
        let h = log.lock().unwrap()[0].headers.clone();
        assert!(h.iter().any(|(k, v)| k.eq_ignore_ascii_case("authorization") && v.contains("Credential=AK/") && v.contains("/eu-west-1/sns/aws4_request")));
        assert!(h.iter().any(|(k, v)| k.eq_ignore_ascii_case("x-amz-security-token") && v == "T"));
        let err = query_call(&c, &creds, "eu-west-1", "sns", &format!("{url}/bad"), &[("Action", "Publish".into())]).await.unwrap_err();
        assert_eq!(err.to_string(), "An error occurred (AuthorizationError) when calling the Publish operation: not allowed");
    }

    #[test]
    fn endpoints() {
        let none = env_of(&[]);
        assert_eq!(endpoint(&none, "SNS", "sns", "eu-west-1"), "https://sns.eu-west-1.amazonaws.com/");
        assert_eq!(endpoint(&none, "SES", "email", "cn-north-1"), "https://email.cn-north-1.amazonaws.com.cn/");
        assert_eq!(endpoint(&env_of(&[("AWS_ENDPOINT_URL", "http://localstack:4566".into())]), "SQS", "sqs", "x"), "http://localstack:4566");
        assert_eq!(endpoint(&env_of(&[("AWS_ENDPOINT_URL", "http://a".into()), ("AWS_ENDPOINT_URL_SQS", "http://b".into())]), "SQS", "sqs", "x"), "http://b");
    }
}
