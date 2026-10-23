//! `opsgenie` alerter.

use super::http::Http;
use super::{Doc, View, per_match_text, required, s, s_or};
use crate::alert::py_format;
use crate::config::expand_env;
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

pub struct OpsGenie {
    account: Option<String>,
    api_key: String,
    default_recipients: Option<Vec<String>>,
    recipients: Option<Vec<String>>,
    recipients_args: Map<String, Value>,
    default_teams: Option<Vec<String>>,
    teams: Option<Vec<String>>,
    teams_args: Map<String, Value>,
    tags: Vec<String>,
    to_addr: String,
    description: Option<String>,
    custom_message: Option<String>,
    subject: Option<String>,
    subject_args: Option<Vec<Value>>,
    alias: Option<String>,
    priority: Option<String>,
    details: Map<String, Value>,
    entity: Option<String>,
    source: Option<String>,
    http: Http,
}

/// Python `template.format(**m)` for the forms seen in OpsGenie options: `{name}`, `{name[key]}`, `{{` and `}}`.
/// A missing key is an error (`KeyError`), as upstream.
fn format_map(template: &str, m: &Doc) -> Result<String> {
    let mut out = String::new();
    let mut chars = template.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        match c {
            '{' if chars.peek().map(|x| x.1) == Some('{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek().map(|x| x.1) == Some('}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let end = template[i..].find('}').ok_or_else(|| anyhow!("ValueError: expected '}}' before end of string"))?;
                let inner = &template[i + 1..i + end];
                while chars.peek().is_some_and(|x| x.0 <= i + end) {
                    chars.next();
                }
                let field = inner.split([':', '!']).next().unwrap_or("");
                let (name, mut rest) = field.split_at(field.find(['[', '.']).unwrap_or(field.len()));
                if name.is_empty() || name.chars().all(|c| c.is_ascii_digit()) {
                    bail!("IndexError: Replacement index {name} out of range for positional args tuple");
                }
                let mut cur = m.get(name).ok_or_else(|| anyhow!("KeyError: '{name}'"))?;
                while !rest.is_empty() {
                    let Some(tail) = rest.strip_prefix('[') else { bail!("AttributeError: '{name}' has no attribute access in {{{inner}}}") };
                    let (key, after) = tail.split_once(']').ok_or_else(|| anyhow!("ValueError: Missing ']' in format string"))?;
                    cur = match (cur, key.parse::<usize>()) {
                        (Value::Array(a), Ok(n)) => a.get(n),
                        (Value::Object(o), _) => o.get(key),
                        _ => None,
                    }
                    .ok_or_else(|| anyhow!("KeyError: '{key}'"))?;
                    rest = after;
                }
                out.push_str(&py_str(cur));
            }
            '}' => bail!("ValueError: Single '}}' encountered in format string"),
            _ => out.push(c),
        }
    }
    Ok(out)
}

fn strings(rule: &Rule, key: &str) -> Option<Vec<String>> {
    match rule.raw.get(key) {
        Some(Value::Array(a)) => Some(a.iter().map(py_str).collect()),
        Some(Value::Null) | None => None,
        Some(other) => Some(vec![py_str(other)]),
    }
}

fn obj(rule: &Rule, key: &str) -> Map<String, Value> {
    rule.raw.get(key).and_then(Value::as_object).cloned().unwrap_or_default()
}

impl OpsGenie {
    pub(super) fn new(rule: &Rule) -> Result<OpsGenie> {
        required(rule, "opsgenie", "opsgenie_key")?;
        let deprecated = strings(rule, "opsgenie_default_receipients");
        if deprecated.is_some() {
            log::warn!("OpsGenieAlerter: `opsgenie_default_receipients` rule configuration option is deprecated and will be removed in the future. Please use `opsgenie_default_recipients` option instead.");
        }
        let mut tags = strings(rule, "opsgenie_tags").unwrap_or_default();
        tags.extend(["ElastAlert".to_string(), rule.name.clone()]);
        Ok(OpsGenie {
            account: s(rule, "opsgenie_account"),
            api_key: s_or(rule, "opsgenie_key", "key"),
            default_recipients: strings(rule, "opsgenie_default_recipients").or(deprecated),
            recipients: strings(rule, "opsgenie_recipients"),
            recipients_args: obj(rule, "opsgenie_recipients_args"),
            default_teams: strings(rule, "opsgenie_default_teams"),
            teams: strings(rule, "opsgenie_teams"),
            teams_args: obj(rule, "opsgenie_teams_args"),
            tags,
            to_addr: s_or(rule, "opsgenie_addr", "https://api.opsgenie.com/v2/alerts"),
            description: s(rule, "opsgenie_description"),
            custom_message: s(rule, "opsgenie_message"),
            subject: s(rule, "opsgenie_subject").filter(|x| !x.is_empty()),
            subject_args: rule.raw.get("opsgenie_subject_args").and_then(Value::as_array).filter(|a| !a.is_empty()).cloned(),
            alias: s(rule, "opsgenie_alias"),
            priority: s(rule, "opsgenie_priority"),
            details: obj(rule, "opsgenie_details"),
            entity: s(rule, "opsgenie_entity"),
            source: rule.raw.get("opsgenie_source").map(|v| v.as_str().map(String::from)).unwrap_or(Some("ElastAlert".into())),
            http: Http::new(rule, "opsgenie", 60)?,
        })
    }

    fn parse_responders(responders: &Option<Vec<String>>, args: &Map<String, Value>, defaults: &Option<Vec<String>>, first: &Doc) -> Option<Vec<String>> {
        let responders = responders.as_ref()?;
        let values: Doc = args
            .iter()
            .filter_map(|(k, v)| v.as_str().and_then(|path| lookup(first, path)).filter(|x| truthy(Some(x))).map(|x| (k.clone(), x.clone())))
            .collect();
        let mut formatted = vec![];
        for r in responders {
            match format_map(r, &values) {
                Ok(x) => formatted.push(x),
                Err(e) => log::warn!("OpsGenieAlerter: Cannot create responder for OpsGenie Alert. Key not found: {e}. "),
            }
        }
        if formatted.is_empty() {
            log::warn!("OpsGenieAlerter: no responders can be formed. Trying the default responder ");
            match defaults.as_ref().filter(|d| !d.is_empty()) {
                Some(d) => formatted = d.clone(),
                None => {
                    log::warn!("OpsGenieAlerter: default responder not set. Falling back");
                    formatted = responders.clone();
                }
            }
        }
        Some(formatted)
    }

    fn title(&self, v: &View<'_>, matches: &[Doc]) -> String {
        let first = &matches[0];
        match &self.subject {
            Some(subject) => match &self.subject_args {
                Some(args) => {
                    let vals: Vec<String> = args
                        .iter()
                        .map(|a| {
                            let name = py_str(a);
                            let found = lookup(first, &name).filter(|x| !x.is_null()).or_else(|| v.rule.raw.get(&name).filter(|x| truthy(Some(x))));
                            found.map(py_str).unwrap_or_else(|| "<MISSING VALUE>".into())
                        })
                        .collect();
                    py_format(subject, &vals, &Map::new())
                }
                None => subject.clone(),
            },
            None => {
                let mut subj = format!("ElastAlert: {}", v.rule.name);
                if let Some(qk) = v.rule.query_key.as_ref().and_then(|qk| first.get(qk)).filter(|x| truthy(Some(x))) {
                    subj.push_str(&format!(" - {}", py_str(qk)));
                }
                subj
            }
        }
    }

    fn details(&self, first: &Doc) -> Map<String, Value> {
        let mut out = Map::new();
        for (key, value) in &self.details {
            match value {
                Value::Object(o) if o.contains_key("field") => {
                    if let Some(x) = o["field"].as_str().and_then(|f| lookup(first, f)).filter(|x| !x.is_null()) {
                        out.insert(key.clone(), json!(py_str(x)));
                    }
                }
                Value::String(s) => {
                    out.insert(key.clone(), json!(expand_env(s)));
                }
                _ => {}
            }
        }
        out
    }

    fn post(&self, v: &View<'_>, matches: &[Doc]) -> Result<Value> {
        let first = &matches[0];
        let message = match &self.custom_message {
            None => self.title(v, matches),
            Some(m) => format_map(m, first)?,
        };
        let recipients = Self::parse_responders(&self.recipients, &self.recipients_args, &self.default_recipients, first);
        let teams = Self::parse_responders(&self.teams, &self.teams_args, &self.default_teams, first);
        let mut post = json!({"message": message});
        if let Some(a) = self.account.as_ref().filter(|x| !x.is_empty()) {
            post["user"] = json!(a);
        }
        if let Some(r) = recipients.filter(|r| !r.is_empty()) {
            post["responders"] = Value::Array(r.iter().map(|x| json!({"username": x, "type": "user"})).collect());
        }
        if let Some(t) = teams.filter(|t| !t.is_empty()) {
            post["teams"] = Value::Array(t.iter().map(|x| json!({"name": x, "type": "team"})).collect());
        }
        post["description"] = match self.description.as_ref().filter(|d| !d.is_empty()) {
            Some(d) => json!(format_map(d, first)?),
            None => json!(per_match_text(v, matches)),
        };
        if let Some(e) = self.entity.as_ref().filter(|x| !x.is_empty()) {
            post["entity"] = json!(format_map(e, first)?);
        }
        if let Some(src) = self.source.as_ref().filter(|x| !x.is_empty()) {
            post["source"] = json!(format_map(src, first)?);
        }
        post["tags"] = Value::Array(self.tags.iter().map(|t| format_map(t, first).map(Value::String)).collect::<Result<_>>()?);
        let priority = self.priority.as_ref().filter(|p| !p.is_empty()).map(|p| format_map(p, first)).transpose()?;
        match priority {
            Some(p) if !["P1", "P2", "P3", "P4", "P5"].contains(&p.as_str()) => {
                log::warn!("Priority level does not appear to be specified correctly. Please make sure to set it to a value between P1 and P5");
            }
            Some(p) => post["priority"] = json!(p),
            None => post["priority"] = Value::Null,
        }
        if let Some(alias) = &self.alias {
            post["alias"] = json!(format_map(alias, first)?);
        }
        let details = self.details(first);
        if !details.is_empty() {
            post["details"] = Value::Object(details);
        }
        Ok(post)
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let post = self.post(v, matches)?;
        let url = format_map(&self.to_addr, &matches[0])?;
        let headers = [("Content-Type".to_string(), "application/json".to_string()), ("Authorization".into(), format!("GenieKey {}", self.api_key))];
        self.http.post_json("alert to OpsGenie", &url, &headers, &post).await.map_err(|e| anyhow!("Error sending alert: {e}"))?;
        log::info!("Alert sent to OpsGenie");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        let mut ret = json!({"type": "opsgenie"});
        if let Some(r) = self.recipients.as_ref().filter(|r| !r.is_empty()) {
            ret["recipients"] = json!(r);
        }
        if let Some(a) = self.account.as_ref().filter(|a| !a.is_empty()) {
            ret["account"] = json!(a);
        }
        if let Some(t) = self.teams.as_ref().filter(|t| !t.is_empty()) {
            ret["teams"] = json!(t);
        }
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture, rule};
    use crate::types::RuleType;

    fn m() -> Doc {
        json!({"@timestamp": "2014-10-31T00:00:00", "Stuff": "bad", "user": {"name": "bob"}, "team": "ops"}).as_object().unwrap().clone()
    }

    #[test]
    fn format_map_cases() {
        let d = m();
        assert_eq!(format_map("a {Stuff} {{x}} {user[name]}", &d).unwrap(), "a bad {x} bob");
        assert!(format_map("{nope}", &d).unwrap_err().to_string().contains("KeyError: 'nope'"));
        assert!(format_map("{}", &d).is_err());
        assert!(format_map("{user.name}", &d).is_err());
    }

    #[test]
    fn default_post() {
        let r = rule("opsgenie", "opsgenie_key: genie\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let og = OpsGenie::new(&r).unwrap();
        let post = og.post(&v, &[m()]).unwrap();
        assert_eq!(post["message"], json!("ElastAlert: r"));
        assert_eq!(post["tags"], json!(["ElastAlert", "r"]));
        assert_eq!(post["source"], json!("ElastAlert"));
        assert_eq!(post["priority"], Value::Null);
        assert!(post["description"].as_str().unwrap().starts_with("r\n\n"));
        assert!(post.get("responders").is_none() && post.get("details").is_none());
    }

    #[test]
    fn full_post() {
        let r = rule(
            "opsgenie",
            "opsgenie_key: genie\nopsgenie_account: acct\nopsgenie_recipients: ['{u}', '{missing}']\nopsgenie_recipients_args: {u: user.name}\nopsgenie_teams: ['{t}']\nopsgenie_teams_args: {t: team}\nopsgenie_tags: ['t-{Stuff}']\nopsgenie_message: 'msg {Stuff}'\nopsgenie_priority: P2\nopsgenie_alias: 'al-{Stuff}'\nopsgenie_entity: 'e-{team}'\nopsgenie_details: {k1: {field: Stuff}, k2: literal, k3: {field: absent}, k4: 5}\n",
        )
        .unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let post = OpsGenie::new(&r).unwrap().post(&v, &[m()]).unwrap();
        assert_eq!(post["message"], json!("msg bad"));
        assert_eq!(post["user"], json!("acct"));
        assert_eq!(post["responders"], json!([{"username": "bob", "type": "user"}]));
        assert_eq!(post["teams"], json!([{"name": "ops", "type": "team"}]));
        assert_eq!(post["tags"], json!(["t-bad", "ElastAlert", "r"]));
        assert_eq!((&post["priority"], &post["alias"], &post["entity"]), (&json!("P2"), &json!("al-bad"), &json!("e-ops")));
        assert_eq!(post["details"], json!({"k1": "bad", "k2": "literal"}));
    }

    #[test]
    fn responder_fallbacks_and_bad_priority() {
        let r = rule("opsgenie", "opsgenie_key: g\nopsgenie_recipients: ['{x}']\nopsgenie_recipients_args: {x: nothere}\nopsgenie_default_recipients: [dflt]\nopsgenie_priority: high\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let post = OpsGenie::new(&r).unwrap().post(&v, &[m()]).unwrap();
        assert_eq!(post["responders"], json!([{"username": "dflt", "type": "user"}]));
        assert!(post.get("priority").is_none());
        let r = rule("opsgenie", "opsgenie_key: g\nopsgenie_recipients: ['{x}']\nopsgenie_subject: 'S {0}'\nopsgenie_subject_args: [Stuff]\n").unwrap();
        let og = OpsGenie::new(&r).unwrap();
        let post = og.post(&View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() }, &[m()]).unwrap();
        assert_eq!(post["responders"], json!([{"username": "{x}", "type": "user"}]));
        assert_eq!(post["message"], json!("S bad"));
    }

    #[tokio::test]
    async fn sends_with_genie_key() {
        let (url, got) = capture(1, 202).await;
        let r = rule("opsgenie", &format!("opsgenie_key: genie\nopsgenie_addr: {url}/v2/alerts\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        OpsGenie::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!(got[0].header("authorization"), Some("GenieKey genie"));
        assert_eq!(got[0].path, "/v2/alerts");
    }
}
