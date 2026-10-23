//! `jira` alerter: opens a ticket (or comments on / transitions an existing one) through the REST API.
//!
//! Upstream connects to Jira when the rule is loaded; here the connection, the priority list and the field definitions are
//! fetched on the first alert, so `validate` and `test-rule --schema-only` work offline.

use super::http::Http;
use super::{Doc, View, required, s, s_or};
use crate::alert::{create_title, match_body_in, summary_text};
use crate::field::{lookup, py_str, truthy};
use crate::rule::Rule;
use crate::time;
use anyhow::{Context, Result, anyhow, bail};
use reqwest::Method;
use serde_json::{Map, Value, json};
use tokio::sync::OnceCell;

/// Options with a meaning of their own; any other `jira_*` option names a Jira field to set.
const KNOWN: [&str; 21] = [
    "jira_account_file",
    "jira_assignee",
    "jira_bump_after_inactivity",
    "jira_bump_in_statuses",
    "jira_bump_not_in_statuses",
    "jira_bump_only",
    "jira_bump_tickets",
    "jira_component",
    "jira_components",
    "jira_description",
    "jira_ignore_in_title",
    "jira_issuetype",
    "jira_label",
    "jira_labels",
    "jira_max_age",
    "jira_priority",
    "jira_project",
    "jira_server",
    "jira_transition_to",
    "jira_watchers",
    "jira_parent",
];

/// Custom field types the metadata calls strings but that the API wants as `{"value": ...}`.
const SPECIAL_CUSTOM: [&str; 3] = [
    "com.atlassian.jira.plugin.system.customfieldtypes:multicheckboxes",
    "com.atlassian.jira.plugin.system.customfieldtypes:multiselect",
    "com.atlassian.jira.plugin.system.customfieldtypes:radiobuttons",
];

struct Meta {
    priority_ids: Vec<String>,
    fields: Vec<Value>,
    cloud: bool,
}

pub struct Jira {
    server: String,
    token: Option<String>,
    project: String,
    issue_type: String,
    parent: Option<String>,
    components: Vec<String>,
    labels: Vec<String>,
    description: String,
    assignee: Option<String>,
    max_age: f64,
    priority: Option<Value>,
    bump_tickets: bool,
    bump_in_statuses: Vec<String>,
    bump_not_in_statuses: Vec<String>,
    bump_after_inactivity: f64,
    bump_only: bool,
    transition: Option<String>,
    watchers: Vec<String>,
    /// `jira_<field name or id>: value`, set on every ticket.
    fixed_fields: Vec<(String, Value)>,
    /// `jira_<field>: '#some.match.field'`, read from the first match.
    deferred_fields: Vec<(String, String)>,
    http: Http,
    meta: OnceCell<Meta>,
}

fn strings(rule: &Rule, keys: &[&str]) -> Vec<String> {
    match keys.iter().find_map(|k| rule.raw.get(*k).filter(|v| !v.is_null())) {
        Some(Value::Array(a)) => a.iter().map(py_str).collect(),
        Some(other) => vec![py_str(other)],
        None => vec![],
    }
}

enum Auth {
    Basic(String, String),
    Token(String),
}

/// `jira_account_file`: a YAML file with `user` and `password`, or `apikey`; relative to the rule file.
fn credentials(rule: &Rule, file: &str) -> Result<Auth> {
    let base = std::path::Path::new(rule.raw.get("rule_file").and_then(Value::as_str).unwrap_or("."));
    let path = if std::path::Path::new(file).is_absolute() { file.into() } else { base.parent().unwrap_or(".".as_ref()).join(file) };
    let conf = crate::config::read_yaml(&path)?;
    if let Some(key) = conf["apikey"].as_str() {
        return Ok(Auth::Token(key.to_string()));
    }
    match (conf["user"].as_str(), conf["password"].as_str()) {
        (Some(u), Some(p)) => Ok(Auth::Basic(u.into(), p.into())),
        _ => bail!("Account file must have user and password fields, or apikey field"),
    }
}

/// A Python-style `int(value)`.
fn to_int(v: &Value) -> Result<Value> {
    match v {
        Value::Number(n) => Ok(json!(n.as_f64().unwrap_or(0.0) as i64)),
        Value::String(s) => s.trim().parse::<i64>().map(|n| json!(n)).with_context(|| format!("invalid literal for int(): {s:?}")),
        other => bail!("int() argument must be a string or a number, not {other}"),
    }
}

/// Puts `value` in `args` under the id of the Jira field named by `jira_field`, shaped the way the field's schema needs.
fn set_jira_arg(args: &mut Map<String, Value>, jira_field: &str, value: &Value, fields: &[Value]) -> Result<()> {
    let normalized = jira_field[5..].replace('_', " ").to_lowercase();
    let norm = |f: &Value, key: &str| f[key].as_str().map(|x| x.replace('_', " ").to_lowercase());
    let field = ["name", "id"].iter().find_map(|key| fields.iter().find(|f| norm(f, key).as_deref() == Some(normalized.as_str())));
    let Some(field) = field else { bail!("Could not find a definition for the jira field '{normalized}'") };
    let arg_name = field["id"].as_str().unwrap_or_default().to_string();
    let Some(schema) = field.get("schema") else { bail!("Could not determine schema information for the jira field '{normalized}'") };
    let special = schema["custom"].as_str().is_some_and(|c| SPECIAL_CUSTOM.contains(&c));
    let result = if schema["type"] == json!("array") {
        let items: Vec<Value> = match value {
            Value::Array(a) => a.clone(),
            other => vec![other.clone()],
        };
        match schema["items"].as_str().unwrap_or_default() {
            "string" | "date" | "datetime" if special => Value::Array(items.iter().map(|v| json!({"value": v})).collect()),
            "string" | "date" | "datetime" => Value::Array(items),
            "number" => Value::Array(items.iter().map(to_int).collect::<Result<_>>()?),
            "option" => Value::Array(items.iter().map(|v| json!({"value": v})).collect()),
            _ => Value::Array(items.iter().map(|v| json!({"name": v})).collect()),
        }
    } else {
        match schema["type"].as_str().unwrap_or_default() {
            "string" | "date" | "datetime" if special => json!({"value": value}),
            "string" | "date" | "datetime" => value.clone(),
            "number" => to_int(value)?,
            "option" => json!({"value": value}),
            _ => json!({"name": value}),
        }
    };
    args.insert(arg_name, result);
    Ok(())
}

impl Jira {
    pub(super) fn new(rule: &Rule) -> Result<Jira> {
        for k in ["jira_server", "jira_account_file", "jira_project", "jira_issuetype"] {
            required(rule, "jira", k)?;
        }
        let mut http = Http::raw(None, None, false, 60)?;
        let mut token = None;
        match credentials(rule, &s(rule, "jira_account_file").unwrap_or_default())? {
            Auth::Basic(u, p) => http = http.with_basic_auth(u, p),
            Auth::Token(t) => token = Some(t),
        }
        let bump_in = strings(rule, &["jira_bump_in_statuses"]);
        let bump_not_in = strings(rule, &["jira_bump_not_in_statuses"]);
        if !bump_in.is_empty() && !bump_not_in.is_empty() {
            let common: Vec<&String> = bump_in.iter().filter(|s| bump_not_in.contains(s)).collect();
            let mut msg = format!("Both jira_bump_in_statuses ({}) and jira_bump_not_in_statuses ({}) are set.", bump_in.join(","), bump_not_in.join(","));
            if !common.is_empty() {
                msg.push_str(&format!(" Both have common statuses of ({}). As such, no tickets will ever be found.", common.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")));
            }
            msg.push_str(" This should be simplified to use only one or the other.");
            log::warn!("{msg}");
        }
        let (mut fixed, mut deferred) = (vec![], vec![]);
        for (key, value) in &rule.raw {
            if key.starts_with("jira_") && !KNOWN.contains(&key.as_str()) {
                let text = py_str(value);
                match text.strip_prefix('#') {
                    Some(path) if text.starts_with('#') => deferred.push((key.clone(), path.to_string())),
                    _ => fixed.push((key.clone(), value.clone())),
                }
            }
        }
        Ok(Jira {
            server: s(rule, "jira_server").unwrap_or_default(),
            token,
            project: py_str(&rule.raw["jira_project"]),
            issue_type: py_str(&rule.raw["jira_issuetype"]),
            parent: s(rule, "jira_parent").filter(|p| !p.is_empty()),
            components: strings(rule, &["jira_components", "jira_component"]),
            labels: strings(rule, &["jira_labels", "jira_label"]),
            description: s_or(rule, "jira_description", ""),
            assignee: s(rule, "jira_assignee").filter(|a| !a.is_empty()),
            max_age: rule.raw.get("jira_max_age").and_then(Value::as_f64).unwrap_or(30.0),
            priority: rule.raw.get("jira_priority").filter(|p| !p.is_null()).cloned(),
            bump_tickets: rule.raw.get("jira_bump_tickets").is_some_and(|v| truthy(Some(v))),
            bump_in_statuses: bump_in,
            bump_not_in_statuses: bump_not_in,
            bump_after_inactivity: rule.raw.get("jira_bump_after_inactivity").and_then(Value::as_f64).unwrap_or(0.0),
            bump_only: rule.raw.get("jira_bump_only").is_some_and(|v| truthy(Some(v))),
            transition: s(rule, "jira_transition_to"),
            watchers: strings(rule, &["jira_watchers"]),
            fixed_fields: fixed,
            deferred_fields: deferred,
            http,
            meta: OnceCell::new(),
        })
    }

    // ---- REST ----

    async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        let url = format!("{}/rest/api/{path}", self.server.trim_end_matches('/'));
        let mut headers = vec![("Accept".to_string(), "application/json".to_string())];
        if let Some(t) = &self.token {
            headers.push(("Authorization".into(), format!("Bearer {t}")));
        }
        let resp = self.http.request(method, "calling Jira", &url, &headers, body).await?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("JiraError HTTP {} url: {url}\n\ttext: {}", status.as_u16(), text.chars().take(1024).collect::<String>());
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    async fn meta(&self) -> Result<&Meta> {
        self.meta
            .get_or_try_init(|| async {
                let load = async {
                    let info = self.call(Method::GET, "2/serverInfo", None).await?;
                    let priorities = self.call(Method::GET, "2/priority", None).await?;
                    let fields = self.call(Method::GET, "2/field", None).await?;
                    anyhow::Ok(Meta {
                        priority_ids: priorities.as_array().into_iter().flatten().map(|p| py_str(&p["id"])).collect(),
                        fields: fields.as_array().cloned().unwrap_or_default(),
                        cloud: info["deploymentType"] == json!("Cloud"),
                    })
                };
                load.await.map_err(|e| anyhow!("Error connecting to Jira: {}", format!("{e:#}").chars().take(1024).collect::<String>()))
            })
            .await
    }

    // ---- ticket content ----

    fn base_args(&self, meta: &Meta) -> Map<String, Value> {
        let mut args = Map::new();
        args.insert("project".into(), json!({"key": self.project}));
        if let Some(parent) = &self.parent {
            args.insert("parent".into(), json!({"key": parent}));
        }
        args.insert("issuetype".into(), json!({"name": self.issue_type}));
        if !self.components.is_empty() {
            args.insert("components".into(), Value::Array(self.components.iter().map(|c| json!({"name": c})).collect()));
        }
        if !self.labels.is_empty() {
            args.insert("labels".into(), json!(self.labels));
        }
        if let Some(p) = &self.priority {
            match p.as_u64().and_then(|i| meta.priority_ids.get(i as usize)) {
                Some(id) => {
                    args.insert("priority".into(), json!({"id": id}));
                }
                None => log::error!("Priority {} not found. Valid priorities are {:?}", py_str(p), (0..meta.priority_ids.len()).collect::<Vec<_>>()),
            }
        }
        args
    }

    fn default_title(&self, v: &View<'_>, first: &Doc, for_search: bool) -> String {
        let name = &v.rule.name;
        let mut title = match v.rule.query_key.as_deref().and_then(|qk| lookup(first, qk)).filter(|x| truthy(Some(x))) {
            Some(qk) => format!("ElastAlert: {} matched {name}", py_str(qk)),
            None => format!("ElastAlert: {name}"),
        };
        if for_search {
            return title;
        }
        if let Some(ts) = first.get(&v.rule.timestamp_field).filter(|x| truthy(Some(x))) {
            let text = py_str(ts);
            title.push_str(&format!(" - {}", time::parse_iso(&text).map_or(text, |t| time::pretty(t, v.rule.use_local_time, v.ts_fmt))));
        }
        if let Some(count) = first.get("spike_count").filter(|x| truthy(Some(x))) {
            title.push_str(&format!(" - {}+ events", py_str(count)));
        }
        title
    }

    fn title(&self, v: &View<'_>, matches: &[Doc]) -> String {
        create_title(v.rule, matches, || self.default_title(v, &matches[0], false))
    }

    /// Description, aggregation summary in `{noformat}`, then every match with its fields in a `{code}` block.
    fn body(&self, v: &View<'_>, matches: &[Doc]) -> String {
        let mut body = format!("{}\n", self.description);
        let summary = summary_text(v.rule, matches, 80);
        if !summary.is_empty() {
            body.push_str(&format!("{{noformat}}{summary}{{noformat}}"));
        }
        if v.rule.raw.get("alert_text_type").and_then(Value::as_str) != Some("aggregation_summary_only") {
            for m in matches {
                body.push_str(&match_body_in(v.rule, v.rtype, m, v.ts_fmt, true));
                if matches.len() > 1 {
                    body.push_str("\n----------------------------------------\n");
                }
            }
        }
        body
    }

    // ---- existing tickets ----

    fn search_jql(&self, v: &View<'_>, matches: &[Doc]) -> String {
        let mut title = if v.rule.raw.contains_key("alert_subject") { self.title(v, matches) } else { self.default_title(v, &matches[0], true) };
        if let Some(field) = v.rule.raw.get("jira_ignore_in_title") {
            let ignored = field.as_str().and_then(|f| matches[0].get(f)).map(py_str).unwrap_or_default();
            title = title.replace(&ignored, "");
        }
        // Needed for the search to work; other special characters and dashes next to words are fine.
        title = title.replace(" - ", " ").replace('\\', "\\\\");
        let date = (chrono::Local::now() - chrono::Duration::microseconds((self.max_age * 86_400e6) as i64)).format("%Y-%m-%d");
        let mut jql = format!("project={} AND summary~\"{title}\" and created >= \"{date}\"", self.project);
        let quote = |statuses: &[String]| statuses.iter().map(|s| if s.contains(' ') { format!("\"{s}\"") } else { s.clone() }).collect::<Vec<_>>().join(",");
        if !self.bump_in_statuses.is_empty() {
            jql.push_str(&format!(" and status in ({})", quote(&self.bump_in_statuses)));
        }
        if !self.bump_not_in_statuses.is_empty() {
            jql.push_str(&format!(" and status not in ({})", quote(&self.bump_not_in_statuses)));
        }
        jql
    }

    /// The first ticket matching the alert's title; search errors are logged and mean "none", as upstream.
    async fn find_existing_ticket(&self, meta: &Meta, v: &View<'_>, matches: &[Doc]) -> Option<(String, time::Ts)> {
        let jql = self.search_jql(v, matches);
        // Jira Cloud retired `/search`; Data Center / Server only has it (upstream only knows the new endpoint).
        let result = if meta.cloud {
            let q: String = url::form_urlencoded::byte_serialize(jql.as_bytes()).collect();
            self.call(Method::GET, &format!("3/search/jql?jql={q}&fields=updated&maxResults=1"), None).await
        } else {
            self.call(Method::POST, "2/search", Some(&json!({"jql": jql, "fields": ["updated"], "maxResults": 1}))).await
        };
        match result {
            Ok(r) => {
                let issue = r["issues"].as_array()?.first()?;
                let updated = issue["fields"]["updated"].as_str().and_then(time::parse_iso).unwrap_or(0);
                Some((issue["key"].as_str()?.to_string(), updated))
            }
            Err(e) => {
                log::error!("Error while searching for Jira ticket using jql '{jql}': {e:#}");
                None
            }
        }
    }

    async fn comment_on_ticket(&self, key: &str, v: &View<'_>, m: &Doc) -> Result<()> {
        let stamp = lookup(m, &v.rule.timestamp_field).map(py_str).unwrap_or_else(|| "None".into());
        let stamp = time::parse_iso(&stamp).map_or(stamp, |t| time::pretty(t, true, v.ts_fmt));
        let comment = format!("This alert was triggered again at {stamp}\n{}", match_body_in(v.rule, v.rtype, m, v.ts_fmt, true));
        self.call(Method::POST, &format!("2/issue/{key}/comment"), Some(&json!({"body": comment}))).await?;
        Ok(())
    }

    async fn transition_ticket(&self, key: &str, name: &str) -> Result<()> {
        let all = self.call(Method::GET, &format!("2/issue/{key}/transitions"), None).await?;
        for t in all["transitions"].as_array().into_iter().flatten() {
            if t["name"].as_str() == Some(name) {
                self.call(Method::POST, &format!("2/issue/{key}/transitions"), Some(&json!({"transition": {"id": t["id"]}}))).await?;
            }
        }
        Ok(())
    }

    fn set_pipeline(&self, v: &View<'_>, ticket: Value) {
        if let Ok(mut p) = v.pipeline.lock() {
            p.insert("jira_ticket".into(), ticket);
            p.insert("jira_server".into(), json!(self.server));
        }
    }

    // ---- alert ----

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let meta = self.meta().await?;
        let mut args = self.base_args(meta);
        for (key, value) in &self.fixed_fields {
            set_jira_arg(&mut args, key, value, &meta.fields)?;
        }
        for (key, path) in &self.deferred_fields {
            let value = lookup(&matches[0], path).cloned().unwrap_or(Value::Null);
            set_jira_arg(&mut args, key, &value, &meta.fields)?;
        }
        let title = self.title(v, matches);

        if self.bump_tickets
            && let Some((key, updated)) = self.find_existing_ticket(meta, v, matches).await
        {
            let threshold = time::now() - (self.bump_after_inactivity * 86_400e6) as i64;
            if updated >= threshold {
                self.set_pipeline(v, Value::Null);
                return Ok(());
            }
            log::info!("Commenting on existing ticket {key}");
            for m in matches {
                if let Err(e) = self.comment_on_ticket(&key, v, m).await {
                    log::error!("Error while commenting on ticket {key}: {e:#}");
                }
            }
            if let Some(name) = &self.transition {
                log::info!("Transitioning existing ticket {key}");
                if let Err(e) = self.transition_ticket(&key, name).await {
                    log::error!("Error while transitioning ticket {key}: {e:#}");
                }
            }
            self.set_pipeline(v, json!(key));
            return Ok(());
        }
        if self.bump_only {
            return Ok(());
        }

        args.insert("summary".into(), json!(title));
        args.insert("description".into(), json!(self.body(v, matches)));
        let create = async {
            let created = self.call(Method::POST, "2/issue", Some(&json!({"fields": args}))).await?;
            let key = created["key"].as_str().context("Jira answered without an issue key")?.to_string();
            if let Some(a) = &self.assignee {
                let body = if meta.cloud { json!({"accountId": a}) } else { json!({"name": a}) };
                self.call(Method::PUT, &format!("2/issue/{key}/assignee"), Some(&body)).await?;
            }
            anyhow::Ok(key)
        };
        let key = create.await.map_err(|e| anyhow!("Error creating Jira ticket using jira_args ({}): {e:#}", Value::Object(args.clone())))?;
        // Watchers cannot be added at creation, only as a follow-up.
        for w in &self.watchers {
            self.call(Method::POST, &format!("2/issue/{key}/watchers"), Some(&json!(w)))
                .await
                .map_err(|e| anyhow!("Exception encountered when trying to add '{w}' as a watcher. Does the user exist?\n{e:#}"))?;
        }
        log::info!("Opened Jira ticket: {key}");
        self.set_pipeline(v, json!(key));
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "jira"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{Route, rule, serve};
    use crate::types::RuleType;

    fn fields() -> Vec<Value> {
        vec![
            json!({"id": "customfield_1", "name": "My Field", "schema": {"type": "string"}}),
            json!({"id": "customfield_2", "name": "Multi", "schema": {"type": "array", "items": "string", "custom": "com.atlassian.jira.plugin.system.customfieldtypes:multiselect"}}),
            json!({"id": "customfield_3", "name": "Plain Array", "schema": {"type": "array", "items": "string"}}),
            json!({"id": "customfield_4", "name": "Score", "schema": {"type": "number"}}),
            json!({"id": "customfield_5", "name": "Pick", "schema": {"type": "option"}}),
            json!({"id": "customfield_6", "name": "Options", "schema": {"type": "array", "items": "option"}}),
            json!({"id": "customfield_7", "name": "Team", "schema": {"type": "user"}}),
            json!({"id": "customfield_8", "name": "Things", "schema": {"type": "array", "items": "version"}}),
            json!({"id": "issuekey", "name": "Key"}),
        ]
    }

    #[test]
    fn field_schemas() {
        let f = fields();
        let set = |key: &str, v: Value| {
            let mut a = Map::new();
            set_jira_arg(&mut a, key, &v, &f).map(|_| Value::Object(a))
        };
        assert_eq!(set("jira_my_field", json!("x")).unwrap(), json!({"customfield_1": "x"}));
        assert_eq!(set("jira_customfield_1", json!("x")).unwrap(), json!({"customfield_1": "x"}));
        assert_eq!(set("jira_multi", json!("a")).unwrap(), json!({"customfield_2": [{"value": "a"}]}));
        assert_eq!(set("jira_plain_array", json!("a")).unwrap(), json!({"customfield_3": ["a"]}));
        assert_eq!(set("jira_score", json!("4")).unwrap(), json!({"customfield_4": 4}));
        assert_eq!(set("jira_pick", json!("p")).unwrap(), json!({"customfield_5": {"value": "p"}}));
        assert_eq!(set("jira_options", json!(["p", "q"])).unwrap(), json!({"customfield_6": [{"value": "p"}, {"value": "q"}]}));
        assert_eq!(set("jira_team", json!("bob")).unwrap(), json!({"customfield_7": {"name": "bob"}}));
        assert_eq!(set("jira_things", json!(["v1"])).unwrap(), json!({"customfield_8": [{"name": "v1"}]}));
        assert!(set("jira_nope", json!("x")).unwrap_err().to_string().contains("Could not find a definition for the jira field 'nope'"));
        assert!(set("jira_key", json!("x")).unwrap_err().to_string().contains("schema"));
        assert!(set("jira_score", json!("many")).is_err());
    }

    fn account(contents: &str) -> String {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!("ea-jira-account-{}-{}.yaml", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn base_routes(cloud: bool) -> Vec<Route> {
        vec![
            ("GET", "/rest/api/2/serverInfo", 200, json!({"deploymentType": if cloud { "Cloud" } else { "Server" }}).to_string()),
            ("GET", "/rest/api/2/priority", 200, json!([{"id": "1"}, {"id": "2"}, {"id": "3"}]).to_string()),
            ("GET", "/rest/api/2/field", 200, Value::Array(fields()).to_string()),
        ]
    }

    fn m() -> Doc {
        json!({"@timestamp": "2024-01-01T10:00:00Z", "host": "web-1", "owner": "alice"}).as_object().unwrap().clone()
    }

    fn rule_for(url: &str, acct: &str, extra: &str) -> Rule {
        rule("jira", &format!("jira_server: {url}\njira_account_file: {acct}\njira_project: PROJ\njira_issuetype: Bug\nquery_key: host\n{extra}")).unwrap()
    }

    #[tokio::test]
    async fn creates_a_ticket_and_fills_the_pipeline() {
        let mut routes = vec![
            ("PUT", "/rest/api/2/issue/PROJ-1/assignee", 204, String::new()),
            ("POST", "/rest/api/2/issue/PROJ-1/watchers", 204, String::new()),
            ("POST", "/rest/api/2/issue", 201, json!({"id": "10", "key": "PROJ-1"}).to_string()),
        ];
        routes.splice(0..0, base_routes(false));
        let (url, log) = serve(routes).await;
        let acct = account("user: u\npassword: p\n");
        let r = rule_for(
            &url,
            &acct,
            "jira_labels: [elastalert]\njira_components: [Infra]\njira_priority: 1\njira_assignee: bob\njira_watchers: [w1, w2]\njira_description: Intro\njira_my_field: fixed\njira_multi: '#owner'\nalert_subject: 'Subj'\n",
        );
        let rt = RuleType::new(&r).unwrap();
        let pipeline = crate::alerters::Pipeline::default();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &pipeline };
        Jira::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();

        let log = log.lock().unwrap();
        let create = log.iter().find(|c| c.path == "/rest/api/2/issue").unwrap().json();
        let f = &create["fields"];
        assert_eq!(f["project"], json!({"key": "PROJ"}));
        assert_eq!(f["issuetype"], json!({"name": "Bug"}));
        assert_eq!((&f["labels"], &f["components"], &f["priority"]), (&json!(["elastalert"]), &json!([{"name": "Infra"}]), &json!({"id": "2"})));
        assert_eq!((&f["customfield_1"], &f["customfield_2"], &f["summary"]), (&json!("fixed"), &json!([{"value": "alice"}]), &json!("Subj")));
        let desc = f["description"].as_str().unwrap();
        assert!(desc.starts_with("Intro\nr\n\n{code}{\n    \"@timestamp\": \"2024-01-01T10:00:00Z\",\n    \"host\": \"web-1\""), "{desc}");
        assert!(desc.ends_with("{code}"), "{desc}");
        assert_eq!(log.iter().find(|c| c.method == "PUT").unwrap().json(), json!({"name": "bob"}));
        let watchers: Vec<Value> = log.iter().filter(|c| c.path.ends_with("/watchers")).map(|c| c.json()).collect();
        assert_eq!(watchers, vec![json!("w1"), json!("w2")]);
        assert_eq!(log[0].header("authorization"), Some("Basic dTpw"));
        assert_eq!(v.jira_url(), Some(format!("{url}/browse/PROJ-1")));
    }

    #[tokio::test]
    async fn bump_comments_on_a_stale_ticket_and_skips_a_fresh_one() {
        for (updated, expect_comment) in [("2020-01-01T00:00:00.000+0000", true), ("2999-01-01T00:00:00.000+0000", false)] {
            let mut routes = vec![
                ("POST", "/rest/api/2/issue/PROJ-9/comment", 201, "{}".to_string()),
                ("GET", "/rest/api/2/issue/PROJ-9/transitions", 200, json!({"transitions": [{"id": "31", "name": "Reopen"}, {"id": "41", "name": "Other"}]}).to_string()),
                ("POST", "/rest/api/2/issue/PROJ-9/transitions", 204, String::new()),
                ("POST", "/rest/api/2/search", 200, json!({"issues": [{"key": "PROJ-9", "fields": {"updated": updated}}]}).to_string()),
            ];
            routes.splice(0..0, base_routes(false));
            let (url, log) = serve(routes).await;
            let acct = account("apikey: tok123\n");
            let r = rule_for(&url, &acct, "jira_bump_tickets: true\njira_bump_after_inactivity: 1\njira_transition_to: Reopen\njira_bump_not_in_statuses: [Closed, 'In Progress']\njira_max_age: 10\n");
            let rt = RuleType::new(&r).unwrap();
            let pipeline = crate::alerters::Pipeline::default();
            let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &pipeline };
            Jira::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
            let log = log.lock().unwrap();
            assert!(!log.iter().any(|c| c.path == "/rest/api/2/issue"), "no new ticket expected");
            let search = log.iter().find(|c| c.path == "/rest/api/2/search").unwrap();
            assert_eq!(search.header("authorization"), Some("Bearer tok123"));
            let jql = search.json()["jql"].as_str().unwrap().to_string();
            assert!(jql.starts_with("project=PROJ AND summary~\"ElastAlert: web-1 matched r\" and created >= \""), "{jql}");
            assert!(jql.ends_with(" and status not in (Closed,\"In Progress\")"), "{jql}");
            let comments: Vec<Value> = log.iter().filter(|c| c.path.ends_with("/comment")).map(|c| c.json()).collect();
            assert_eq!(comments.len(), usize::from(expect_comment));
            let transitions: Vec<Value> = log.iter().filter(|c| c.method == "POST" && c.path.ends_with("/transitions")).map(|c| c.json()).collect();
            assert_eq!(transitions, if expect_comment { vec![json!({"transition": {"id": "31"}})] } else { vec![] });
            if expect_comment {
                assert!(comments[0]["body"].as_str().unwrap().starts_with("This alert was triggered again at 2024-01-01 "));
                assert_eq!(v.jira_url(), Some(format!("{url}/browse/PROJ-9")));
            } else {
                assert_eq!(v.jira_url(), None);
                assert_eq!(pipeline.lock().unwrap()["jira_ticket"], Value::Null);
            }
        }
    }

    #[tokio::test]
    async fn cloud_uses_the_new_search_and_account_id() {
        let mut routes = vec![
            ("GET", "/rest/api/3/search/jql", 200, json!({"issues": []}).to_string()),
            ("PUT", "/rest/api/2/issue/PROJ-2/assignee", 204, String::new()),
            ("POST", "/rest/api/2/issue", 201, json!({"key": "PROJ-2"}).to_string()),
        ];
        routes.splice(0..0, base_routes(true));
        let (url, log) = serve(routes).await;
        let acct = account("user: u\npassword: p\n");
        let r = rule_for(&url, &acct, "jira_bump_tickets: true\njira_assignee: acc-1\n");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Jira::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let log = log.lock().unwrap();
        assert!(log.iter().any(|c| c.method == "GET" && c.path.starts_with("/rest/api/3/search/jql?jql=project%3DPROJ")));
        assert_eq!(log.iter().find(|c| c.method == "PUT").unwrap().json(), json!({"accountId": "acc-1"}));
    }

    #[tokio::test]
    async fn bump_only_never_creates_and_errors_name_the_cause() {
        let mut routes = vec![("POST", "/rest/api/2/search", 200, json!({"issues": []}).to_string())];
        routes.splice(0..0, base_routes(false));
        let (url, log) = serve(routes).await;
        let acct = account("user: u\npassword: p\n");
        let r = rule_for(&url, &acct, "jira_bump_tickets: true\njira_bump_only: true\n");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Jira::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        assert!(!log.lock().unwrap().iter().any(|c| c.path == "/rest/api/2/issue"));

        // a Jira that refuses the ticket
        let mut routes = vec![("POST", "/rest/api/2/issue", 400, json!({"errors": {"summary": "bad"}}).to_string())];
        routes.splice(0..0, base_routes(false));
        let (url, _) = serve(routes).await;
        let r = rule_for(&url, &acct, "");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let err = Jira::new(&r).unwrap().alert(&v, &[m()]).await.unwrap_err().to_string();
        assert!(err.starts_with("Error creating Jira ticket using jira_args (") && err.contains("HTTP 400"), "{err}");
    }

    #[test]
    fn titles() {
        let acct = account("user: u\npassword: p\n");
        let r = rule_for("http://j", &acct, "");
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        let j = Jira::new(&r).unwrap();
        let mut spike = m();
        spike.insert("spike_count".into(), json!(12));
        assert_eq!(j.default_title(&v, &spike, true), "ElastAlert: web-1 matched r");
        let full = j.default_title(&v, &spike, false);
        assert!(full.starts_with("ElastAlert: web-1 matched r - 2024-01-01 ") && full.ends_with(" - 12+ events"), "{full}");
        let no_qk = json!({"x": 1}).as_object().unwrap().clone();
        assert_eq!(j.default_title(&v, &no_qk, false), "ElastAlert: r");
    }

    #[test]
    fn account_file_rules() {
        let bad = account("user: only\n");
        let r = rule("jira", &format!("jira_server: http://j\njira_account_file: {bad}\njira_project: P\njira_issuetype: T\n")).unwrap();
        assert!(Jira::new(&r).err().unwrap().to_string().contains("user and password fields, or apikey"));
        assert!(Jira::new(&rule("jira", "jira_server: http://j\n").unwrap()).is_err());
    }
}
