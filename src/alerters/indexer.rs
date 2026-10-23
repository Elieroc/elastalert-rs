//! `indexer` alerter: indexes a document built from the first match into Elasticsearch / OpenSearch.

use super::{Doc, View, lookup_field, required};
use crate::es::Es;
use crate::field::{py_str, truthy};
use crate::rule::Rule;
use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};
use tokio::sync::OnceCell;

pub struct Indexer {
    config: Map<String, Value>,
    connection: Option<Map<String, Value>>,
    config_file: Option<String>,
    es: OnceCell<(Es, String)>,
}

/// Dict values are replaced by their flattened `a.b.c` entries; everything else stays.
fn flatten(data: &Map<String, Value>, prefix: &str, out: &mut Map<String, Value>) {
    for (k, v) in data {
        match v {
            Value::Object(o) => flatten(o, &format!("{prefix}{k}."), out),
            other => {
                out.insert(format!("{prefix}{k}"), other.clone());
            }
        }
    }
}

fn nest(flat: Map<String, Value>) -> Map<String, Value> {
    let mut root = Map::new();
    for (key, value) in flat {
        let parts: Vec<&str> = key.split('.').collect();
        let mut cur = &mut root;
        for part in &parts[..parts.len() - 1] {
            let entry = cur.entry(part.to_string()).or_insert_with(|| json!({}));
            if !entry.is_object() {
                *entry = json!({});
            }
            cur = entry.as_object_mut().unwrap();
        }
        cur.insert(parts[parts.len() - 1].to_string(), value);
    }
    root
}

impl Indexer {
    pub(super) fn new(rule: &Rule) -> Result<Indexer> {
        required(rule, "indexer", "indexer_alert_config")?;
        Ok(Indexer {
            config: rule.raw.get("indexer_alert_config").and_then(Value::as_object).cloned().unwrap_or_default(),
            connection: rule.raw.get("indexer_connection").and_then(Value::as_object).filter(|c| !c.is_empty()).cloned(),
            config_file: rule.raw.get("indexer_config").and_then(Value::as_str).map(String::from),
            es: OnceCell::new(),
        })
    }

    /// The `filter` of the rule is `[{query: {query_string: {query: ...}}}]`: the innermost `query` is the value.
    fn filter_query(rule: &Rule) -> Result<Value> {
        let filter = rule.raw.get("filter").and_then(Value::as_array).and_then(|f| f.first()).and_then(Value::as_object).context("indexer: the rule has no filter to take a query from")?;
        let mut query = None;
        for orig in filter.values().filter_map(Value::as_object) {
            for q in orig.values() {
                query = Some(q);
            }
        }
        query.and_then(|q| q.get("query")).cloned().context("indexer: the filter has no query")
    }

    fn list_fields(&self, rule: &Rule, fields: &[Value], m: &Doc) -> Result<Map<String, Value>> {
        let mut out = Map::new();
        for field in fields {
            let Some(field) = field.as_object() else { bail!("indexer_alert_config: list entries must be maps") };
            if truthy(field.get("value")) {
                let raw = &field["value"];
                let value = match raw {
                    Value::String(s) if s == "filter" => Self::filter_query(rule)?,
                    Value::String(s) => lookup_field(rule, m, s, raw.clone()),
                    other => other.clone(),
                };
                let Some(name) = field.get("name").and_then(Value::as_str) else { bail!("KeyError: 'name' in indexer_alert_config") };
                out.insert(name.to_string(), value);
            } else {
                for (k, v) in field {
                    let Some(list) = v.as_array() else { bail!("indexer_alert_config: {k} must be a list of fields") };
                    out.insert(k.clone(), Value::Object(self.list_fields(rule, list, m)?));
                }
            }
        }
        Ok(out)
    }

    fn orig_fields(&self, rule: &Rule, raw: &Value, m: &Doc) -> Result<Value> {
        Ok(match raw {
            Value::String(s) => lookup_field(rule, m, s, raw.clone()),
            Value::Array(a) => Value::Object(self.list_fields(rule, a, m)?),
            other => other.clone(),
        })
    }

    /// The document to index; `now` is the local time upstream stamps as `@timestamp`.
    fn document(&self, rule: &Rule, m: &Doc, now: &str) -> Result<Value> {
        let mut config = Map::new();
        config.insert("@timestamp".into(), json!(now));
        config.extend(self.config.clone());
        let mut flat = Map::new();
        flatten(&config, "", &mut flat);
        for value in flat.values_mut() {
            *value = self.orig_fields(rule, value, m)?;
        }
        let mut again = Map::new();
        flatten(&flat, "", &mut again);
        // A field mapped to itself was not found in the match: drop it.
        again.retain(|k, v| v.as_str() != Some(k.as_str()));
        Ok(Value::Object(nest(again)))
    }

    async fn client(&self) -> Result<&(Es, String)> {
        self.es
            .get_or_try_init(|| async {
                let conf = match (&self.connection, &self.config_file) {
                    (Some(c), _) => c.clone(),
                    (None, Some(f)) if std::path::Path::new(f).is_file() => crate::config::read_yaml(std::path::Path::new(f))?.as_object().cloned().unwrap_or_default(),
                    _ => bail!("indexer needs indexer_connection or an existing indexer_config file"),
                };
                let Some(index) = conf.get("indexer_alerts_name").map(py_str) else { bail!("indexer_alerts_name is missing from the indexer connection") };
                Ok((Es::from_conf(&conf)?, index))
            })
            .await
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        let now = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        let doc = self.document(v.rule, &matches[0], &now)?;
        let (es, index) = self.client().await?;
        es.post(&format!("/{index}/_doc?refresh=true"), &doc).await.map_err(|e| anyhow!("Error posting to SIEM: {e:#}"))?;
        log::info!("Alert sent to SIEM");
        Ok(())
    }

    pub(super) fn info(&self) -> Value {
        json!({"type": "indexer"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerters::testutil::{capture_with, rule};
    use crate::types::RuleType;

    const CFG: &str = "indexer_alert_config:\n  event.kind: signal\n  rule:\n    name: name\n  source.ip: src.ip\n  host.name: host.name\n  tags:\n  - {name: first, value: user}\n  - {name: lit, value: 5}\n  - group:\n    - {name: inner, value: src.ip}\nfilter:\n- query:\n    query_string:\n      query: 'user:bob'\n";

    fn m() -> Doc {
        json!({"user": "bob", "src": {"ip": "10.0.0.1"}}).as_object().unwrap().clone()
    }

    #[test]
    fn document_resolves_and_nests() {
        let r = rule("indexer", CFG).unwrap();
        let doc = Indexer::new(&r).unwrap().document(&r, &m(), "NOW").unwrap();
        assert_eq!(
            doc,
            json!({
                "@timestamp": "NOW",
                "event": {"kind": "signal"},
                "rule": {"name": "r"},
                "source": {"ip": "10.0.0.1"},
                "tags": {"first": "bob", "lit": 5, "group": {"inner": "10.0.0.1"}},
            })
        );
    }

    #[test]
    fn strings_fall_back_to_rule_options() {
        // like upstream's `lookup_field`: "name" is the rule's name, and a bare "filter" is the whole filter list
        let r = rule("indexer", "indexer_alert_config: {n: name, f: filter}\nfilter:\n- term: {a: 1}\n").unwrap();
        let doc = Indexer::new(&r).unwrap().document(&r, &m(), "NOW").unwrap();
        assert_eq!((&doc["n"], &doc["f"]), (&json!("r"), &json!([{"term": {"a": 1}}])));
    }

    #[test]
    fn filter_keyword_in_a_list_takes_the_query() {
        let r = rule("indexer", "indexer_alert_config:\n  q:\n  - {name: query, value: filter}\nfilter:\n- query:\n    query_string:\n      query: 'user:bob'\n").unwrap();
        let doc = Indexer::new(&r).unwrap().document(&r, &m(), "NOW").unwrap();
        assert_eq!(doc["q"], json!({"query": "user:bob"}));
    }

    #[tokio::test]
    async fn indexes_into_the_configured_cluster() {
        let (url, got) = capture_with(1, 201, r#"{"result":"created"}"#).await;
        let port = url.rsplit_once(':').unwrap().1;
        let r = rule("indexer", &format!("indexer_connection: {{es_host: 127.0.0.1, es_port: {port}, indexer_alerts_name: siem-alerts}}\nindexer_alert_config: {{who: user}}\n")).unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        Indexer::new(&r).unwrap().alert(&v, &[m()]).await.unwrap();
        let got = got.await.unwrap();
        assert_eq!((got[0].method.as_str(), got[0].path.as_str()), ("POST", "/siem-alerts/_doc?refresh=true"));
        assert_eq!(got[0].json()["who"], json!("bob"));
        assert!(got[0].json()["@timestamp"].as_str().unwrap().ends_with('Z'));
    }

    #[tokio::test]
    async fn needs_a_connection() {
        let r = rule("indexer", "indexer_alert_config: {a: b}\n").unwrap();
        let rt = RuleType::new(&r).unwrap();
        let v = View { rule: &r, rtype: &rt, ts_fmt: None, pipeline: &Default::default() };
        assert!(Indexer::new(&r).unwrap().alert(&v, &[m()]).await.is_err());
    }
}
