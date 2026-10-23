//! EQL and ES|QL rules: a `filter` entry `{eql: "..."}` or `{esql: "..."}` replaces the Query DSL search.
//! Same request / response conversion as upstream's `eql.py` and `esql.py`.

use crate::field::py_str;
use anyhow::{Result, bail};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QueryLang {
    Eql,
    Esql,
}

impl QueryLang {
    pub fn key(self) -> &'static str {
        match self {
            QueryLang::Eql => "eql",
            QueryLang::Esql => "esql",
        }
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null | Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(m)) => !m.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

/// Which language the rule's filters use. Mixing both is an error (upstream would send the ES|QL entry as Query DSL).
pub fn detect(filter: &[Value]) -> Result<Option<QueryLang>> {
    let has = |k: &str| filter.iter().any(|f| truthy(f.get(k)));
    match (has("eql"), has("esql")) {
        (true, true) => bail!("a rule cannot use both an eql and an esql filter"),
        (true, false) => Ok(Some(QueryLang::Eql)),
        (false, true) => Ok(Some(QueryLang::Esql)),
        (false, false) => Ok(None),
    }
}

/// `esql.apply_limit`: every ES|QL entry gets `| limit <max_query_size>` appended.
pub fn apply_limit(filter: &mut [Value], size: u64) {
    for f in filter {
        if let Some(Value::String(q)) = f.get_mut("esql") {
            *q = format!("{}\n| limit {size}", q.trim_end());
        }
    }
}

/// Splits the `bool.filter.bool.must` list of a search body into the language query (the last entry wins)
/// and the other filters. `None` when the body has no such entry.
pub fn split(query: &Value, lang: QueryLang) -> Option<(Value, Vec<Value>)> {
    let must = query.pointer("/bool/filter/bool/must")?.as_array()?;
    let mut found = None;
    let mut others = Vec::new();
    for f in must {
        match f.get(lang.key()).filter(|v| truthy(Some(v))) {
            Some(q) => found = Some(q.clone()),
            None => others.push(f.clone()),
        }
    }
    found.map(|q| (q, others))
}

/// Body for `POST <index>/_eql/search` / `POST _query` built from the rule's Query DSL body.
/// `timestamp_field` is passed to EQL when it is not the default `@timestamp` (upstream relies on the default).
pub fn request(query: &Value, lang: QueryLang, size: u64, timestamp_field: &str) -> Option<Value> {
    let (q, others) = split(query, lang)?;
    let mut body = json!({"filter": {"bool": {"must": others}}, "query": q});
    if lang == QueryLang::Eql {
        body["size"] = json!(size);
        if timestamp_field != "@timestamp" {
            body["timestamp_field"] = json!(timestamp_field);
        }
    }
    Some(body)
}

/// EQL: `hits.events` become `hits.hits`. Sequence and join queries (`hits.sequences`) are an error.
pub fn eql_hits(resp: &mut Value) -> Result<Vec<Value>> {
    if resp.pointer("/hits/sequences").is_some() {
        bail!("EQL sequence and join queries are not supported: only event queries are");
    }
    Ok(match resp.pointer_mut("/hits/events").map(Value::take) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    })
}

/// One ES|QL row as a document: `_source` verbatim when it is a column, otherwise the flat columns nested by their dots
/// (nulls and multi-fields dropped).
fn format_source(cols: &[String], row: &[Value]) -> Map<String, Value> {
    if let Some(i) = cols.iter().position(|c| c == "_source") {
        let doc = match &row[i] {
            Value::String(s) => serde_json::from_str::<Value>(s).ok(),
            v => Some(v.clone()),
        };
        if let Some(Value::Object(mut doc)) = doc {
            for name in ["_id", "_index"] {
                if let Some(j) = cols.iter().position(|c| c == name)
                    && !row[j].is_null()
                {
                    doc.entry(name).or_insert_with(|| row[j].clone());
                }
            }
            return doc;
        }
    }
    let mut pairs: Vec<(&String, &Value)> = cols.iter().zip(row).collect();
    pairs.sort_by_key(|(name, _)| name.matches('.').count());
    let mut source = Map::new();
    for (name, value) in pairs {
        if value.is_null() {
            continue;
        }
        let keys: Vec<&str> = name.split('.').collect();
        // A multi-field: some ancestor path is itself a column.
        if (1..keys.len()).any(|i| cols.contains(&keys[..i].join("."))) {
            continue;
        }
        let mut node = &mut source;
        for key in &keys[..keys.len() - 1] {
            let slot = node.entry(*key).or_insert_with(|| json!({}));
            if !slot.is_object() {
                *slot = json!({});
            }
            node = slot.as_object_mut().expect("made an object above");
        }
        node.insert(keys[keys.len() - 1].to_string(), value.clone());
    }
    source
}

/// `json.dumps(v, sort_keys=True, default=str)` (ASCII output, `", "` / `": "` separators).
fn py_dumps(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(_) => out.push_str(&py_str(v)),
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{8}' => out.push_str("\\b"),
                    '\u{c}' => out.push_str("\\f"),
                    ' '..='~' => out.push(c),
                    _ => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            out.push_str(&format!("\\u{unit:04x}"));
                        }
                    }
                }
            }
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_dumps(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                py_dumps(&Value::String(k.clone()), out);
                out.push_str(": ");
                py_dumps(x, out);
            }
            out.push('}');
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// ES|QL response (`columns` + `values`) as search hits; rows without an `_id` get the SHA-256 of their document.
pub fn esql_hits(resp: &Value, default_index: &str) -> Vec<Value> {
    let (Some(columns), Some(values)) = (resp["columns"].as_array(), resp["values"].as_array()) else { return Vec::new() };
    let cols: Vec<String> = columns.iter().map(|c| c["name"].as_str().unwrap_or_default().to_string()).collect();
    values
        .iter()
        .filter_map(Value::as_array)
        .map(|row| {
            let doc = format_source(&cols, row);
            let id = match doc.get("_id") {
                Some(v) if truthy(Some(v)) => v.clone(),
                _ => {
                    let mut text = String::new();
                    py_dumps(&Value::Object(doc.clone()), &mut text);
                    json!(hex(&Sha256::digest(text.as_bytes())))
                }
            };
            let index = doc.get("_index").cloned().unwrap_or_else(|| json!(default_index));
            json!({"_index": index, "_id": id, "_source": doc})
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(key: &str) -> Value {
        json!({"bool": {"filter": {"bool": {"must": [{key: "test query"}, {"other": "other filter"}]}}}})
    }

    #[test]
    fn split_like_upstream() {
        for bad in [json!({}), json!({"bool": {}}), json!({"bool": {"filter": {"bool": {"must": []}}}}), json!({"bool": {"filter": {"bool": {"must": [{"foo": "bar"}]}}}})] {
            assert!(split(&bad, QueryLang::Eql).is_none());
            assert!(request(&bad, QueryLang::Esql, 10, "@timestamp").is_none());
        }
        assert_eq!(request(&body("eql"), QueryLang::Eql, 5, "@timestamp").unwrap(), json!({"filter": {"bool": {"must": [{"other": "other filter"}]}}, "query": "test query", "size": 5}));
        assert_eq!(request(&body("esql"), QueryLang::Esql, 5, "@timestamp").unwrap(), json!({"filter": {"bool": {"must": [{"other": "other filter"}]}}, "query": "test query"}));
        let mut twice = body("eql");
        twice["bool"]["filter"]["bool"]["must"].as_array_mut().unwrap().push(json!({"eql": "newer query"}));
        assert_eq!(split(&twice, QueryLang::Eql).unwrap().0, json!("newer query"));
        assert_eq!(request(&body("eql"), QueryLang::Eql, 5, "ts").unwrap()["timestamp_field"], json!("ts"));
    }

    #[test]
    fn detect_and_limit() {
        assert_eq!(detect(&[json!({"term": {"a": 1}})]).unwrap(), None);
        assert_eq!(detect(&[json!({"eql": "x"})]).unwrap(), Some(QueryLang::Eql));
        assert_eq!(detect(&[json!({"esql": "x"})]).unwrap(), Some(QueryLang::Esql));
        assert!(detect(&[json!({"esql": "x"}), json!({"eql": "y"})]).is_err());
        let mut f = vec![json!({"esql": "FROM logs-*\n| WHERE a > 1  \n"}), json!({"term": {"a": 1}})];
        apply_limit(&mut f, 100);
        assert_eq!(f[0]["esql"], json!("FROM logs-*\n| WHERE a > 1\n| limit 100"));
        assert_eq!(f[1], json!({"term": {"a": 1}}));
    }

    #[test]
    fn eql_events_become_hits() {
        let mut r = json!({"hits": {"events": [{"foo": "bar"}]}});
        assert_eq!(eql_hits(&mut r).unwrap(), vec![json!({"foo": "bar"})]);
        assert!(eql_hits(&mut json!({"hits": {"hits": []}})).unwrap().is_empty());
        assert!(eql_hits(&mut json!({"hits": {"sequences": []}})).is_err());
    }

    #[test]
    fn esql_rows_become_documents() {
        let resp = json!({"columns": [{"name": "@timestamp"}, {"name": "host.name"}, {"name": "host"}, {"name": "user.id"}, {"name": "gone"}],
                          "values": [["2026-01-01T00:00:00Z", "a", "ignored", 7, null]]});
        let hits = esql_hits(&resp, "logs-*");
        assert_eq!(hits.len(), 1);
        // `host` is a column, so `host.name` is a multi-field and is skipped.
        assert_eq!(hits[0]["_source"], json!({"@timestamp": "2026-01-01T00:00:00Z", "host": "ignored", "user": {"id": 7}}));
        assert_eq!(hits[0]["_index"], json!("logs-*"));

        let with_source = json!({"columns": [{"name": "_id"}, {"name": "_index"}, {"name": "_source"}],
                                 "values": [["abc", "idx-1", "{\"a\": 1}"], ["def", null, {"b": 2}]]});
        let hits = esql_hits(&with_source, "logs-*");
        assert_eq!(hits[0], json!({"_index": "idx-1", "_id": "abc", "_source": {"a": 1, "_id": "abc", "_index": "idx-1"}}));
        assert_eq!(hits[1]["_index"], json!("logs-*"));
        assert!(esql_hits(&json!({}), "x").is_empty());
    }

    #[test]
    fn esql_id_is_python_compatible_hash() {
        // hashlib.sha256(json.dumps({"a": 1, "b": "é"}, sort_keys=True, default=str).encode()).hexdigest()
        let resp = json!({"columns": [{"name": "a"}, {"name": "b"}], "values": [[1, "é"]]});
        let hits = esql_hits(&resp, "x");
        assert_eq!(hits[0]["_id"], json!("fb0782fb7a8a00c6a46d1f2aadc5c94b9df08eba809089335da3acdf393c7c13"));
    }
}
