//! One rule run: pick the time range, query ES page by page, feed the rule type,
//! then silence/realert and alert on each match. Same semantics as ElastAlert's `run_rule`.

use crate::alert;
use crate::alerters::{Alerter, View};
use crate::es::Es;
use crate::field::{self, py_str};
use crate::index;
use crate::metrics::Metrics;
use crate::rule::{Aggregation, Rule, TsType};
use crate::time::{Dur, MINUTE, SECOND, Ts, now, parse_iso, pretty, to_iso};
use crate::types::{Event, RuleType, parse_ts, ts_value};
use crate::writeback::{Kind as Wb, Writeback};
use anyhow::{Context, Result, bail};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use serde_json::{Map, Value, json};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

type Doc = Map<String, Value>;

/// Realert/silence state shared by all rules (several rules may share a `realert_key`).
#[derive(Default)]
pub struct Silences(Mutex<FxHashMap<String, (Ts, i32)>>);

impl Silences {
    pub fn is_silenced(&self, key: &str) -> bool {
        self.0.lock().unwrap().get(key).is_some_and(|(until, _)| now() < *until)
    }

    pub fn get(&self, key: &str) -> Option<(Ts, i32)> {
        self.0.lock().unwrap().get(key).copied()
    }

    /// Merge a silence read from ES: never shortens one we already know.
    pub fn raise(&self, key: &str, until: Ts, exponent: i32) {
        let mut m = self.0.lock().unwrap();
        if m.get(key).is_none_or(|(u, _)| *u < until) {
            m.insert(key.to_string(), (until, exponent));
        }
    }

    pub fn set(&self, key: &str, until: Ts, exponent: i32) {
        self.0.lock().unwrap().insert(key.to_string(), (until, exponent));
    }
}

/// Everything a rule task needs besides its own state.
pub struct Ctx {
    pub es: Es,
    pub writeback: Writeback,
    pub silences: Arc<Silences>,
    pub metrics: Arc<Metrics>,
    pub debug: bool,
    /// Rules disabled after a panic (`disable_rules_on_error`); shown in the log, cleared on reload.
    pub disabled: Arc<Mutex<Vec<String>>>,
    pub disable_rules_on_error: bool,
    pub use_pit: bool,
    /// Global `run_every`: count and terms queries read this much per query.
    pub run_every: Dur,
    pub old_query_limit: Dur,
    pub alert_time_limit: Dur,
    pub scroll_keepalive: String,
    pub ts_fmt: Option<String>,
}

/// An alert that has not reached every alerter yet. Kept in memory and mirrored in ES (`alert_sent: false`).
pub struct Pending {
    pub id: String,
    pub matches: Vec<Doc>,
    pub done: Vec<bool>,
    pub attempts: u32,
    pub next_try: Ts,
    pub alert_time: Ts,
    pub exception: String,
    /// Ids of the docs of an aggregated alert's other matches (deleted once the alert is fully sent).
    pub child_ids: Vec<String>,
}

/// Matches waiting for their aggregation time, one group per `aggregation_key` value.
struct AggGroup {
    alert_time: Ts,
    head_id: String,
    matches: Vec<Doc>,
    child_ids: Vec<String>,
}

pub struct RuleState {
    pub rule: Rule,
    rtype: RuleType,
    alerters: Vec<Alerter>,
    pub pending: Vec<Pending>,
    agg: FxHashMap<String, AggGroup>,
    starttime: Option<Ts>,
    previous_endtime: Option<Ts>,
    minimum_starttime: Option<Ts>,
    /// Hash of `_id` -> event time, to skip hits already seen in overlapping windows.
    seen: FxHashMap<u64, Ts>,
    /// Documents to query instead of ES (`test-rule --data`).
    pub mock: Option<Vec<Doc>>,
    /// Counters for the current run.
    hits: u64,
    dupes: u64,
    alerts_sent: AtomicU64,
    alerts_not_sent: AtomicU64,
}

fn id_hash(id: &str) -> u64 {
    let mut h = FxHasher::default();
    id.hash(&mut h);
    h.finish()
}

/// Retry delay: 30 s doubling per attempt, at most one hour.
fn backoff(attempts: u32) -> Dur {
    (30 * SECOND << attempts.min(7)).min(60 * MINUTE)
}

impl RuleState {
    pub fn new(rule: Rule) -> Result<Self> {
        let alerters = rule.alerts.iter().map(|k| Alerter::from_rule(k, &rule)).collect::<Result<Vec<_>>>()?;
        Ok(RuleState {
            rtype: RuleType::new(&rule)?,
            alerters,
            pending: Vec::new(),
            agg: FxHashMap::default(),
            rule,
            starttime: None,
            previous_endtime: None,
            minimum_starttime: None,
            seen: FxHashMap::default(),
            mock: None,
            hits: 0,
            dupes: 0,
            alerts_sent: AtomicU64::new(0),
            alerts_not_sent: AtomicU64::new(0),
        })
    }

    /// Only for building queries (`test-rule`): no alerters are created.
    pub fn new_for_query(rule: &Rule) -> Self {
        RuleState {
            rtype: RuleType::new(rule).unwrap_or(RuleType::Any),
            alerters: vec![],
            pending: vec![],
            agg: FxHashMap::default(),
            rule: rule.clone(),
            starttime: None,
            previous_endtime: None,
            minimum_starttime: None,
            seen: FxHashMap::default(),
            mock: None,
            hits: 0,
            dupes: 0,
            alerts_sent: AtomicU64::new(0),
            alerts_not_sent: AtomicU64::new(0),
        }
    }

    /// After a reload: keep the query position, dedup set, unsent alerts and open aggregation groups.
    pub fn carry_over(&mut self, old: RuleState) {
        (self.starttime, self.previous_endtime, self.minimum_starttime, self.seen, self.pending, self.agg) =
            (old.starttime, old.previous_endtime, old.minimum_starttime, old.seen, old.pending, old.agg);
        let n = self.alerters.len();
        self.pending.iter_mut().for_each(|p| p.done.resize(n, false));
        if self.rule.aggregation.is_none() {
            // Aggregation was switched off: whatever is waiting goes out as soon as possible.
            for g in self.agg.values_mut() {
                g.alert_time = 0;
            }
        }
    }

    fn counting(&self) -> bool {
        self.rule.use_count_query || self.rule.use_terms_query
    }

    // ---- queries ----

    fn range_field(&self) -> &str {
        self.rule.ingest_field.as_deref().unwrap_or(&self.rule.timestamp_field)
    }

    fn range_value(&self, ts: Ts) -> Value {
        if let (Some(tz), true) = (&self.rule.query_timezone, self.rule.timestamp_type == TsType::Iso || self.rule.ingest_field.is_some()) {
            return json!(crate::time::to_iso_in(ts, tz));
        }
        if self.rule.ingest_field.is_some() { json!(to_iso(ts)) } else { ts_value(&self.rule, ts) }
    }

    pub fn filters(&self, start: Ts, end: Ts, extra: Vec<Value>) -> Value {
        let mut must = vec![json!({"range": {self.range_field(): {"gt": self.range_value(start), "lte": self.range_value(end)}}})];
        // Old-style `- query: {...}` filter entries are unwrapped.
        must.extend(self.rule.filter.iter().map(|f| f.get("query").cloned().unwrap_or_else(|| f.clone())));
        must.extend(self.rtype.extra_filter(&self.rule));
        must.extend(extra);
        json!({"bool": {"filter": {"bool": {"must": must}}}})
    }

    /// Range filter + user filters + timestamp sort, the query every hit search uses.
    pub fn query(&self, start: Ts, end: Ts) -> Value {
        let mut q = json!({
            "query": self.filters(start, end, vec![]),
            "sort": [{&self.rule.timestamp_field: {"order": "asc"}}],
            "_source": {"includes": self.rule.include},
        });
        if let Some(f) = &self.rule.include_fields {
            q["fields"] = json!(f);
        }
        q
    }

    pub fn index_for(&self, start: Ts, end: Ts) -> Result<String> {
        if self.rule.use_strftime_index { index::format_index(&self.rule.index, start, end, self.rule.search_extra_index) } else { Ok(self.rule.index.clone()) }
    }

    /// Turns raw hits into events: merges `fields`, parses the timestamp, copies metadata,
    /// builds compound query keys.
    fn process_hits(&self, hits: &mut [Value]) -> Result<Vec<Event>> {
        let mut out = Vec::with_capacity(hits.len());
        for hit in hits.iter_mut() {
            let mut doc = match hit.get_mut("_source").map(Value::take) {
                Some(Value::Object(m)) => m,
                _ => Map::new(),
            };
            if let Some(fields) = hit.get("fields").and_then(Value::as_object) {
                for (k, v) in fields {
                    let v = match v {
                        Value::Array(a) if a.len() == 1 => a[0].clone(),
                        other => other.clone(),
                    };
                    doc.entry(k.clone()).or_insert(v);
                }
            }
            let ts_raw = field::lookup(&doc, &self.rule.timestamp_field).with_context(|| {
                format!(
                    "the configured timestamp_field '{}' was not found in the query results. Available fields: {:?}",
                    self.rule.timestamp_field,
                    doc.keys().collect::<Vec<_>>()
                )
            })?;
            let ts = parse_ts(&self.rule, ts_raw).with_context(|| format!("cannot parse timestamp {ts_raw}"))?;
            for meta in ["_id", "_index", "_type"] {
                if let Some(v) = hit.get(meta) {
                    doc.insert(meta.into(), v.clone());
                }
            }
            for (key, parts) in [(&self.rule.query_key, &self.rule.compound_query_key), (&self.rule.aggregation_key, &self.rule.compound_aggregation_key)] {
                if let (Some(key), false) = (key, parts.is_empty()) {
                    let joined: Vec<String> = parts.iter().map(|k| field::lookup(&doc, k).map_or_else(|| "None".into(), py_str)).collect();
                    doc.insert(key.clone(), json!(joined.join(", ")));
                }
            }
            out.push(Event { ts, doc });
        }
        Ok(out)
    }

    /// Dedups a page of hits, feeds the fresh ones to the rule type.
    fn on_hits(&mut self, ctx: &Ctx, start: Ts, end: Ts, mut hits: Vec<Value>, scrolling: bool, matches: &mut Vec<Doc>) -> Result<()> {
        self.hits += hits.len() as u64;
        let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
        log::info!(
            "Queried rule {} from {} to {}: {} / {} hits{}",
            self.rule.name,
            pretty(start, lt, fmt),
            pretty(end, lt, fmt),
            self.hits,
            hits.len(),
            if scrolling { " (scrolling..)" } else { "" }
        );
        let events = self.process_hits(&mut hits)?;
        let before = events.len();
        let fresh: Vec<Event> = events
            .into_iter()
            .filter(|e| match e.doc.get("_id").and_then(Value::as_str) {
                Some(id) => self.seen.insert(id_hash(id), e.ts).is_none(),
                None => true,
            })
            .collect();
        self.dupes += (before - fresh.len()) as u64;
        if !fresh.is_empty() {
            self.rtype.add_data(&self.rule, fresh, matches);
        }
        Ok(())
    }

    /// Queries [start, end] and feeds the result to the rule type (hits, count or terms).
    async fn run_query(&mut self, ctx: &Ctx, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        if self.mock.is_some() {
            return self.run_mock(ctx, start, end, matches);
        }
        let index = self.index_for(start, end)?;
        if self.rule.use_count_query {
            let body = json!({"query": self.filters(start, end, vec![])});
            let count = ctx.es.count(&index, &body).await.map_err(|e| anyhow::anyhow!("Error running count query: {e:#}"))?;
            self.hits += count;
            let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
            log::info!("Queried rule {} from {} to {}: {} hits", self.rule.name, pretty(start, lt, fmt), pretty(end, lt, fmt), count);
            self.rtype.add_count(&self.rule, end, count as i64, matches);
            return Ok(());
        }
        if self.rule.use_terms_query {
            let buckets = self.terms(ctx, &index, start, end, self.rule.query_key.clone().unwrap_or_default(), self.rule.terms_size, vec![]).await?;
            self.hits += buckets.len() as u64;
            let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
            log::info!("Queried rule {} from {} to {}: {} buckets", self.rule.name, pretty(start, lt, fmt), pretty(end, lt, fmt), buckets.len());
            self.rtype.add_terms(&self.rule, end, &buckets, matches);
            return Ok(());
        }
        let body = self.query(start, end);
        if ctx.use_pit && ctx.es.supports_pit().await {
            match ctx.es.pit_open(&index, "1m").await {
                Ok(id) => return self.pit_pages(ctx, start, end, body, id, matches).await,
                Err(e) => log::warn!("rule {}: point in time unavailable ({e:#}), using scroll", self.rule.name),
            }
        }
        self.scroll_pages(ctx, start, end, &index, body, matches).await
    }

    /// Terms aggregation `field` -> (key, doc_count), most frequent first.
    #[allow(clippy::too_many_arguments)]
    async fn terms(&self, ctx: &Ctx, index: &str, start: Ts, end: Ts, field: String, size: u64, extra: Vec<Value>) -> Result<Vec<(Value, i64)>> {
        let min = self.rule.raw.get("min_doc_count").and_then(Value::as_u64).unwrap_or(1);
        let body = json!({
            "query": self.filters(start, end, extra), "size": 0,
            "aggs": {"counts": {"terms": {"field": field, "size": size, "min_doc_count": min}}},
        });
        let resp = ctx.es.search(index, &body).await.map_err(|e| anyhow::anyhow!("Error running terms query: {e:#}"))?;
        Ok(resp["aggregations"]["counts"]["buckets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|b| (b["key"].clone(), b["doc_count"].as_i64().unwrap_or(0)))
            .collect())
    }

    /// Mock data (`test-rule --data`): same time filter as upstream's mock (`start <= ts < end`).
    fn run_mock(&mut self, ctx: &Ctx, start: Ts, end: Ts, matches: &mut Vec<Doc>) -> Result<()> {
        let docs = self.mock.as_ref().expect("checked by caller");
        if self.rule.use_count_query {
            let n = docs.iter().filter(|d| self.in_range(d, start, end)).count();
            self.hits += n as u64;
            self.rtype.add_count(&self.rule, end, n as i64, matches);
            return Ok(());
        }
        if self.rule.use_terms_query {
            let qk = self.rule.query_key.clone().unwrap_or_default();
            let key = qk.strip_suffix(".keyword").or(qk.strip_suffix(".raw")).unwrap_or(&qk).to_string();
            let mut buckets: Vec<(Value, i64)> = Vec::new();
            for d in docs.iter().filter(|d| self.in_range(d, start, end)) {
                let Some(v) = field::lookup(d, &key).cloned() else { continue };
                match buckets.iter_mut().find(|(k, _)| *k == v) {
                    Some(b) => b.1 += 1,
                    None => buckets.push((v, 1)),
                }
            }
            buckets.sort_by(|a, b| b.1.cmp(&a.1));
            self.rtype.add_terms(&self.rule, end, &buckets, matches);
            return Ok(());
        }
        let hits: Vec<Value> = docs
            .iter()
            .filter(|d| self.in_range(d, start, end))
            .map(|d| {
                let mut src = d.clone();
                let id = src.remove("_id").unwrap_or(Value::Null);
                json!({"_id": id, "_source": src})
            })
            .collect();
        self.on_hits(ctx, start, end, hits, false, matches)
    }

    fn in_range(&self, d: &Doc, start: Ts, end: Ts) -> bool {
        field::lookup(d, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)).is_some_and(|t| start <= t && t < end)
    }

    async fn scroll_pages(&mut self, ctx: &Ctx, start: Ts, end: Ts, index: &str, body: Value, matches: &mut Vec<Doc>) -> Result<()> {
        let size = self.rule.max_query_size;
        let mut resp = ctx.es.search_scroll(index, &body, size, &ctx.scroll_keepalive).await?;
        let total = resp["hits"]["total"]["value"].as_u64().or_else(|| resp["hits"]["total"].as_u64()).unwrap_or(0);
        let (mut pages, mut seen_hits) = (0, 0u64);
        loop {
            pages += 1;
            check_shards(&resp, self.rule.allow_degraded, &self.rule.name)?;
            let hits = match resp["hits"]["hits"].take() {
                Value::Array(a) => a,
                _ => Vec::new(),
            };
            seen_hits += hits.len() as u64;
            let empty = hits.is_empty();
            self.on_hits(ctx, start, end, hits, total > size, matches)?;
            let scroll_id = resp["_scroll_id"].as_str().map(String::from);
            let more = !empty && seen_hits < total && (self.rule.max_scrolling_count == 0 || pages < self.rule.max_scrolling_count);
            match (scroll_id, more) {
                (Some(id), true) => resp = ctx.es.scroll(&id, &ctx.scroll_keepalive).await?,
                (Some(id), false) => {
                    ctx.es.clear_scroll(&id).await;
                    return Ok(());
                }
                (None, _) => return Ok(()),
            }
        }
    }

    /// Point in time + `search_after`: no scroll contexts held, no page cap.
    async fn pit_pages(&mut self, ctx: &Ctx, start: Ts, end: Ts, mut body: Value, mut pit: String, matches: &mut Vec<Doc>) -> Result<()> {
        let size = self.rule.max_query_size;
        body["sort"] = json!([{&self.rule.timestamp_field: {"order": "asc"}}, {"_shard_doc": "asc"}]);
        body["size"] = json!(size);
        body["track_total_hits"] = json!(false);
        let mut pages = 0;
        let result = async {
            loop {
                pages += 1;
                body["pit"] = json!({"id": pit, "keep_alive": "1m"});
                let mut resp = ctx.es.pit_search(&body).await?;
                check_shards(&resp, self.rule.allow_degraded, &self.rule.name)?;
                if let Some(p) = resp["pit_id"].as_str() {
                    pit = p.to_string();
                }
                let hits = match resp["hits"]["hits"].take() {
                    Value::Array(a) => a,
                    _ => Vec::new(),
                };
                let n = hits.len() as u64;
                let last = hits.last().and_then(|h| h.get("sort")).cloned();
                self.on_hits(ctx, start, end, hits, pages > 1 || n >= size, matches)?;
                match last {
                    Some(l) if n >= size && (self.rule.max_scrolling_count == 0 || pages < self.rule.max_scrolling_count) => body["search_after"] = l,
                    _ => return Ok::<(), anyhow::Error>(()),
                }
            }
        }
        .await;
        ctx.es.pit_close(&pit).await;
        result
    }

    // ---- run position ----

    /// Last `endtime` this rule recorded in the status index, if recent enough.
    async fn last_run_end(&self, ctx: &Ctx) -> Option<Ts> {
        let body = json!({
            "query": {"bool": {"filter": {"term": {"rule_name": self.rule.name}}}},
            "sort": {"@timestamp": {"order": "desc"}},
            "size": 1,
            "_source": ["endtime", "rule_name"],
        });
        let index = ctx.writeback.index_for(Wb::Status);
        match ctx.es.search(&index, &body).await {
            Ok(r) => {
                let end = parse_iso(r["hits"]["hits"][0]["_source"]["endtime"].as_str()?)?;
                if now() - end < ctx.old_query_limit {
                    Some(end)
                } else {
                    log::info!("Found expired previous run for {} at {}", self.rule.name, to_iso(end));
                    None
                }
            }
            Err(e) => {
                ctx.writeback.error(format!("Error querying for last run: {e:#}"), json!({"rule": self.rule.name})).await;
                None
            }
        }
    }

    async fn set_starttime(&mut self, ctx: &Ctx, endtime: Ts) {
        if self.starttime.is_none()
            && !self.rule.scan_entire_timeframe
            && !ctx.debug
            && let Some(last) = self.last_run_end(ctx).await
        {
            self.starttime = Some(last);
            self.minimum_starttime = Some(last);
            return;
        }
        if self.counting() {
            // Count and terms queries read exactly one run_every per run.
            self.starttime = Some(if self.rule.scan_entire_timeframe {
                endtime - self.rule.timeframe.unwrap_or_default()
            } else {
                self.previous_endtime.unwrap_or(endtime - ctx.run_every)
            });
            return;
        }
        let back = if self.rule.scan_entire_timeframe { self.rule.timeframe.unwrap_or_default() } else { self.rule.buffer_time };
        let buffer_delta = endtime - back;
        self.starttime = Some(match (self.minimum_starttime, self.previous_endtime) {
            // Documents carry an ingest time: no need to re-read the overlap, just continue where we stopped.
            _ if self.rule.ingest_field.is_some() && !self.rule.scan_entire_timeframe => self.previous_endtime.or(self.minimum_starttime).unwrap_or(buffer_delta),
            (Some(min), _) if min > buffer_delta => min,
            (_, Some(prev)) if prev < buffer_delta => prev,
            _ => buffer_delta,
        });
    }

    /// One run over (start, endtime]. Returns the number of matches.
    pub async fn run(&mut self, ctx: &Ctx, endtime: Ts, starttime: Option<Ts>) -> Result<usize> {
        let t0 = std::time::Instant::now();
        if !ctx.debug {
            self.retry_pending(ctx).await;
        }
        self.rtype.init(&self.rule, &ctx.es, starttime).await?;
        match starttime {
            Some(s) => self.starttime = Some(s),
            None => self.set_starttime(ctx, endtime).await,
        }
        let original_start = self.starttime.expect("starttime set above");
        (self.hits, self.dupes) = (0, 0);
        *self.alerts_sent.get_mut() = 0;
        *self.alerts_not_sent.get_mut() = 0;
        if now() <= original_start {
            log::warn!("Attempted to use query start time in the future ({}), sleeping instead", to_iso(original_start));
            return Ok(0);
        }

        // Long ranges are split into segments, like a continuously running instance would see them.
        let segment = if self.counting() { ctx.run_every } else { self.rule.buffer_time }.max(1);
        let mut matches = Vec::new();
        let mut start = original_start;
        while endtime - start > segment {
            let seg_end = start + segment;
            self.run_query(ctx, start, seg_end, &mut matches).await?;
            start = seg_end;
            self.starttime = Some(start);
            self.rtype.garbage_collect(&self.rule, seg_end, &mut matches);
        }
        self.run_query(ctx, start, endtime, &mut matches).await?;
        self.rtype.garbage_collect(&self.rule, endtime, &mut matches);
        self.enrich(ctx, &mut matches).await;

        let num_matches = matches.len();
        let mut silenced = 0u64;
        for mut m in matches {
            m.insert("num_hits".into(), json!(self.hits));
            m.insert("num_matches".into(), json!(num_matches));
            let mut key = self.rule.realert_key.clone();
            let qv = self.rtype.silence_key(&m).or_else(|| self.rule.query_key.as_ref().and_then(|qk| field::lookup(&m, qk)).map(py_str));
            if let Some(qv) = qv {
                key = format!("{key}.{qv}");
            }
            if ctx.silences.is_silenced(&key) || ctx.silences.is_silenced(&format!("{}._silence", self.rule.name)) {
                log::info!("Ignoring match for silenced rule {key}");
                silenced += 1;
                continue;
            }
            if self.rule.realert > 0 {
                let (until, exponent) = self.next_alert_time(ctx, &key, now());
                ctx.silences.set(&key, until, exponent);
                let doc = json!({"exponent": exponent, "rule_name": key, "@timestamp": to_iso(now()), "until": to_iso(until)});
                ctx.writeback.write(Wb::Silence, doc.as_object().cloned().unwrap_or_default()).await;
            }
            if self.rule.aggregation.is_some() {
                self.add_aggregated(ctx, m).await;
            } else {
                self.alert(ctx, vec![m]).await;
            }
        }

        self.previous_endtime = Some(endtime);
        let took = t0.elapsed().as_secs_f64();
        let status = json!({
            "rule_name": self.rule.name,
            "endtime": to_iso(endtime),
            "starttime": to_iso(original_start),
            "matches": num_matches,
            "hits": self.hits,
            "@timestamp": to_iso(now()),
            "time_taken": took,
        });
        ctx.writeback.write(Wb::Status, status.as_object().cloned().unwrap_or_default()).await;
        let (lt, fmt) = (self.rule.use_local_time, ctx.ts_fmt.as_deref());
        let sent = self.alerts_sent.load(Ordering::Relaxed);
        log::info!(
            "Ran {} from {} to {}: {} query hits ({} already seen), {} matches, {} alerts sent",
            self.rule.name,
            pretty(original_start, lt, fmt),
            pretty(endtime, lt, fmt),
            self.hits,
            self.dupes,
            num_matches,
            sent
        );
        ctx.metrics.rule(&self.rule.name, |c| {
            c.scrapes += 1;
            c.hits += self.hits;
            c.matches += num_matches as u64;
            c.time_taken += took;
            c.alerts_sent += sent;
            c.alerts_not_sent += self.alerts_not_sent.load(Ordering::Relaxed);
            c.alerts_silenced += silenced;
        });
        Ok(num_matches)
    }

    fn next_alert_time(&self, ctx: &Ctx, key: &str, ts: Ts) -> (Ts, i32) {
        next_alert(self.rule.realert, self.rule.exponential_realert, ctx.silences.get(key), ts)
    }

    // ---- enrichment ----

    /// Matches were built from projected documents; fetch the full `_source` of the few that matched.
    async fn enrich(&self, ctx: &Ctx, matches: &mut [Doc]) {
        if !self.rule.enrich || matches.is_empty() || self.mock.is_some() {
            return;
        }
        fn collect(m: &Doc, out: &mut FxHashSet<(String, String)>) {
            if let (Some(i), Some(d)) = (m.get("_index").and_then(Value::as_str), m.get("_id").and_then(Value::as_str)) {
                out.insert((i.to_string(), d.to_string()));
            }
            for r in m.get("related_events").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_object) {
                collect(r, out);
            }
        }
        let mut wanted = FxHashSet::default();
        matches.iter().for_each(|m| collect(m, &mut wanted));
        let wanted: Vec<_> = wanted.into_iter().collect();
        let mut full: FxHashMap<(String, String), Doc> = FxHashMap::default();
        for chunk in wanted.chunks(500) {
            match ctx.es.mget(chunk).await {
                Ok(docs) => {
                    for d in docs {
                        if let (Some(i), Some(id), Some(src)) = (d["_index"].as_str(), d["_id"].as_str(), d["_source"].as_object()) {
                            full.insert((i.to_string(), id.to_string()), src.clone());
                        }
                    }
                }
                Err(e) => log::warn!("rule {}: could not fetch full documents for matches, alerting with partial data: {e:#}", self.rule.name),
            }
        }
        // Fields we asked ES for are replaced by the full values; everything else on the match
        // (num_hits, spike_count, key, ...) was added by the rule and stays.
        let mut tops: FxHashSet<&str> = FxHashSet::default();
        for f in &self.rule.include {
            tops.insert(f.as_str());
            tops.insert(f.split('.').next().unwrap_or(f));
        }
        fn apply(m: &mut Doc, full: &FxHashMap<(String, String), Doc>, tops: &FxHashSet<&str>, ts_field: &str) {
            if let (Some(i), Some(d)) = (m.get("_index").and_then(Value::as_str), m.get("_id").and_then(Value::as_str))
                && let Some(src) = full.get(&(i.to_string(), d.to_string()))
            {
                let ts = field::lookup(m, ts_field).cloned();
                for (k, v) in src {
                    if tops.contains(k.as_str()) {
                        m.insert(k.clone(), v.clone());
                    } else {
                        m.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
                if let Some(ts) = ts
                    && !field::set(m, ts_field, ts.clone())
                {
                    m.insert(ts_field.to_string(), ts);
                }
            }
            if let Some(Value::Array(rel)) = m.get_mut("related_events") {
                for r in rel.iter_mut().filter_map(Value::as_object_mut) {
                    apply(r, full, tops, ts_field);
                }
            }
        }
        for m in matches.iter_mut() {
            apply(m, &full, &tops, &self.rule.timestamp_field);
        }
    }

    // ---- top counts ----

    /// `top_events_<key>`: most frequent values of each `top_count_keys` field around the match.
    async fn add_top_counts(&self, ctx: &Ctx, m: &mut Doc) {
        if self.rule.top_count_keys.is_empty() {
            return;
        }
        let Some(ts) = field::lookup(m, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)) else { return };
        let timeframe = match (&self.rtype, self.rule.timeframe) {
            (RuleType::Flatline(_), Some(t)) => 2 * t,
            (_, Some(t)) => t,
            (_, None) => 10 * MINUTE,
        };
        let (start, end) = (ts - timeframe, ts + 10 * MINUTE);
        let qk = self.rule.query_key.as_ref().and_then(|q| field::lookup(m, q)).map(py_str);
        let extra = self.query_key_filters(qk.as_deref());
        for key in &self.rule.top_count_keys {
            let counts: Doc = if self.mock.is_some() {
                self.mock_top_counts(key, start, end, qk.as_deref())
            } else {
                let result = match self.index_for(start, end) {
                    Ok(index) => self.terms(ctx, &index, start, end, key.clone(), self.rule.top_count_number, extra.clone()).await,
                    Err(e) => Err(e),
                };
                match result {
                    Ok(b) => b.into_iter().map(|(k, n)| (py_str(&k), json!(n))).collect(),
                    Err(e) => {
                        ctx.writeback.error(format!("{e:#}"), json!({"rule": self.rule.name})).await;
                        Doc::new()
                    }
                }
            };
            m.insert(format!("top_events_{key}"), Value::Object(counts));
        }
    }

    fn mock_top_counts(&self, key: &str, start: Ts, end: Ts, qk: Option<&str>) -> Doc {
        let key = key.strip_suffix(".keyword").or(key.strip_suffix(".raw")).unwrap_or(key);
        let mut counts: Vec<(String, i64)> = Vec::new();
        for d in self.mock.iter().flatten().filter(|d| self.in_range(d, start, end)) {
            if let (Some(q), Some(want)) = (&self.rule.query_key, qk)
                && field::lookup(d, q).map(py_str).as_deref() != Some(want)
            {
                continue;
            }
            let Some(v) = field::lookup(d, key) else { continue };
            let v = py_str(v);
            match counts.iter_mut().find(|(k, _)| *k == v) {
                Some(c) => c.1 += 1,
                None => counts.push((v, 1)),
            }
        }
        counts.sort_by(|a, b| b.1.cmp(&a.1));
        counts.truncate(self.rule.top_count_number as usize);
        counts.into_iter().map(|(k, n)| (k, json!(n))).collect()
    }

    /// Term filters restricting the top counts to the match's `query_key` value(s).
    fn query_key_filters(&self, qk: Option<&str>) -> Vec<Value> {
        let Some(qk) = qk else { return vec![] };
        let values: Vec<&str> = qk.split(',').map(str::trim_start).collect();
        let keys: Vec<String> = if self.rule.compound_query_key.is_empty() { self.rule.query_key.iter().cloned().collect() } else { self.rule.compound_query_key.clone() };
        if values.len() != keys.len() {
            log::warn!("Received {} value(s) for {} key(s). Did '{qk}' have a value with a comma?", values.len(), keys.len());
        }
        let raw = self.rule.raw.get("raw_count_keys").and_then(Value::as_bool).unwrap_or(true);
        keys.into_iter()
            .zip(values)
            .map(|(k, v)| json!({"term": {if raw && !k.ends_with(".keyword") { format!("{k}.keyword") } else { k }: v}}))
            .collect()
    }

    // ---- alerting ----

    /// Runs every alerter not yet done for `p`. Returns true when all succeeded.
    async fn deliver(&self, ctx: &Ctx, p: &mut Pending) -> bool {
        let view = View { rule: &self.rule, rtype: &self.rtype, ts_fmt: ctx.ts_fmt.as_deref() };
        let mut all = true;
        for (i, a) in self.alerters.iter().enumerate() {
            if p.done[i] {
                continue;
            }
            match a.alert(&view, &p.matches).await {
                Ok(()) => {
                    p.done[i] = true;
                    self.alerts_sent.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    all = false;
                    p.exception = format!("{e:#}");
                    self.alerts_not_sent.fetch_add(1, Ordering::Relaxed);
                    ctx.metrics.error();
                    ctx.writeback.error(format!("Error while running alert {}: {e:#}", a.kind()), json!({"rule": self.rule.name})).await;
                }
            }
        }
        all
    }

    /// `add_metadata_alert`: category, description, owner and priority of the rule go into the alert doc.
    fn add_metadata(&self, doc: &mut Doc) {
        if self.rule.raw.get("add_metadata_alert").and_then(Value::as_bool).unwrap_or(false) {
            let text = |k: &str, d: &str| self.rule.raw.get(k).map_or_else(|| d.to_string(), py_str);
            doc.insert("category".into(), json!(text("category", "")));
            doc.insert("description".into(), json!(text("description", "")));
            doc.insert("owner".into(), json!(text("owner", "")));
            doc.insert("priority".into(), json!(text("priority", "2")));
        }
    }

    /// Writes the alert doc(s) for `p`: one per match, same `_id` every time so updates overwrite.
    /// An aggregated alert is one doc (the first match); the other matches' docs are deleted once it is fully sent.
    async fn write_alert(&self, ctx: &Ctx, p: &mut Pending) {
        let sent: Vec<&str> = self.alerters.iter().zip(&p.done).filter(|(_, d)| **d).map(|(a, _)| a.kind()).collect();
        let complete = p.done.iter().all(|d| *d);
        let grouped = !p.child_ids.is_empty();
        for (n, m) in p.matches.iter().enumerate() {
            if grouped && n > 0 {
                break;
            }
            let mut doc = Map::new();
            if let Some(t) = field::lookup(m, &self.rule.timestamp_field) {
                doc.insert("match_time".into(), t.clone());
            }
            doc.insert("rule_name".into(), json!(self.rule.name));
            doc.insert("alert_info".into(), self.alerters.first().map_or(json!({}), Alerter::info));
            doc.insert("alert_sent".into(), json!(complete));
            doc.insert("alert_time".into(), json!(to_iso(p.alert_time)));
            doc.insert("alerters_sent".into(), json!(sent));
            doc.insert("retry_count".into(), json!(p.attempts));
            if !complete {
                doc.insert("alert_exception".into(), json!(p.exception));
            }
            self.add_metadata(&mut doc);
            doc.insert("match_body".into(), Value::Object(m.clone()));
            let id = if n == 0 { p.id.clone() } else { Writeback::new_id() };
            ctx.writeback.write_id(Wb::Alert, &id, doc).await;
        }
        if complete {
            for id in p.child_ids.drain(..) {
                ctx.writeback.delete_id(Wb::Alert, &id).await;
            }
        }
    }

    async fn alert(&mut self, ctx: &Ctx, mut matches: Vec<Doc>) {
        for m in &mut matches {
            self.add_top_counts(ctx, m).await;
        }
        if ctx.debug {
            alert::debug_alert(&self.rule, &self.rtype, &matches, ctx.ts_fmt.as_deref());
            return; // --debug never counts as sent, like upstream
        }
        let p = Pending {
            id: Writeback::new_id(),
            matches,
            done: vec![false; self.alerters.len()],
            attempts: 0,
            next_try: 0,
            alert_time: now(),
            exception: String::new(),
            child_ids: vec![],
        };
        self.send(ctx, p).await;
    }

    async fn send(&mut self, ctx: &Ctx, mut p: Pending) {
        let ok = self.deliver(ctx, &mut p).await;
        if !ok {
            p.attempts += 1;
            p.next_try = now() + backoff(p.attempts);
        }
        self.write_alert(ctx, &mut p).await;
        if !ok {
            self.pending.push(p);
        }
    }

    /// Re-sends alerts whose alerters failed earlier; only the failed alerters are retried.
    async fn retry_pending(&mut self, ctx: &Ctx) {
        let mut pending = std::mem::take(&mut self.pending);
        let mut keep = Vec::new();
        for mut p in pending.drain(..) {
            if now() - p.alert_time > ctx.alert_time_limit {
                log::warn!("Giving up on alert {} of rule {}: older than alert_time_limit", p.id, self.rule.name);
                continue;
            }
            if p.next_try > now() {
                keep.push(p);
                continue;
            }
            let ok = self.deliver(ctx, &mut p).await;
            p.attempts += 1;
            if !ok {
                p.next_try = now() + backoff(p.attempts);
            }
            self.write_alert(ctx, &mut p).await;
            if !ok {
                keep.push(p);
            }
        }
        self.pending = keep;
    }

    /// Puts back an alert that failed before the last shutdown.
    pub fn restore_pending(&mut self, p: Pending) {
        self.pending.push(p);
    }

    // ---- aggregation ----

    fn aggregation_key_value(&self, m: &Doc) -> String {
        match &self.rule.aggregation_key {
            Some(k) => field::lookup(m, k).map_or_else(String::new, py_str),
            None => String::new(),
        }
    }

    fn first_alert_time(&self, m: &Doc) -> Ts {
        match self.rule.aggregation.as_ref() {
            Some(Aggregation::Cron(c)) => c
                .parse::<croner::Cron>()
                .ok()
                .and_then(|cron| cron.find_next_occurrence(&chrono::Utc::now(), false).ok())
                .map_or_else(now, |t| t.timestamp_micros()),
            Some(Aggregation::Timespan(d)) => {
                let base = if self.rule.raw.get("aggregate_by_match_time").and_then(Value::as_bool).unwrap_or(false) {
                    field::lookup(m, &self.rule.timestamp_field).and_then(|v| parse_ts(&self.rule, v)).unwrap_or_else(now)
                } else {
                    now()
                };
                base + d
            }
            None => now(),
        }
    }

    /// Queues a match in its group; the group is sent when its time comes (or at shutdown / replay end).
    async fn add_aggregated(&mut self, ctx: &Ctx, m: Doc) {
        let key = self.aggregation_key_value(&m);
        if self.agg.get(&key).is_some_and(|g| g.alert_time < now()) {
            self.flush_group(ctx, &key).await; // due but not sent yet: send it, then start a new one
        }
        let is_new = !self.agg.contains_key(&key);
        if is_new {
            let alert_time = self.first_alert_time(&m);
            log::info!("New aggregation for {}, aggregation_key: {key}. next alert at {}.", self.rule.name, to_iso(alert_time));
            self.agg.insert(key.clone(), AggGroup { alert_time, head_id: Writeback::new_id(), matches: vec![], child_ids: vec![] });
        }
        let g = self.agg.get_mut(&key).expect("inserted above");
        let (id, alert_time, head_id) = if is_new {
            (g.head_id.clone(), g.alert_time, None)
        } else {
            let id = Writeback::new_id();
            g.child_ids.push(id.clone());
            (id, g.alert_time, Some(g.head_id.clone()))
        };
        g.matches.push(m.clone());
        let mut doc = Map::new();
        if let Some(t) = field::lookup(&m, &self.rule.timestamp_field) {
            doc.insert("match_time".into(), t.clone());
        }
        doc.insert("rule_name".into(), json!(self.rule.name));
        doc.insert("alert_info".into(), self.alerters.first().map_or(json!({}), Alerter::info));
        doc.insert("alert_sent".into(), json!(false));
        doc.insert("alert_time".into(), json!(to_iso(alert_time)));
        if !key.is_empty() {
            doc.insert("aggregation_key".into(), json!(key));
        }
        if let Some(h) = head_id {
            doc.insert("aggregate_id".into(), json!(h));
        }
        self.add_metadata(&mut doc);
        doc.insert("match_body".into(), Value::Object(m));
        if !ctx.debug {
            ctx.writeback.write_id(Wb::Alert, &id, doc).await;
        }
    }

    pub fn next_agg_due(&self) -> Option<Ts> {
        self.agg.values().map(|g| g.alert_time).min()
    }

    async fn flush_group(&mut self, ctx: &Ctx, key: &str) {
        let Some(g) = self.agg.remove(key) else { return };
        log::info!("Sending aggregated alert of {} ({} matches, aggregation_key: {key})", self.rule.name, g.matches.len());
        let mut matches = g.matches;
        for m in &mut matches {
            self.add_top_counts(ctx, m).await;
        }
        if ctx.debug {
            alert::debug_alert(&self.rule, &self.rtype, &matches, ctx.ts_fmt.as_deref());
            return;
        }
        let p = Pending {
            id: g.head_id,
            matches,
            done: vec![false; self.alerters.len()],
            attempts: 0,
            next_try: 0,
            alert_time: g.alert_time,
            exception: String::new(),
            child_ids: g.child_ids,
        };
        self.send(ctx, p).await;
    }

    /// Sends the groups whose time has come (`all`: every group, used at the end of a replay).
    pub async fn flush_due(&mut self, ctx: &Ctx, all: bool) {
        let t = now();
        let keys: Vec<String> = self.agg.iter().filter(|(_, g)| all || g.alert_time <= t).map(|(k, _)| k.clone()).collect();
        for k in keys {
            self.flush_group(ctx, &k).await;
        }
    }

    /// Rebuilds a group from the pending docs found in ES at startup.
    pub fn restore_group(&mut self, key: String, head_id: String, alert_time: Ts, matches: Vec<Doc>, child_ids: Vec<String>) {
        self.agg.insert(key, AggGroup { alert_time, head_id, matches, child_ids });
    }

    /// Forgets dedup ids older than buffer_time (+ query_delay).
    pub fn forget_old_hits(&mut self) {
        let horizon = now() - self.rule.buffer_time - self.rule.query_delay;
        self.seen.retain(|_, ts| *ts >= horizon);
    }

}

/// Port of `next_alert_time`: with `exponential_realert` the silence doubles while matches keep coming.
/// `cached` is the previous (until, exponent) for the same key.
fn next_alert(realert: Dur, max: Option<Dur>, cached: Option<(Ts, i32)>, ts: Ts) -> (Ts, i32) {
    let (Some((last_until, mut exponent)), Some(max)) = (cached, max) else {
        return (ts + realert, 0);
    };
    let r = realert as f64 / 1e6;
    let mut diff = (ts - last_until) as f64 / 1e6;
    if diff < r * 2f64.powi(exponent) {
        exponent += 1;
    } else {
        while diff > r * 2f64.powi(exponent) && exponent > 0 {
            diff -= r * 2f64.powi(exponent);
            exponent -= 1;
        }
    }
    let wait = (r * 2f64.powi(exponent) * 1e6) as Dur;
    if wait >= max { (ts + max, exponent - 1) } else { (ts + wait, exponent) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values printed by upstream's `ElastAlerter.next_alert_time` for the same call sequence.
    #[test]
    fn exponential_realert_matches_upstream() {
        let (realert, max) = (60 * SECOND, Some(600 * SECOND));
        let mut cache = None;
        let expected = [(0, 60, 0), (10, 130, 1), (140, 380, 2), (400, 880, 3), (900, 1500, 3), (2000, 2240, 2), (2001, 2481, 3), (5000, 5060, 0)];
        for (t, until, exp) in expected {
            let got = next_alert(realert, max, cache, t * SECOND);
            assert_eq!(got, (until * SECOND, exp), "at t={t}");
            cache = Some(got);
        }
    }
}

/// Shard failures stop the rule, unless `allow_queries_on_degraded_indices`: then only query parse errors do.
fn check_shards(resp: &Value, allow_degraded: bool, rule: &str) -> Result<()> {
    let Some(failures) = resp["_shards"]["failures"].as_array().filter(|f| !f.is_empty()) else { return Ok(()) };
    let parse_errors: Vec<&str> = failures.iter().filter_map(|f| f["reason"]["reason"].as_str()).filter(|r| r.contains("Failed to parse")).collect();
    if !parse_errors.is_empty() {
        bail!("{parse_errors:?}");
    }
    if allow_degraded {
        let mut indices: Vec<&str> = failures.iter().filter_map(|f| f["index"].as_str()).collect();
        indices.sort();
        indices.dedup();
        let listed: String = indices.join(", ").chars().take(1024).collect();
        log::warn!("Rule {rule}: {} shard(s) failed, continuing with partial results. Affected indices: {listed}", failures.len());
        return Ok(());
    }
    bail!("shard failures: {}", Value::Array(failures.clone()))
}
