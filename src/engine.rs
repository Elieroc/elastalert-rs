//! One rule run: pick the time range, query ES page by page, feed the rule type,
//! then silence/realert and alert on each match. Same semantics as ElastAlert's `run_rule`.

use crate::alert;
use crate::alerters::{Alerter, View};
use crate::index;
use crate::es::Es;
use crate::field::{self, py_str};
use crate::rule::Rule;
use crate::time::{Dur, MINUTE, SECOND, Ts, now, pretty, to_iso};
use crate::types::{Event, RuleType, parse_ts, ts_value};
use crate::writeback::{Kind, Writeback};
use anyhow::{Context, Result, bail};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use serde_json::{Map, Value, json};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

/// Realert/silence state shared by all rules (several rules may share a `realert_key`).
#[derive(Default)]
pub struct Silences(Mutex<FxHashMap<String, (Ts, u32)>>);

impl Silences {
    pub fn is_silenced(&self, key: &str) -> bool {
        self.0.lock().unwrap().get(key).is_some_and(|(until, _)| now() < *until)
    }

    /// Merge a silence read from ES: never shortens one we already know.
    pub fn raise(&self, key: &str, until: Ts, exponent: u32) {
        let mut m = self.0.lock().unwrap();
        if m.get(key).is_none_or(|(u, _)| *u < until) {
            m.insert(key.to_string(), (until, exponent));
        }
    }

    pub fn set(&self, key: &str, until: Ts, exponent: u32) {
        self.0.lock().unwrap().insert(key.to_string(), (until, exponent));
    }
}

/// Everything a rule task needs besides its own state.
pub struct Ctx {
    pub es: Es,
    pub writeback: Writeback,
    pub silences: Arc<Silences>,
    pub debug: bool,
    pub old_query_limit: Dur,
    pub alert_time_limit: Dur,
    pub scroll_keepalive: String,
    pub ts_fmt: Option<String>,
}

/// An alert that has not reached every alerter yet. Kept in memory and mirrored in ES (`alert_sent: false`).
pub struct Pending {
    pub id: String,
    pub matches: Vec<Map<String, Value>>,
    pub done: Vec<bool>,
    pub attempts: u32,
    pub next_try: Ts,
    pub alert_time: Ts,
    pub exception: String,
}

pub struct RuleState {
    pub rule: Rule,
    rtype: RuleType,
    alerters: Vec<Alerter>,
    pub pending: Vec<Pending>,
    starttime: Option<Ts>,
    previous_endtime: Option<Ts>,
    minimum_starttime: Option<Ts>,
    /// Hash of `_id` -> event time, to skip hits already seen in overlapping windows.
    seen: FxHashMap<u64, Ts>,
    /// Counters for the current run.
    hits: u64,
    dupes: u64,
    alerts_sent: u64,
}

fn id_hash(id: &str) -> u64 {
    let mut h = FxHasher::default();
    id.hash(&mut h);
    h.finish()
}

impl RuleState {
    pub fn new(rule: Rule) -> Result<Self> {
        let alerters = rule.alerts.iter().map(|k| Alerter::from_rule(k, &rule)).collect::<Result<Vec<_>>>()?;
        Ok(RuleState {
            rtype: RuleType::new(&rule)?,
            alerters,
            pending: Vec::new(),
            rule,
            starttime: None,
            previous_endtime: None,
            minimum_starttime: None,
            seen: FxHashMap::default(),
            hits: 0,
            dupes: 0,
            alerts_sent: 0,
        })
    }

    /// After a reload: keep the query position, dedup set and unsent alerts of the previous version.
    pub fn carry_over(&mut self, old: RuleState) {
        (self.starttime, self.previous_endtime, self.minimum_starttime, self.seen, self.pending) =
            (old.starttime, old.previous_endtime, old.minimum_starttime, old.seen, old.pending);
        let n = self.alerters.len();
        self.pending.iter_mut().for_each(|p| p.done.resize(n, false));
    }

    fn fmt_ts(&self, ts: Ts) -> Value {
        ts_value(&self.rule, ts)
    }

    /// Range filter + user filters + timestamp sort, the query every hit search uses.
    fn query(&self, start: Ts, end: Ts) -> Value {
        let mut must = vec![json!({"range": {&self.rule.timestamp_field: {"gt": self.fmt_ts(start), "lte": self.fmt_ts(end)}}})];
        // Old-style `- query: {...}` filter entries are unwrapped.
        must.extend(self.rule.filter.iter().map(|f| f.get("query").cloned().unwrap_or_else(|| f.clone())));
        must.extend(self.rtype.extra_filter(&self.rule));
        json!({
            "query": {"bool": {"filter": {"bool": {"must": must}}}},
            "sort": [{&self.rule.timestamp_field: {"order": "asc"}}],
            "_source": {"includes": self.rule.include},
        })
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
            if !self.rule.compound_query_key.is_empty() {
                let joined: Vec<String> = self
                    .rule
                    .compound_query_key
                    .iter()
                    .map(|k| field::lookup(&doc, k).map_or_else(|| "None".into(), py_str))
                    .collect();
                doc.insert(self.rule.query_key.clone().unwrap_or_default(), json!(joined.join(", ")));
            }
            out.push(Event { ts, doc });
        }
        Ok(out)
    }

    fn index_for(&self, start: Ts, end: Ts) -> Result<String> {
        if self.rule.use_strftime_index { index::format_index(&self.rule.index, start, end, self.rule.search_extra_index) } else { Ok(self.rule.index.clone()) }
    }

    /// Runs the search for [start, end] with scrolling, feeding every page to the rule type.
    async fn run_query(&mut self, ctx: &Ctx, start: Ts, end: Ts, matches: &mut Vec<Map<String, Value>>) -> Result<()> {
        let body = self.query(start, end);
        let index = self.index_for(start, end)?;
        let size = self.rule.max_query_size;
        let mut resp = ctx.es.search_scroll(&index, &body, size, &ctx.scroll_keepalive).await?;
        let total = resp["hits"]["total"]["value"].as_u64().or_else(|| resp["hits"]["total"].as_u64()).unwrap_or(0);
        let mut pages = 0;
        let mut seen_hits = 0u64;
        loop {
            pages += 1;
            check_shards(&resp)?;
            let mut hits = match resp["hits"]["hits"].take() {
                Value::Array(a) => a,
                _ => Vec::new(),
            };
            seen_hits += hits.len() as u64;
            self.hits += hits.len() as u64;
            let lt = self.rule.use_local_time;
            let fmt = ctx.ts_fmt.as_deref();
            let status = format!(
                "Queried rule {} from {} to {}: {} / {} hits",
                self.rule.name,
                pretty(start, lt, fmt),
                pretty(end, lt, fmt),
                self.hits,
                hits.len()
            );
            if total > size {
                log::info!("{status} (scrolling..)");
            } else {
                log::info!("{status}");
            }
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
            let scroll_id = resp["_scroll_id"].as_str().map(String::from);
            let more = !hits.is_empty() && seen_hits < total && (self.rule.max_scrolling_count == 0 || pages < self.rule.max_scrolling_count);
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

    /// Last `endtime` this rule recorded in the status index, if recent enough.
    async fn last_run_end(&self, ctx: &Ctx) -> Option<Ts> {
        let body = json!({
            "query": {"bool": {"filter": {"term": {"rule_name": self.rule.name}}}},
            "sort": {"@timestamp": {"order": "desc"}},
            "size": 1,
            "_source": ["endtime", "rule_name"],
        });
        let index = ctx.writeback.index_for(Kind::Status);
        match ctx.es.search(&index, &body).await {
            Ok(r) => {
                let end = crate::time::parse_iso(r["hits"]["hits"][0]["_source"]["endtime"].as_str()?)?;
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
            && let Some(last) = self.last_run_end(ctx).await
        {
            self.starttime = Some(last);
            self.minimum_starttime = Some(last);
            return;
        }
        let back = if self.rule.scan_entire_timeframe { self.rule.timeframe.unwrap_or_default() } else { self.rule.buffer_time };
        let buffer_delta = endtime - back;
        self.starttime = Some(match (self.minimum_starttime, self.previous_endtime) {
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
        (self.hits, self.dupes, self.alerts_sent) = (0, 0, 0);
        if now() <= original_start {
            log::warn!("Attempted to use query start time in the future ({}), sleeping instead", to_iso(original_start));
            return Ok(0);
        }

        // Long ranges are split into buffer_time segments, like a continuously running instance would see them.
        let segment = self.rule.buffer_time.max(1);
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
                continue;
            }
            if self.rule.realert > 0 {
                let until = now() + self.rule.realert;
                ctx.silences.set(&key, until, 0);
                let doc = json!({"exponent": 0, "rule_name": key, "@timestamp": to_iso(now()), "until": to_iso(until)});
                ctx.writeback.write(Kind::Silence, doc.as_object().cloned().unwrap_or_default()).await;
            }
            self.alert(ctx, vec![m]).await;
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
        ctx.writeback.write(Kind::Status, status.as_object().cloned().unwrap_or_default()).await;
        let lt = self.rule.use_local_time;
        let fmt = ctx.ts_fmt.as_deref();
        log::info!(
            "Ran {} from {} to {}: {} query hits ({} already seen), {} matches, {} alerts sent",
            self.rule.name,
            pretty(original_start, lt, fmt),
            pretty(endtime, lt, fmt),
            self.hits,
            self.dupes,
            num_matches,
            self.alerts_sent
        );
        Ok(num_matches)
    }

    /// Matches were built from projected documents; fetch the full `_source` of the few that matched.
    async fn enrich(&self, ctx: &Ctx, matches: &mut [Map<String, Value>]) {
        if !self.rule.enrich || matches.is_empty() {
            return;
        }
        fn collect(m: &Map<String, Value>, out: &mut FxHashSet<(String, String)>) {
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
        let mut full: FxHashMap<(String, String), Map<String, Value>> = FxHashMap::default();
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
        fn apply(m: &mut Map<String, Value>, full: &FxHashMap<(String, String), Map<String, Value>>, tops: &FxHashSet<&str>, ts_field: &str) {
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

    /// Runs every alerter not yet done for `p`. Returns true when all succeeded.
    async fn deliver(&self, ctx: &Ctx, p: &mut Pending) -> bool {
        let view = View { rule: &self.rule, rtype: &self.rtype, ts_fmt: ctx.ts_fmt.as_deref() };
        let mut all = true;
        for (i, a) in self.alerters.iter().enumerate() {
            if p.done[i] {
                continue;
            }
            match a.alert(&view, &p.matches).await {
                Ok(()) => p.done[i] = true,
                Err(e) => {
                    all = false;
                    p.exception = format!("{e:#}");
                    ctx.writeback
                        .error(format!("Error while running alert {}: {e:#}", a.kind()), json!({"rule": self.rule.name}))
                        .await;
                }
            }
        }
        all
    }

    /// Writes the alert doc(s) for `p`: one per match, same `_id` every time so updates overwrite.
    async fn write_alert(&self, ctx: &Ctx, p: &Pending) {
        let sent: Vec<&str> = self.alerters.iter().zip(&p.done).filter(|(_, d)| **d).map(|(a, _)| a.kind()).collect();
        let complete = p.done.iter().all(|d| *d);
        for (n, m) in p.matches.iter().enumerate() {
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
            doc.insert("match_body".into(), Value::Object(m.clone()));
            let id = if n == 0 { p.id.clone() } else { Writeback::new_id() };
            ctx.writeback.write_id(Kind::Alert, &id, doc).await;
        }
    }

    async fn alert(&mut self, ctx: &Ctx, matches: Vec<Map<String, Value>>) {
        if ctx.debug {
            alert::debug_alert(&self.rule, &self.rtype, &matches, ctx.ts_fmt.as_deref());
            return; // --debug never counts as sent, like upstream
        }
        let mut p = Pending {
            id: Writeback::new_id(),
            matches,
            done: vec![false; self.alerters.len()],
            attempts: 0,
            next_try: 0,
            alert_time: now(),
            exception: String::new(),
        };
        let ok = self.deliver(ctx, &mut p).await;
        self.alerts_sent += p.done.iter().filter(|d| **d).count() as u64 / self.alerters.len().max(1) as u64;
        if !ok {
            p.attempts = 1;
            p.next_try = now() + backoff(1);
        }
        self.write_alert(ctx, &p).await;
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
            self.write_alert(ctx, &p).await;
            if ok {
                self.alerts_sent += 1;
            } else {
                keep.push(p);
            }
        }
        self.pending = keep;
    }

    /// Forgets dedup ids older than buffer_time (+ query_delay).
    pub fn forget_old_hits(&mut self) {
        let horizon = now() - self.rule.buffer_time - self.rule.query_delay;
        self.seen.retain(|_, ts| *ts >= horizon);
    }
}

/// Retry delay: 30 s doubling per attempt, at most one hour.
fn backoff(attempts: u32) -> Dur {
    (30 * SECOND << attempts.min(7)).min(60 * MINUTE)
}

fn check_shards(resp: &Value) -> Result<()> {
    let Some(failures) = resp["_shards"]["failures"].as_array().filter(|f| !f.is_empty()) else { return Ok(()) };
    let parse_errors: Vec<&str> = failures
        .iter()
        .filter_map(|f| f["reason"]["reason"].as_str())
        .filter(|r| r.contains("Failed to parse"))
        .collect();
    if !parse_errors.is_empty() {
        bail!("{parse_errors:?}");
    }
    bail!("shard failures: {}", Value::Array(failures.clone()))
}
