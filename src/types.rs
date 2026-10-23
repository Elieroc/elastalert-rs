//! Rule types: they receive query results and emit matches. State is per rule (never shared).

use crate::es::Es;
use crate::field::{self, py_str};
use crate::rule::{Kind, Rule, TsType};
use crate::time::{Dur, Ts, pretty, pretty_duration, to_iso};
use anyhow::Result;
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::{Map, Value, json};
use std::collections::VecDeque;

pub type Doc = Map<String, Value>;

/// One hit from Elasticsearch with its parsed timestamp.
pub struct Event {
    pub ts: Ts,
    pub doc: Doc,
}

impl Event {
    fn placeholder(rule: &Rule, ts: Ts, qk: Option<Value>) -> Event {
        let mut doc = Doc::new();
        doc.insert(rule.timestamp_field.clone(), json!(to_iso(ts)));
        doc.insert("placeholder".into(), json!(true));
        if let (Some(k), Some(v)) = (&rule.query_key, qk) {
            doc.insert(k.clone(), v);
        }
        Event { ts, doc }
    }

    fn is_placeholder(&self) -> bool {
        self.doc.contains_key("placeholder")
    }
}

/// Time-ordered events covering less than `timeframe`. Oldest are evicted on append.
pub struct EventWindow {
    timeframe: Dur,
    data: VecDeque<(Event, i64)>,
    count: i64,
}

impl EventWindow {
    pub fn new(timeframe: Dur) -> Self {
        EventWindow { timeframe, data: VecDeque::new(), count: 0 }
    }

    /// Inserts in timestamp order (after equal timestamps) and evicts while the span >= timeframe.
    /// Returns what was evicted, oldest first.
    pub fn append(&mut self, ev: Event, count: i64) -> Vec<(Event, i64)> {
        let pos = self.data.partition_point(|(e, _)| e.ts <= ev.ts);
        self.data.insert(pos, (ev, count));
        self.count += count;
        let mut evicted = Vec::new();
        while self.duration() >= self.timeframe {
            let Some(old) = self.data.pop_front() else { break };
            self.count -= old.1;
            evicted.push(old);
        }
        evicted
    }

    fn duration(&self) -> Dur {
        match (self.data.front(), self.data.back()) {
            (Some(a), Some(b)) => b.0.ts - a.0.ts,
            _ => 0,
        }
    }

    pub fn count(&self) -> i64 {
        self.count
    }

    fn clear(&mut self) {
        self.data.clear();
        self.count = 0;
    }

    pub fn last_ts(&self) -> Option<Ts> {
        self.data.back().map(|(e, _)| e.ts)
    }

    /// Mean of the counts (the field values) of non-placeholder entries.
    fn mean(&self) -> Option<f64> {
        let vals: Vec<i64> = self.data.iter().filter(|(e, _)| !e.is_placeholder()).map(|(_, c)| *c).collect();
        (!vals.is_empty()).then(|| vals.iter().sum::<i64>() as f64 / vals.len() as f64)
    }
}

/// Converts the parsed timestamp back to the rule's wire format (ElastAlert's `add_match`).
pub fn ts_value(rule: &Rule, ts: Ts) -> Value {
    match rule.timestamp_type {
        TsType::Iso => json!(to_iso(ts)),
        TsType::Unix => json!(ts.div_euclid(1_000_000)),
        TsType::UnixMs => json!(ts.div_euclid(1_000)),
    }
}

fn into_match(rule: &Rule, mut ev: Event) -> Doc {
    let v = ts_value(rule, ev.ts);
    if !field::set(&mut ev.doc, &rule.timestamp_field, v.clone()) {
        ev.doc.insert(rule.timestamp_field.clone(), v);
    }
    ev.doc
}

const ALL: &str = "\"all\"";

/// Group key: JSON text of the query_key value (so `1` and `"1"` stay apart, like Python dict keys).
fn group_key(rule: &Rule, doc: &Doc) -> String {
    match &rule.query_key {
        Some(qk) => field::lookup(doc, qk).map_or_else(|| "null".into(), Value::to_string),
        None => ALL.into(),
    }
}

fn key_value(key: &str) -> Value {
    serde_json::from_str(key).unwrap_or_else(|_| json!(key))
}

/// Python truthiness of a JSON value.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn opt_f64(rule: &Rule, key: &str) -> Option<f64> {
    rule.raw.get(key).and_then(Value::as_f64)
}

fn opt_bool(rule: &Rule, key: &str) -> bool {
    rule.raw.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn tf(rule: &Rule) -> Dur {
    rule.timeframe.unwrap_or_default()
}

pub enum RuleType {
    Any,
    Frequency(Frequency),
    Spike(Spike),
    Flatline(Flatline),
    Compare(Compare),
    NewTerm(NewTerm),
    Cardinality(Cardinality),
}

impl RuleType {
    pub fn new(rule: &Rule) -> Result<Self> {
        Ok(match rule.kind {
            Kind::Any => RuleType::Any,
            Kind::Frequency => RuleType::Frequency(Frequency::default()),
            Kind::Spike => RuleType::Spike(Spike::new(rule)),
            Kind::Flatline => RuleType::Flatline(Flatline::new(rule)),
            Kind::Blacklist | Kind::Whitelist | Kind::Change => RuleType::Compare(Compare::new(rule)?),
            Kind::NewTerm => RuleType::NewTerm(NewTerm::new(rule)?),
            Kind::Cardinality => RuleType::Cardinality(Cardinality::new(rule)),
        })
    }

    /// One-time async setup (new_term loads existing terms). Safe to call every run.
    pub async fn init(&mut self, rule: &Rule, es: &Es, end: Option<Ts>) -> Result<()> {
        match self {
            RuleType::NewTerm(n) => n.init(rule, es, end).await,
            _ => Ok(()),
        }
    }

    pub fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        match self {
            RuleType::Any => matches.extend(events.into_iter().map(|e| into_match(rule, e))),
            RuleType::Frequency(f) => f.add_data(rule, events, matches),
            RuleType::Spike(s) => s.add_data(rule, events, matches),
            RuleType::Flatline(f) => f.add_data(rule, events, matches),
            RuleType::Compare(c) => c.add_data(rule, events, matches),
            RuleType::NewTerm(n) => n.add_data(rule, events, matches),
            RuleType::Cardinality(c) => c.add_data(rule, events, matches),
        }
    }

    /// Called with the end of each queried segment; drops stale state and may produce matches
    /// (flatline, spike placeholders, min_cardinality).
    pub fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        match self {
            RuleType::Frequency(f) => f.occurrences.retain(|_, w| w.last_ts().is_some_and(|t| ts - t <= tf(rule))),
            RuleType::Spike(s) => s.garbage_collect(rule, ts, matches),
            RuleType::Flatline(f) => f.garbage_collect(rule, ts, matches),
            RuleType::Cardinality(c) => c.garbage_collect(rule, ts, matches),
            _ => {}
        }
    }

    /// Silence key part for rules whose matches don't carry the query_key (flatline).
    pub fn silence_key(&self, m: &Doc) -> Option<String> {
        matches!(self, RuleType::Flatline(_)).then(|| m.get("key").map(py_str)).flatten()
    }

    /// Query filters this type adds (blacklist / whitelist terms).
    pub fn extra_filter(&self, rule: &Rule) -> Option<Value> {
        match self {
            RuleType::Compare(c) => c.extra_filter(rule),
            _ => None,
        }
    }

    /// The type-specific sentence in the alert body.
    pub fn match_str(&self, rule: &Rule, m: &Doc, ts_fmt: Option<&str>) -> String {
        let ts = || field::lookup(m, &rule.timestamp_field).and_then(|v| parse_ts(rule, v));
        let lt = rule.use_local_time;
        match self {
            RuleType::Frequency(_) => {
                let Some(ts) = ts() else { return String::new() };
                let start = pretty(ts - tf(rule), lt, ts_fmt);
                let end = pretty(ts, lt, ts_fmt);
                format!("At least {} events occurred between {start} and {end}\n\n", rule.num_events)
            }
            RuleType::Spike(s) => {
                let Some(ts) = ts() else { return String::new() };
                let at = pretty(ts, lt, ts_fmt);
                let (cur, refc) = (m.get("spike_count").and_then(Value::as_f64).unwrap_or(0.0), m.get("reference_count").and_then(Value::as_f64).unwrap_or(0.0));
                match &s.field_value {
                    None => format!(
                        "An abnormal number ({}) of events occurred around {at}.\nPreceding that time, there were only {} events within {}\n\n",
                        cur as i64,
                        refc as i64,
                        pretty_duration(tf(rule))
                    ),
                    Some(f) => format!(
                        "An abnormal average value ({cur:.2}) of field '{f}' occurred around {at}.\nPreceding that time, the field had an average value of ({refc:.2}) within {}\n\n",
                        pretty_duration(tf(rule))
                    ),
                }
            }
            RuleType::Flatline(f) => {
                let Some(ts) = ts() else { return String::new() };
                format!(
                    "An abnormally low number of events occurred around {}.\nBetween {} and {}, there were less than {} events.\n\n",
                    pretty(ts, lt, ts_fmt),
                    pretty(ts - tf(rule), lt, ts_fmt),
                    pretty(ts, lt, ts_fmt),
                    py_str(&f.threshold)
                )
            }
            RuleType::Cardinality(c) => {
                let Some(ts) = ts() else { return String::new() };
                let (start, end) = (pretty(ts - tf(rule), lt, ts_fmt), pretty(ts, lt, ts_fmt));
                match c.max {
                    Some(max) => format!("A maximum of {} unique {}(s) occurred since last alert or between {start} and {end}\n\n", py_num(max), c.field),
                    None => format!("Less than {} unique {}(s) occurred since last alert or between {start} and {end}\n\n", py_num(c.min.unwrap_or(0.0)), c.field),
                }
            }
            _ => String::new(),
        }
    }
}

fn py_num(f: f64) -> String {
    if f.fract() == 0.0 { format!("{}", f as i64) } else { f.to_string() }
}

/// Reads a timestamp value according to `timestamp_type`.
pub fn parse_ts(rule: &Rule, v: &Value) -> Option<Ts> {
    match (rule.timestamp_type, v) {
        (TsType::Iso, Value::String(s)) => crate::time::parse_iso(s),
        (TsType::Unix, v) => num(v).map(|n| (n * 1e6) as Ts),
        (TsType::UnixMs, v) => num(v).map(|n| (n * 1e3) as Ts),
        _ => None,
    }
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str()?.parse().ok())
}

// ---- frequency ----

#[derive(Default)]
pub struct Frequency {
    occurrences: FxHashMap<String, EventWindow>,
}

impl Frequency {
    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let key = group_key(rule, &ev.doc);
            let window = self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule)));
            window.append(ev, 1);
            if window.count() >= rule.num_events as i64 {
                let mut w = self.occurrences.remove(&key).expect("window just used");
                let (last, _) = w.data.pop_back().expect("non-empty window");
                let mut m = into_match(rule, last);
                if rule.attach_related {
                    let related: Vec<Value> = w.data.into_iter().map(|(e, _)| Value::Object(into_match(rule, e))).collect();
                    m.insert("related_events".into(), Value::Array(related));
                }
                matches.push(m);
            }
        }
    }
}

// ---- flatline ----

pub struct Flatline {
    occurrences: FxHashMap<String, EventWindow>,
    first_event: FxHashMap<String, Ts>,
    threshold: Value,
}

impl Flatline {
    fn new(rule: &Rule) -> Self {
        Flatline { occurrences: FxHashMap::default(), first_event: FxHashMap::default(), threshold: rule.raw.get("threshold").cloned().unwrap_or(json!(0)) }
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        let mut last_key = None;
        for ev in events {
            let key = group_key(rule, &ev.doc);
            self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule))).append(ev, 1);
            last_key = Some(key);
        }
        // Like upstream, only the last event's key is checked after a batch; the rest wait for garbage_collect.
        if let Some(k) = last_key.filter(|k| self.occurrences.contains_key(k)) {
            self.check(rule, &k, matches);
        }
    }

    fn check(&mut self, rule: &Rule, key: &str, matches: &mut Vec<Doc>) {
        let Some(window) = self.occurrences.get(key) else { return };
        let Some((last_ev, _)) = window.data.back() else { return };
        let most_recent = last_ev.ts;
        let first = *self.first_event.entry(key.to_string()).or_insert(most_recent);
        if most_recent - first < tf(rule) {
            return;
        }
        let count = window.count();
        let threshold = self.threshold.as_f64().unwrap_or(0.0);
        if (count as f64) < threshold {
            let mut m = into_match(rule, Event { ts: last_ev.ts, doc: last_ev.doc.clone() });
            m.insert("key".into(), key_value(key));
            m.insert("count".into(), json!(count));
            m.insert("threshold".into(), self.threshold.clone());
            matches.push(m);
            if opt_bool(rule, "forget_keys") {
                self.first_event.remove(key);
                self.occurrences.remove(key);
            } else {
                let least_recent = window.data.front().map_or(most_recent, |(e, _)| e.ts);
                self.first_event.insert(key.to_string(), least_recent.min(most_recent - tf(rule)));
            }
        }
    }

    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let mut keys: Vec<String> = self.occurrences.keys().cloned().collect();
        if keys.is_empty() && rule.query_key.is_none() {
            keys.push(ALL.into());
        }
        for key in keys {
            // A zero-count event slides the window so old events are evicted and absence is noticed.
            let ev = Event { ts, doc: Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]) };
            self.occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(tf(rule))).append(ev, 0);
            self.first_event.entry(key.clone()).or_insert(ts);
            self.check(rule, &key, matches);
        }
    }
}

// ---- spike ----

pub struct Spike {
    ref_windows: FxHashMap<String, EventWindow>,
    cur_windows: FxHashMap<String, EventWindow>,
    first_event: FxHashMap<String, Ts>,
    skip_checks: FxHashMap<String, Ts>,
    ref_filled_once: bool,
    field_value: Option<String>,
}

impl Spike {
    fn new(rule: &Rule) -> Self {
        Spike {
            ref_windows: FxHashMap::default(),
            cur_windows: FxHashMap::default(),
            first_event: FxHashMap::default(),
            skip_checks: FxHashMap::default(),
            ref_filled_once: false,
            field_value: rule.raw.get("field_value").and_then(Value::as_str).map(String::from),
        }
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let qk = match &rule.query_key {
                Some(q) => match field::lookup(&ev.doc, q) {
                    Some(v) if !v.is_null() => v.to_string(),
                    _ => json!("other").to_string(),
                },
                None => ALL.to_string(),
            };
            match &self.field_value {
                Some(f) => {
                    // Upstream checks the literal top-level key, then reads it by path.
                    if !ev.doc.contains_key(f) {
                        continue;
                    }
                    let Some(v) = field::lookup(&ev.doc, f).filter(|v| !v.is_null()) else { continue };
                    match num(v) {
                        Some(n) => self.handle_event(rule, ev, n as i64, qk, matches),
                        None => log::warn!("{f} is not a number: {}", py_str(v)),
                    }
                }
                None => self.handle_event(rule, ev, 1, qk, matches),
            }
        }
    }

    fn values(&self, qk: &str) -> (Option<f64>, Option<f64>) {
        let (r, c) = (&self.ref_windows[qk], &self.cur_windows[qk]);
        if self.field_value.is_some() { (r.mean(), c.mean()) } else { (Some(r.count() as f64), Some(c.count() as f64)) }
    }

    fn find_matches(&self, rule: &Rule, refv: Option<f64>, cur: Option<f64>) -> bool {
        if self.field_value.is_none() && cur.is_some() && refv.is_some() {
            if cur < Some(opt_f64(rule, "threshold_cur").unwrap_or(0.0)) || refv < Some(opt_f64(rule, "threshold_ref").unwrap_or(0.0)) {
                return false;
            }
        } else if refv.is_none_or(|r| r == 0.0) || cur.is_none_or(|c| c == 0.0) {
            return false;
        }
        let (r, c) = (refv.unwrap_or(0.0), cur.unwrap_or(0.0));
        let h = opt_f64(rule, "spike_height").unwrap_or(1.0);
        let (down, up) = (c <= r / h, c >= r * h);
        match rule.raw.get("spike_type").and_then(Value::as_str) {
            Some("up") => up,
            Some("down") => down,
            _ => up || down,
        }
    }

    fn handle_event(&mut self, rule: &Rule, ev: Event, count: i64, qk: String, matches: &mut Vec<Doc>) {
        let timeframe = tf(rule);
        let ev_ts = ev.ts;
        self.first_event.entry(qk.clone()).or_insert(ev_ts);
        self.ref_windows.entry(qk.clone()).or_insert_with(|| EventWindow::new(timeframe));
        let evicted = self.cur_windows.entry(qk.clone()).or_insert_with(|| EventWindow::new(timeframe)).append(ev, count);
        let ref_w = self.ref_windows.get_mut(&qk).expect("inserted above");
        for (e, c) in evicted {
            ref_w.append(e, c);
        }

        if ev_ts - self.first_event[&qk] < 2 * timeframe {
            if !self.ref_filled_once {
                return;
            }
            if !(rule.query_key.is_some() && opt_bool(rule, "alert_on_new_data")) {
                return;
            }
            if self.skip_checks.get(&qk).is_some_and(|until| ev_ts < *until) {
                return;
            }
        } else {
            self.ref_filled_once = true;
        }

        let (refv, cur) = self.values(&qk);
        if !self.find_matches(rule, refv, cur) {
            return;
        }
        let w = &self.cur_windows[&qk];
        let pick = if self.field_value.is_some() { w.data.iter().find(|(e, _)| !e.is_placeholder()) } else { w.data.iter().find(|(_, c)| *c != 0) };
        let Some((src, _)) = pick.or(w.data.back()) else { return };
        let (m_ts, mut m) = (src.ts, into_match(rule, Event { ts: src.ts, doc: src.doc.clone() }));
        m.insert("spike_count".into(), json!(cur));
        m.insert("reference_count".into(), json!(refv));
        if self.field_value.is_none() {
            m.insert("spike_count".into(), json!(cur.unwrap_or(0.0) as i64));
            m.insert("reference_count".into(), json!(refv.unwrap_or(0.0) as i64));
        }
        matches.push(m);
        self.ref_windows.get_mut(&qk).expect("exists").clear();
        self.first_event.remove(&qk);
        self.skip_checks.insert(qk, m_ts + 2 * timeframe);
    }

    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let keys: Vec<String> = self.cur_windows.keys().cloned().collect();
        for qk in keys {
            if qk != ALL && self.ref_windows[&qk].count() == 0 && self.cur_windows[&qk].count() == 0 {
                self.cur_windows.remove(&qk);
                self.ref_windows.remove(&qk);
                continue;
            }
            let ph = Event::placeholder(rule, ts, (qk != ALL).then(|| key_value(&qk)));
            self.handle_event(rule, ph, 0, qk, matches);
        }
    }
}

// ---- blacklist / whitelist / change ----

pub struct Compare {
    kind: Kind,
    key: String,
    keys: Vec<String>,
    list: FxHashSet<String>,
    ignore_null: bool,
    last_values: FxHashMap<String, Vec<Option<Value>>>,
    last_time: FxHashMap<String, Ts>,
    change_map: FxHashMap<String, (Vec<Option<Value>>, Vec<Option<Value>>)>,
}

impl Compare {
    fn new(rule: &Rule) -> Result<Self> {
        let list_name = match rule.kind {
            Kind::Blacklist => "blacklist",
            Kind::Whitelist => "whitelist",
            _ => "",
        };
        let mut list = FxHashSet::default();
        if let Some(Value::Array(entries)) = rule.raw.get(list_name) {
            for e in entries {
                let e = py_str(e);
                match e.strip_prefix("!file") {
                    Some(path) => {
                        let path = path.trim();
                        let text = std::fs::read_to_string(path).map_err(|err| anyhow::anyhow!("{path}: {err}"))?;
                        list.extend(text.lines().map(|l| l.trim_end().to_string()));
                    }
                    None => {
                        list.insert(e);
                    }
                }
            }
        }
        Ok(Compare {
            kind: rule.kind,
            key: rule.compare_key.join(","),
            keys: rule.compare_key.clone(),
            list,
            ignore_null: opt_bool(rule, "ignore_null"),
            last_values: FxHashMap::default(),
            last_time: FxHashMap::default(),
            change_map: FxHashMap::default(),
        })
    }

    /// Terms appended to the query so ES only returns candidates (upstream `enhance_filter`).
    fn extra_filter(&self, rule: &Rule) -> Option<Value> {
        if rule.raw.get("filter_by_list").and_then(Value::as_bool) == Some(false) || self.kind == Kind::Change {
            return None;
        }
        let mut terms: Vec<&String> = self.list.iter().collect();
        terms.sort();
        let parts: Vec<String> = terms
            .into_iter()
            .map(|t| if t.starts_with('/') && t.ends_with('/') { format!("{}:{t}", self.key) } else { format!("{}:\"{t}\"", self.key) })
            .collect();
        let query = if self.kind == Kind::Whitelist { format!("NOT {}", parts.join(" AND NOT ")) } else { parts.join(" OR ") };
        Some(json!({"query_string": {"query": query}}))
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let hit = match self.kind {
                Kind::Blacklist => field::lookup(&ev.doc, &self.key).and_then(Value::as_str).is_some_and(|t| self.list.contains(t)),
                Kind::Whitelist => match field::lookup(&ev.doc, &self.key) {
                    None | Some(Value::Null) => !self.ignore_null,
                    Some(Value::String(t)) => !self.list.contains(t.as_str()),
                    Some(_) => true,
                },
                _ => self.changed(rule, &ev),
            };
            if hit {
                let mut m = into_match(rule, Event { ts: ev.ts, doc: ev.doc });
                if self.kind == Kind::Change {
                    let qk = rule.query_key.as_ref().and_then(|q| field::lookup(&m, q)).map_or_else(|| "null".to_string(), Value::to_string);
                    if let Some((old, new)) = self.change_map.get(&qk) {
                        m.insert("old_value".into(), json!(old));
                        m.insert("new_value".into(), json!(new));
                    }
                }
                matches.push(m);
            }
        }
    }

    fn changed(&mut self, rule: &Rule, ev: &Event) -> bool {
        let key = rule.query_key.as_ref().and_then(|q| field::lookup(&ev.doc, q)).map_or_else(|| "null".to_string(), Value::to_string);
        let values: Vec<Option<Value>> = self.keys.iter().map(|k| field::lookup(&ev.doc, k).cloned()).collect();
        if self.ignore_null && values.iter().any(|v| !matches!(v, Some(Value::Bool(_))) && !truthy(v.as_ref())) {
            return false;
        }
        let mut changed = false;
        if let Some(prev) = self.last_values.get(&key) {
            changed = prev.iter().zip(&values).any(|(a, b)| a != b);
            if changed {
                self.change_map.insert(key.clone(), (prev.clone(), values.clone()));
                if let Some(t) = self.last_time.get(&key) {
                    changed = ev.ts - t <= tf(rule);
                }
            }
        }
        self.last_values.insert(key.clone(), values);
        if rule.timeframe.is_some() {
            self.last_time.insert(key, ev.ts);
        }
        changed
    }
}

// ---- new_term ----

pub struct NewTerm {
    /// One entry per field (a composite field is a list of sub-fields).
    fields: Vec<Vec<String>>,
    seen: Vec<FxHashSet<String>>,
    ready: bool,
}

fn kw(field: &str, rule: &Rule) -> String {
    if rule.raw.get("use_keyword_postfix").and_then(Value::as_bool).unwrap_or(true) && !field.ends_with(".keyword") {
        format!("{field}.keyword")
    } else {
        field.to_string()
    }
}

impl NewTerm {
    fn new(rule: &Rule) -> Result<Self> {
        let raw = rule.raw.get("fields").or(rule.raw.get("query_key")).cloned().unwrap_or(Value::Null);
        let list = match raw {
            Value::Array(a) => a,
            Value::String(s) => vec![Value::String(s)],
            _ => anyhow::bail!("fields or query_key must be specified"),
        };
        if list.is_empty() {
            anyhow::bail!("fields must not be an empty list");
        }
        let fields: Vec<Vec<String>> = list
            .iter()
            .map(|f| match f {
                Value::Array(sub) => sub.iter().map(py_str).collect(),
                other => vec![py_str(other)],
            })
            .collect();
        Ok(NewTerm { seen: vec![FxHashSet::default(); fields.len()], fields, ready: false })
    }

    /// Loads every value seen in the last `terms_window_size` (30 days) with composite aggregations.
    async fn init(&mut self, rule: &Rule, es: &Es, end: Option<Ts>) -> Result<()> {
        if self.ready {
            return Ok(());
        }
        let window = rule.raw.get("terms_window_size").map(crate::time::parse_duration_map).transpose()?.unwrap_or(30 * 24 * 60 * crate::time::MINUTE);
        let end = end.unwrap_or_else(crate::time::now);
        let start = end - window;
        let index = if rule.use_strftime_index { crate::index::format_index(&rule.index, start, end, rule.search_extra_index)? } else { rule.index.clone() };
        let mut must = vec![json!({"range": {&rule.timestamp_field: {"lt": ts_value(rule, end), "gte": ts_value(rule, start)}}})];
        must.extend(rule.filter.iter().map(|f| f.get("query").cloned().unwrap_or_else(|| f.clone())));
        for (i, fields) in self.fields.iter().enumerate() {
            let sources: Vec<Value> = fields.iter().enumerate().map(|(n, f)| json!({format!("f{n}"): {"terms": {"field": kw(f, rule)}}})).collect();
            let mut after: Option<Value> = None;
            loop {
                let mut comp = json!({"size": 1000, "sources": sources});
                if let Some(a) = &after {
                    comp["after"] = a.clone();
                }
                let body = json!({"size": 0, "query": {"bool": {"filter": must}}, "aggs": {"values": {"composite": comp}}});
                let resp = es.search(&index, &body).await.map_err(|e| anyhow::anyhow!("Error searching for existing terms: {e:#}"))?;
                let buckets = resp["aggregations"]["values"]["buckets"].as_array().cloned().unwrap_or_default();
                for b in &buckets {
                    let vals: Vec<Value> = (0..fields.len()).map(|n| b["key"][format!("f{n}")].clone()).collect();
                    self.seen[i].insert(if fields.len() == 1 { vals[0].to_string() } else { Value::Array(vals).to_string() });
                }
                after = resp["aggregations"]["values"].get("after_key").cloned().filter(|_| !buckets.is_empty());
                if after.is_none() {
                    break;
                }
            }
            log::info!("Found {} unique values for {}", self.seen[i].len(), fields.join(","));
        }
        self.ready = true;
        Ok(())
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        let alert_missing = opt_bool(rule, "alert_on_missing_field");
        for ev in events {
            for (i, fields) in self.fields.iter().enumerate() {
                let vals: Vec<Option<&Value>> = fields.iter().map(|f| field::lookup(&ev.doc, f)).collect();
                let key = if fields.len() == 1 {
                    vals[0].filter(|v| truthy(Some(v))).map(Value::to_string)
                } else if vals.iter().all(|v| truthy(*v)) {
                    Some(Value::Array(vals.iter().map(|v| (*v).cloned().unwrap_or(Value::Null)).collect()).to_string())
                } else {
                    None
                };
                let name = if fields.len() == 1 { json!(fields[0]) } else { json!(fields) };
                match key {
                    None if alert_missing => {
                        let mut m = ev.doc.clone();
                        m.insert("missing_field".into(), name);
                        matches.push(into_match(rule, Event { ts: ev.ts, doc: m }));
                    }
                    Some(k) if !self.seen[i].contains(&k) => {
                        let mut m = ev.doc.clone();
                        m.insert("new_field".into(), name);
                        matches.push(into_match(rule, Event { ts: ev.ts, doc: m }));
                        self.seen[i].insert(k);
                    }
                    _ => {}
                }
            }
        }
    }
}

// ---- cardinality ----

pub struct Cardinality {
    field: String,
    max: Option<f64>,
    min: Option<f64>,
    cache: FxHashMap<String, FxHashMap<String, Ts>>,
    first_event: FxHashMap<String, Ts>,
}

impl Cardinality {
    fn new(rule: &Rule) -> Self {
        Cardinality {
            field: rule.raw.get("cardinality_field").map(py_str).unwrap_or_default(),
            max: opt_f64(rule, "max_cardinality"),
            min: opt_f64(rule, "min_cardinality"),
            cache: FxHashMap::default(),
            first_event: FxHashMap::default(),
        }
    }

    fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Doc>) {
        for ev in events {
            let key = group_key(rule, &ev.doc);
            self.cache.entry(key.clone()).or_default();
            self.first_event.entry(key.clone()).or_insert(ev.ts);
            let Some(v) = field::lookup(&ev.doc, &self.field).filter(|v| !v.is_null()) else { continue };
            self.cache.get_mut(&key).expect("inserted").insert(v.to_string(), ev.ts);
            self.check(rule, &key, ev.ts, Some(&ev.doc), true, matches);
        }
    }

    fn check(&mut self, rule: &Rule, key: &str, ts: Ts, doc: Option<&Doc>, gc: bool, matches: &mut Vec<Doc>) {
        let elapsed = ts - self.first_event.get(key).copied().unwrap_or(ts);
        let n = self.cache.get(key).map_or(0, |c| c.len()) as f64;
        let over = self.max.is_some_and(|m| n > m);
        let under = self.min.is_some_and(|m| n < m) && elapsed > tf(rule);
        if over || under {
            if gc {
                self.garbage_collect(rule, ts, matches);
                self.check(rule, key, ts, doc, false, matches);
            } else {
                self.first_event.remove(key);
                let mut d = doc.cloned().unwrap_or_default();
                d.entry(rule.timestamp_field.clone()).or_insert_with(|| json!(to_iso(ts)));
                matches.push(into_match(rule, Event { ts, doc: d }));
            }
        }
    }

    fn garbage_collect(&mut self, rule: &Rule, ts: Ts, matches: &mut Vec<Doc>) {
        let keys: Vec<String> = self.cache.keys().cloned().collect();
        for qk in keys {
            if let Some(terms) = self.cache.get_mut(&qk) {
                terms.retain(|_, last| ts - *last <= tf(rule));
            }
            if self.min.is_some() {
                let mut ph = Doc::from_iter([(rule.timestamp_field.clone(), json!(to_iso(ts)))]);
                if let Some(q) = &rule.query_key {
                    ph.insert(q.clone(), key_value(&qk));
                }
                self.check(rule, &qk, ts, Some(&ph), false, matches);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: Ts) -> Event {
        Event { ts, doc: Doc::new() }
    }

    #[test]
    fn window_evicts_at_timeframe() {
        let mut w = EventWindow::new(10);
        w.append(ev(0), 1);
        w.append(ev(5), 1);
        assert_eq!(w.count(), 2);
        let gone = w.append(ev(10), 1); // span 10 >= 10 -> evict ts 0
        assert_eq!(gone.len(), 1);
        assert_eq!(w.count(), 2);
        w.append(ev(7), 1); // out of order insert
        assert_eq!(w.data.iter().map(|(e, _)| e.ts).collect::<Vec<_>>(), vec![5, 7, 10]);
    }

    #[test]
    fn python_truthiness() {
        assert!(!truthy(Some(&json!(0))));
        assert!(!truthy(Some(&json!(""))));
        assert!(truthy(Some(&json!("a"))));
        assert!(!truthy(None));
    }
}
