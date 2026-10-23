//! Rule types: they receive query results and emit matches.

use crate::field;
use crate::rule::{Kind, Rule, TsType};
use crate::time::{Dur, Ts, pretty, to_iso};
use rustc_hash::FxHashMap;
use serde_json::{Map, Value, json};
use std::collections::VecDeque;

/// One hit from Elasticsearch with its parsed timestamp.
pub struct Event {
    pub ts: Ts,
    pub doc: Map<String, Value>,
}

/// Time-ordered events covering at most `timeframe`. Oldest are evicted on append.
pub struct EventWindow {
    timeframe: Dur,
    data: VecDeque<(Event, u64)>,
    count: u64,
}

impl EventWindow {
    pub fn new(timeframe: Dur) -> Self {
        EventWindow { timeframe, data: VecDeque::new(), count: 0 }
    }

    /// Inserts in timestamp order (after equal timestamps) and evicts while the span >= timeframe.
    /// Returns what was evicted, oldest first.
    pub fn append(&mut self, ev: Event, count: u64) -> Vec<(Event, u64)> {
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

    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn last_ts(&self) -> Option<Ts> {
        self.data.back().map(|(e, _)| e.ts)
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

fn into_match(rule: &Rule, mut ev: Event) -> Map<String, Value> {
    field::set(&mut ev.doc, &rule.timestamp_field, ts_value(rule, ev.ts));
    ev.doc
}

/// Key used to group events by `query_key`. JSON text keeps `1` and `"1"` apart, like Python dict keys.
fn group_key(rule: &Rule, doc: &Map<String, Value>) -> String {
    match &rule.query_key {
        Some(qk) => field::lookup(doc, qk).map_or_else(|| "null".into(), Value::to_string),
        None => "all".into(),
    }
}

pub enum RuleType {
    Any,
    Frequency { occurrences: FxHashMap<String, EventWindow> },
}

impl RuleType {
    pub fn new(rule: &Rule) -> Self {
        match rule.kind {
            Kind::Any => RuleType::Any,
            Kind::Frequency => RuleType::Frequency { occurrences: FxHashMap::default() },
        }
    }

    pub fn add_data(&mut self, rule: &Rule, events: Vec<Event>, matches: &mut Vec<Map<String, Value>>) {
        match self {
            RuleType::Any => matches.extend(events.into_iter().map(|e| into_match(rule, e))),
            RuleType::Frequency { occurrences } => {
                let timeframe = rule.timeframe.unwrap_or_default();
                for ev in events {
                    let key = group_key(rule, &ev.doc);
                    let window = occurrences.entry(key.clone()).or_insert_with(|| EventWindow::new(timeframe));
                    window.append(ev, 1);
                    if window.count() >= rule.num_events {
                        let mut w = occurrences.remove(&key).expect("window just used");
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
    }

    /// Drops state older than `timeframe` before `now_ts` (the end of the queried range).
    pub fn garbage_collect(&mut self, rule: &Rule, now_ts: Ts) {
        if let RuleType::Frequency { occurrences } = self {
            let tf = rule.timeframe.unwrap_or_default();
            occurrences.retain(|_, w| w.last_ts().is_some_and(|t| now_ts - t <= tf));
        }
    }

    /// The type-specific sentence in the alert body.
    pub fn match_str(&self, rule: &Rule, m: &Map<String, Value>, ts_fmt: Option<&str>) -> String {
        match self {
            RuleType::Any => String::new(),
            RuleType::Frequency { .. } => {
                let Some(ts) = field::lookup(m, &rule.timestamp_field).and_then(|v| parse_ts(rule, v)) else {
                    return String::new();
                };
                let start = pretty(ts - rule.timeframe.unwrap_or_default(), rule.use_local_time, ts_fmt);
                let end = pretty(ts, rule.use_local_time, ts_fmt);
                format!("At least {} events occurred between {start} and {end}\n\n", rule.num_events)
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(ts: Ts) -> Event {
        Event { ts, doc: Map::new() }
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
}
