//! Writeback: every status/alert/silence/error doc goes through one task that sends `_bulk`
//! requests (every second or 500 docs). Ids are generated here, so retries can't duplicate.

use crate::es::Es;
use crate::time::{now, to_iso};
use serde_json::{Map, Value, json};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const BATCH: usize = 500;
/// Docs kept for retry while ES is unreachable; beyond this the oldest are dropped.
const MAX_BUFFER: usize = 50_000;

#[derive(Clone, Copy)]
pub enum Kind {
    Alert,
    Status,
    Silence,
    Error,
}

#[derive(Clone)]
pub struct Writeback {
    tx: Option<mpsc::Sender<(String, Value)>>,
    index: String,
}

impl Writeback {
    /// `es = None` (debug mode) logs the docs instead of writing them.
    pub fn start(es: Option<Es>, index: String) -> (Writeback, Option<JoinHandle<()>>) {
        let Some(es) = es else { return (Writeback { tx: None, index }, None) };
        let (tx, rx) = mpsc::channel(10_000);
        let handle = tokio::spawn(run(es, rx));
        (Writeback { tx: Some(tx), index }, Some(handle))
    }

    pub fn index_for(&self, kind: Kind) -> String {
        let suffix = match kind {
            Kind::Alert => "",
            Kind::Status => "_status",
            Kind::Silence => "_silence",
            Kind::Error => "_error",
        };
        format!("{}{suffix}", self.index)
    }

    pub async fn write(&self, kind: Kind, mut doc: Map<String, Value>) {
        doc.entry("@timestamp").or_insert_with(|| json!(to_iso(now())));
        match &self.tx {
            None => log::info!("Skipping writing to ES: {}", Value::Object(doc)),
            Some(tx) => {
                let _ = tx.send((self.index_for(kind), Value::Object(doc))).await;
            }
        }
    }

    /// Logs the error and records it in the `_error` index.
    pub async fn error(&self, message: String, data: Value) {
        log::error!("{message}");
        let mut doc = Map::new();
        doc.insert("message".into(), json!(message));
        doc.insert("traceback".into(), json!([]));
        if !data.is_null() {
            doc.insert("data".into(), data);
        }
        self.write(Kind::Error, doc).await;
    }
}

async fn run(es: Es, mut rx: mpsc::Receiver<(String, Value)>) {
    let mut buf: Vec<String> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        let open = tokio::select! {
            msg = rx.recv() => match msg {
                Some((index, doc)) => {
                    let id = uuid::Uuid::now_v7();
                    buf.push(format!("{}\n{}\n", json!({"create": {"_index": index, "_id": id.to_string()}}), doc));
                    if buf.len() < BATCH { continue }
                    true
                }
                None => false,
            },
            _ = tick.tick() => true,
        };
        while !buf.is_empty() {
            let n = buf.len().min(BATCH);
            match es.bulk(buf[..n].concat()).await {
                Ok(resp) => {
                    if resp["errors"] == json!(true) {
                        let first = resp["items"].as_array().and_then(|items| {
                            items.iter().find_map(|i| i["create"]["error"].as_object().filter(|_| i["create"]["status"] != json!(409)))
                        });
                        if let Some(e) = first {
                            log::error!("Error writing to writeback index: {}", Value::Object(e.clone()));
                        }
                    }
                    buf.drain(..n);
                }
                Err(e) => {
                    log::error!("Error writing to Elasticsearch writeback (will retry): {e:#}");
                    if buf.len() > MAX_BUFFER {
                        buf.drain(..buf.len() - MAX_BUFFER);
                    }
                    if open {
                        break;
                    }
                    return; // shutting down and ES is down: give up
                }
            }
        }
        if !open {
            return;
        }
    }
}
