//! Prometheus metrics (same names as upstream, `--prometheus_port`). Hand-rolled text exposition:
//! eight counters, no dependency.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default, Clone)]
pub struct RuleCounters {
    pub scrapes: u64,
    pub hits: u64,
    pub matches: u64,
    pub time_taken: f64,
    pub alerts_sent: u64,
    pub alerts_not_sent: u64,
    pub alerts_silenced: u64,
}

#[derive(Default)]
pub struct Metrics {
    rules: Mutex<BTreeMap<String, RuleCounters>>,
    errors: AtomicU64,
}

impl Metrics {
    pub fn rule(&self, name: &str, f: impl FnOnce(&mut RuleCounters)) {
        f(self.rules.lock().unwrap().entry(name.to_string()).or_default());
    }

    pub fn error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Prometheus text format. Counter names end in `_total` like prometheus_client's.
    pub fn render(&self) -> String {
        let rules = self.rules.lock().unwrap();
        let mut out = String::new();
        let mut family = |name: &str, help: &str, value: &dyn Fn(&RuleCounters) -> String| {
            let _ = writeln!(out, "# HELP {name}_total {help}\n# TYPE {name}_total counter");
            for (rule, c) in rules.iter() {
                let _ = writeln!(out, "{name}_total{{rule_name=\"{}\"}} {}", rule.replace('\\', "\\\\").replace('"', "\\\""), value(c));
            }
        };
        family("elastalert_scrapes", "Number of scrapes for rule", &|c| c.scrapes.to_string());
        family("elastalert_hits", "Number of hits for rule", &|c| c.hits.to_string());
        family("elastalert_matches", "Number of matches for rule", &|c| c.matches.to_string());
        family("elastalert_time_taken", "Time taken to evaluate rule", &|c| c.time_taken.to_string());
        family("elastalert_alerts_sent", "Number of alerts sent for rule", &|c| c.alerts_sent.to_string());
        family("elastalert_alerts_not_sent", "Number of alerts not sent", &|c| c.alerts_not_sent.to_string());
        family("elastalert_alerts_silenced", "Number of silenced alerts", &|c| c.alerts_silenced.to_string());
        let _ = writeln!(out, "# HELP elastalert_errors_total Number of errors for rule\n# TYPE elastalert_errors_total counter\nelastalert_errors_total {}", self.errors.load(Ordering::Relaxed));
        out
    }
}

/// Serves `/metrics` (any path) until the process exits.
pub async fn serve(addr: String, metrics: std::sync::Arc<Metrics>) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    log::info!("Prometheus metrics on http://{addr}/metrics");
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { continue };
            let m = metrics.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), sock.read(&mut buf)).await;
                let body = m.render();
                let head = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
            });
        }
    });
    Ok(())
}
