mod alert;
mod alerters;
mod config;
mod engine;
mod es;
mod field;
mod index;
mod rule;
mod setup;
mod time;
mod types;
mod writeback;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use config::Config;
use engine::{Ctx, Pending, RuleState, Silences};
use es::Es;
use rustc_hash::FxHashMap;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::{Ts, now, parse_iso, to_iso};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use writeback::Writeback;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// ElastAlert-compatible alerting daemon for Elasticsearch / OpenSearch.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Global config file
    #[arg(long, default_value = "config.yaml", global = true)]
    config: PathBuf,
    /// Log alerts instead of sending them; nothing is written to ES
    #[arg(long)]
    debug: bool,
    /// Log at info level without suppressing alerts
    #[arg(long)]
    verbose: bool,
    /// Run only this rule (file name inside the rules folder, or a path)
    #[arg(long)]
    rule: Option<String>,
    /// Silence the rule for a period, e.g. hours=2 (needs --rule)
    #[arg(long)]
    silence: Option<String>,
    /// Silence only this query_key value
    #[arg(long = "silence_qk_value")]
    silence_qk_value: Option<String>,
    /// Start querying from this ISO timestamp, or NOW
    #[arg(long)]
    start: Option<String>,
    /// Query up to this ISO timestamp, then exit
    #[arg(long)]
    end: Option<String>,
    /// Wait up to this long for ES and the writeback index, e.g. minutes=5
    #[arg(long = "patience")]
    patience: Option<String>,
    /// Do not reload rule files when they change
    #[arg(long = "pin_rules")]
    pin_rules: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the writeback indices (with the mappings the daemon relies on)
    CreateIndex {
        /// Index name (default: writeback_index from the config)
        #[arg(long)]
        index: Option<String>,
        /// Copy the data of this existing index into the new one
        #[arg(long = "old-index")]
        old_index: Option<String>,
        /// Delete and recreate existing indices (data loss)
        #[arg(long)]
        recreate: bool,
    },
}

struct Logger(log::LevelFilter);

impl log::Log for Logger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= self.0
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!("{}:elastalert:{}", r.level().as_str().replace("WARN", "WARNING"), r.args());
        }
    }
    fn flush(&self) {}
}

fn parse_time_arg(s: &str) -> Result<Ts> {
    if s == "NOW" {
        return Ok(now());
    }
    parse_iso(s).with_context(|| format!("{s} is not a valid ISO8601 timestamp (YYYY-MM-DDTHH:MM:SS+XX:00)"))
}

async fn wait_until_responsive(es: &Es, index: &str, patience: time::Dur) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_micros(patience as u64);
    while std::time::Instant::now() < deadline {
        if es.exists(index).await.unwrap_or(false) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("writeback index \"{index}\" not reachable; is ES up and did you run `elastalert create-index`?")
}

/// `--silence`: write a silence doc and exit.
async fn silence(args: &Args, rule: &rule::Rule, es: &Es, index: &str) -> Result<()> {
    if args.debug {
        bail!("--silence not compatible with --debug");
    }
    let until = now() + time::parse_duration_arg(args.silence.as_deref().unwrap_or_default())?;
    let key = match &args.silence_qk_value {
        Some(v) => format!("{}.{v}", rule.realert_key),
        None => format!("{}._silence", rule.name),
    };
    let doc = json!({"exponent": 0, "rule_name": key, "@timestamp": to_iso(now()), "until": to_iso(until)});
    es.post(&format!("{index}_silence/_doc?refresh=true"), &doc).await.context("Failed to save silence command to Elasticsearch")?;
    log::info!("Success. {key} will be silenced until {}", to_iso(until));
    Ok(())
}

/// Loads every active silence from ES into memory (startup, then every maintenance tick so that
/// `--silence` from another process takes effect).
async fn refresh_silences(ctx: &Ctx, index: &str) {
    let body = json!({"query": {"range": {"until": {"gt": "now"}}}, "size": 10000});
    match ctx.es.search(&format!("{index}_silence"), &body).await {
        Ok(r) => {
            for h in r["hits"]["hits"].as_array().into_iter().flatten() {
                let s = &h["_source"];
                if let (Some(name), Some(until)) = (s["rule_name"].as_str(), s["until"].as_str().and_then(parse_iso)) {
                    ctx.silences.raise(name, until, s["exponent"].as_u64().unwrap_or(0) as u32);
                }
            }
        }
        Err(e) => log::warn!("Error reading silences from Elasticsearch: {e:#}"),
    }
}

/// Alerts that were not fully sent before the last shutdown are queued again.
async fn recover_pending(ctx: &Ctx, index: &str, states: &mut [RuleState]) {
    let body = json!({"query": {"bool": {
        "filter": [{"term": {"alert_sent": false}}, {"range": {"alert_time": {"gte": to_iso(now() - ctx.alert_time_limit), "lte": to_iso(now())}}}],
        "must_not": [{"exists": {"field": "aggregate_id"}}, {"exists": {"field": "aggregation_key"}}],
    }}});
    let hits = match ctx.es.scan(index, &body, "1m").await {
        Ok(h) => h,
        Err(e) => return log::warn!("Error finding recent pending alerts: {e:#}"),
    };
    let mut recovered = 0;
    for h in hits {
        let s = &h["_source"];
        let (Some(name), Some(body)) = (s["rule_name"].as_str(), s["match_body"].as_object()) else { continue };
        let Some(st) = states.iter_mut().find(|st| st.rule.name == name) else { continue };
        let sent: Vec<&str> = s["alerters_sent"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        st.pending.push(Pending {
            id: h["_id"].as_str().unwrap_or_default().to_string(),
            matches: vec![body.clone()],
            done: st.rule.alerts.iter().map(|k| sent.contains(&k.as_str())).collect(),
            attempts: s["retry_count"].as_u64().unwrap_or(0) as u32,
            next_try: 0,
            alert_time: s["alert_time"].as_str().and_then(parse_iso).unwrap_or_else(now),
            exception: s["alert_exception"].as_str().unwrap_or_default().to_string(),
        });
        recovered += 1;
    }
    if recovered > 0 {
        log::info!("Recovered {recovered} unsent alert(s) from the writeback index");
    }
}

/// Runs one rule forever on its `run_every` schedule until `stop` flips; hands the state back.
async fn rule_task(
    mut st: RuleState,
    ctx: Arc<Ctx>,
    sem: Arc<Semaphore>,
    mut stop: watch::Receiver<bool>,
    mut initial: Option<Ts>,
    first_delay: Duration,
) -> RuleState {
    tokio::select! {
        _ = tokio::time::sleep(first_delay) => {}
        _ = stop.changed() => return st,
    }
    loop {
        let next = tokio::time::Instant::now() + Duration::from_micros(st.rule.run_every.max(time::SECOND) as u64);
        {
            let _permit = sem.acquire().await;
            let end = now() - st.rule.query_delay;
            if let Err(e) = st.run(&ctx, end, initial.take()).await {
                ctx.writeback.error(format!("Error running rule {}: {e:#}", st.rule.name), json!({"rule": st.rule.name})).await;
            }
        }
        st.forget_old_hits();
        if tokio::time::Instant::now() > next {
            log::warn!("Rule {} took longer than its run_every to process", st.rule.name);
        }
        let jitter = Duration::from_millis(pseudo_random(5_000));
        tokio::select! {
            _ = tokio::time::sleep_until(next + jitter) => {}
            _ = stop.changed() => return st,
        }
    }
}

fn pseudo_random(max_ms: u64) -> u64 {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos();
    (nanos as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) % max_ms.max(1)
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}

/// A rule file being watched: its content hash and, unless disabled, its running task.
struct Running {
    hash: u64,
    name: String,
    task: Option<(watch::Sender<bool>, JoinHandle<RuleState>)>,
}

impl Running {
    async fn stop(&mut self) -> Option<RuleState> {
        let (tx, handle) = self.task.take()?;
        let _ = tx.send(true);
        handle.await.ok()
    }
}

struct Runtime {
    ctx: Arc<Ctx>,
    sem: Arc<Semaphore>,
    running: FxHashMap<PathBuf, Running>,
}

impl Runtime {
    fn spawn(&mut self, st: RuleState, initial: Option<Ts>, delay: Duration) -> (watch::Sender<bool>, JoinHandle<RuleState>) {
        let (tx, rx) = watch::channel(false);
        let h = tokio::spawn(rule_task(st, self.ctx.clone(), self.sem.clone(), rx, initial, delay));
        (tx, h)
    }

    /// Syncs running rules with the files on disk: removed -> stop, changed -> reload keeping state, new -> start.
    async fn reload(&mut self, conf: &Config, only: Option<&str>) {
        let files = match rule::discover(conf, only) {
            Ok(f) => f,
            Err(e) => return log::error!("Error scanning rules folder: {e:#}"),
        };
        let current: FxHashMap<PathBuf, u64> = files.into_iter().map(|f| (rule::file_hash(&f), f)).map(|(h, f)| (f, h)).collect();
        let gone: Vec<PathBuf> = self.running.keys().filter(|p| !current.contains_key(*p)).cloned().collect();
        for path in gone {
            log::info!("Rule file {} not found, stopping rule execution", path.display());
            if let Some(mut r) = self.running.remove(&path) {
                r.stop().await;
            }
        }
        for (path, hash) in current {
            if self.running.get(&path).is_some_and(|r| r.hash == hash) {
                continue;
            }
            let is_new = !self.running.contains_key(&path);
            let loaded = rule::load(&path, conf).and_then(|r| {
                if self.running.iter().any(|(p, x)| *p != path && x.name == r.name) {
                    bail!("A rule with the name {} already exists", r.name);
                }
                Ok(r)
            });
            let rule = match loaded {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("Could not load rule {}: {e:#}", path.display());
                    self.ctx.writeback.error(msg, json!({})).await;
                    if let Some(r) = self.running.get_mut(&path) {
                        r.hash = hash; // keep the old version running; don't complain every cycle
                    }
                    continue;
                }
            };
            let name = rule.name.clone();
            if rule.raw.get("is_enabled").and_then(Value::as_bool) == Some(false) {
                log::info!("Rule file {} is now disabled.", path.display());
                if let Some(mut r) = self.running.remove(&path) {
                    r.stop().await;
                }
                self.running.insert(path, Running { hash, name, task: None });
                continue;
            }
            let mut st = match RuleState::new(rule) {
                Ok(s) => s,
                Err(e) => {
                    self.ctx.writeback.error(format!("Could not load rule {}: {e:#}", path.display()), json!({})).await;
                    continue;
                }
            };
            if let Some(mut old) = self.running.remove(&path) {
                log::info!("Reloading configuration for rule {}", path.display());
                if let Some(old_state) = old.stop().await {
                    st.carry_over(old_state);
                }
            } else {
                log::info!("Loaded new rule {}", path.display());
            }
            let delay = if is_new { Duration::from_millis(pseudo_random(15_000)) } else { Duration::ZERO };
            let task = self.spawn(st, None, delay);
            self.running.insert(path, Running { hash, name, task: Some(task) });
        }
    }

    async fn stop_all(&mut self) {
        for (_, mut r) in self.running.drain() {
            r.stop().await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level = if args.debug || args.verbose { log::LevelFilter::Info } else { log::LevelFilter::Warn };
    log::set_logger(Box::leak(Box::new(Logger(level)))).expect("logger set once");
    log::set_max_level(level);

    let conf = Config::load(&args.config)?;
    let es = Es::from_conf(&conf.raw)?;

    if let Some(Cmd::CreateIndex { index, old_index, recreate }) = &args.cmd {
        let index = index.as_deref().unwrap_or(&conf.writeback_index);
        return setup::create_index(&es, index, *recreate, old_index.as_deref()).await;
    }
    if args.debug {
        log::info!("Note: In debug mode, alerts will be logged to console but NOT actually sent. To send them but remain verbose, use --verbose instead.");
    }

    let rules = rule::load_all(&conf, args.rule.as_deref())?;
    let (wb, wb_handle) = Writeback::start((!args.debug).then(|| es.clone()), conf.writeback_index.clone());
    let ctx = Arc::new(Ctx {
        es: es.clone(),
        writeback: wb,
        silences: Arc::new(Silences::default()),
        debug: args.debug,
        old_query_limit: conf.old_query_limit,
        alert_time_limit: conf.alert_time_limit,
        scroll_keepalive: conf.scroll_keepalive.clone(),
        ts_fmt: conf.custom_pretty_ts_format.clone(),
    });

    if args.silence.is_some() {
        let Some(rule) = rules.first().filter(|_| args.rule.is_some()) else { bail!("--silence must be used with --rule") };
        return silence(&args, rule, &es, &conf.writeback_index).await;
    }
    if let Some(p) = &args.patience {
        wait_until_responsive(&es, &conf.writeback_index, time::parse_duration_arg(p)?).await?;
    }
    let start = args.start.as_deref().map(parse_time_arg).transpose()?;
    let end = args.end.as_deref().map(parse_time_arg).transpose()?;

    let mut states = Vec::new();
    let mut hashes = Vec::new();
    for r in rules {
        hashes.push((r.file.clone(), rule::file_hash(&r.file)));
        match RuleState::new(r) {
            Ok(s) => states.push(s),
            Err(e) if conf.skip_invalid => log::error!("Invalid rule skipped: {e:#}"),
            Err(e) => bail!("{e:#}"),
        }
    }
    if !args.debug {
        refresh_silences(&ctx, &conf.writeback_index).await;
        recover_pending(&ctx, &conf.writeback_index, &mut states).await;
    }
    log::info!("Starting up");

    let sem = Arc::new(Semaphore::new(conf.max_threads.max(1)));
    if let Some(end) = end {
        // Bounded replay: one run per rule over [start, end], then exit.
        let mut tasks = tokio::task::JoinSet::new();
        for mut st in states {
            let (ctx, sem) = (ctx.clone(), sem.clone());
            tasks.spawn(async move {
                let _permit = sem.acquire().await;
                if let Err(e) = st.run(&ctx, end, start).await {
                    ctx.writeback.error(format!("Error running rule {}: {e:#}", st.rule.name), json!({"rule": st.rule.name})).await;
                }
            });
        }
        while tasks.join_next().await.is_some() {}
    } else {
        let mut rt = Runtime { ctx: ctx.clone(), sem, running: FxHashMap::default() };
        for st in states {
            let path = st.rule.file.clone();
            let hash = hashes.iter().find(|(p, _)| *p == path).map_or(0, |(_, h)| *h);
            let name = st.rule.name.clone();
            let task = rt.spawn(st, start, Duration::from_millis(pseudo_random(15_000)));
            rt.running.insert(path, Running { hash, name, task: Some(task) });
        }
        let period = Duration::from_micros(conf.run_every.max(time::SECOND) as u64);
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        let stop = shutdown_signal();
        tokio::pin!(stop);
        loop {
            tokio::select! {
                _ = &mut stop => break,
                _ = tick.tick() => {
                    if !args.debug {
                        refresh_silences(&ctx, &conf.writeback_index).await;
                    }
                    if !args.pin_rules {
                        rt.reload(&conf, args.rule.as_deref()).await;
                    }
                }
            }
        }
        log::info!("Stopping: finishing running rules and flushing writeback");
        rt.stop_all().await;
    }

    drop(ctx);
    if let Some(h) = wb_handle {
        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
    Ok(())
}
