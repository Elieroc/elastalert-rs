mod alert;
mod config;
mod engine;
mod es;
mod field;
mod rule;
mod time;
mod types;
mod writeback;

use anyhow::{Context, Result, bail};
use clap::Parser;
use config::Config;
use engine::{Ctx, RuleState, Silences};
use es::Es;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use time::{Ts, now, parse_iso, to_iso};
use tokio::sync::{Semaphore, watch};
use writeback::{Kind, Writeback};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// ElastAlert-compatible alerting daemon for Elasticsearch / OpenSearch.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Global config file
    #[arg(long, default_value = "config.yaml")]
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
    /// Do not reload rule files when they change (reload is not implemented yet)
    #[arg(long = "pin_rules")]
    pin_rules: bool,
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
    bail!("writeback index \"{index}\" not reachable; is ES up and did you create the index?")
}

async fn silence(args: &Args, rules: &[engine::RuleState], ctx: &Ctx, wb_handle: Option<tokio::task::JoinHandle<()>>) -> Result<()> {
    if args.debug {
        bail!("--silence not compatible with --debug");
    }
    let (Some(_), Some(rule)) = (&args.rule, rules.first()) else { bail!("--silence must be used with --rule") };
    let until = now() + time::parse_duration_arg(args.silence.as_deref().unwrap_or_default())?;
    let key = match &args.silence_qk_value {
        Some(v) => format!("{}.{v}", rule.rule.realert_key),
        None => format!("{}._silence", rule.rule.name),
    };
    let doc = json!({"exponent": 0, "rule_name": key, "@timestamp": to_iso(now()), "until": to_iso(until)});
    let index = ctx.writeback.index_for(Kind::Silence);
    ctx.es
        .post(&format!("{index}/_doc?refresh=true"), &doc)
        .await
        .context("Failed to save silence command to Elasticsearch")?;
    drop(wb_handle);
    log::info!("Success. {key} will be silenced until {}", to_iso(until));
    Ok(())
}

/// Runs one rule forever on its `run_every` schedule until `stop` flips.
async fn rule_task(mut st: RuleState, ctx: Arc<Ctx>, sem: Arc<Semaphore>, mut stop: watch::Receiver<bool>, mut initial: Option<Ts>, first_delay: Duration) {
    tokio::select! {
        _ = tokio::time::sleep(first_delay) => {}
        _ = stop.changed() => return,
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
            _ = stop.changed() => return,
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let level = if args.debug || args.verbose { log::LevelFilter::Info } else { log::LevelFilter::Warn };
    log::set_logger(Box::leak(Box::new(Logger(level)))).expect("logger set once");
    log::set_max_level(level);
    if args.debug {
        log::info!("Note: In debug mode, alerts will be logged to console but NOT actually sent. To send them but remain verbose, use --verbose instead.");
    }

    let conf = Config::load(&args.config)?;
    let rules = rule::load_all(&conf, args.rule.as_deref())?;
    if !args.debug {
        for r in &rules {
            if let Some(a) = r.alerts.iter().find(|a| a.as_str() != "debug") {
                bail!("rule {}: alerter '{a}' is not supported yet (run with --debug to test the rule)", r.name);
            }
        }
    }
    let es = Es::from_conf(&conf.raw)?;
    let (wb, wb_handle) = Writeback::start((!args.debug).then(|| es.clone()), conf.writeback_index.clone());
    let ctx = Arc::new(Ctx {
        es: es.clone(),
        writeback: wb,
        silences: Arc::new(Silences::default()),
        debug: args.debug,
        old_query_limit: conf.old_query_limit,
        scroll_keepalive: conf.scroll_keepalive.clone(),
        ts_fmt: conf.custom_pretty_ts_format.clone(),
    });
    let states: Vec<RuleState> = rules.into_iter().map(RuleState::new).collect();

    if args.silence.is_some() {
        return silence(&args, &states, &ctx, wb_handle).await;
    }
    if let Some(p) = &args.patience {
        wait_until_responsive(&es, &conf.writeback_index, time::parse_duration_arg(p)?).await?;
    }
    let start = args.start.as_deref().map(parse_time_arg).transpose()?;
    let end = args.end.as_deref().map(parse_time_arg).transpose()?;
    log::info!("Starting up");

    let sem = Arc::new(Semaphore::new(conf.max_threads.max(1)));
    let mut tasks = tokio::task::JoinSet::new();
    if let Some(end) = end {
        // Bounded replay: one run per rule over [start, end], then exit.
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
        let (stop_tx, stop_rx) = watch::channel(false);
        for st in states {
            let delay = Duration::from_millis(pseudo_random(15_000));
            tasks.spawn(rule_task(st, ctx.clone(), sem.clone(), stop_rx.clone(), start, delay));
        }
        shutdown_signal().await;
        log::info!("Stopping: finishing running rules and flushing writeback");
        let _ = stop_tx.send(true);
        while tasks.join_next().await.is_some() {}
    }

    drop(ctx);
    if let Some(h) = wb_handle {
        let _ = tokio::time::timeout(Duration::from_secs(10), h).await;
    }
    Ok(())
}
