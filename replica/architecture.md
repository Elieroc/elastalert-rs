# Architecture: elastalert-rs (Rust rebuild of ElastAlert 2 core, performance-first)

Input: `replica/recon.md`, `replica/features.csv`. Goal from user: rewrite in Rust, fix the original's weaknesses, maximise performance.
Contract: existing ElastAlert 2 rule YAML + `config.yaml` run unchanged; writeback docs keep the same shapes (new fields additive only).

Assumptions (recon open questions, defaults taken, change if wrong):
- Targets: Elasticsearch 7.10+, 8.x, OpenSearch 2.x. ES 6 dropped.
- Rust daemon **replaces** Python ElastAlert. It reads Python's writeback state at startup (switch-over works), but both must not run at the same time (they would double-alert, same as two Python instances).
- `alert_text` keeps Python `str.format` / `%` semantics (re-implemented subset). Jinja via minijinja.

## Weaknesses of the original (evidence -> fix)

| # | weakness | evidence (elastalert2 source) | fix in elastalert-rs | gain |
| --- | --- | --- | --- | --- |
| W1 | GIL + thread pool of `max_threads` (10): rules queue behind slow ones, CPU work serialised | `elastalert.py:169` ThreadPoolExecutor, apscheduler | tokio tasks, one task per rule; ES concurrency bounded by a semaphore (`max_threads` kept as its size) | 100s of rules on 1-2 cores |
| W2 | Fetches **whole `_source`** for every hit (`include: ['*']` default), even when the rule type only needs ts + query_key | `loaders.py` include default `['*']`, `get_hits` `_source_includes` | per-type field projection computed at load; full doc fetched by `_mget` **only for matches** (+`related_events`). Opt-out `fetch_full_source: true`. User-set `include` is respected | 10-100x less bytes from ES for frequency/spike/flatline/cardinality/new_term/change |
| W3 | Re-reads the whole `buffer_time` window every run (15 min default vs 1 min `run_every`) then dedups by `_id` in a Python dict of strings | `set_starttime` uses `now - buffer_time` while `previous_endtime` is newer; `remove_duplicate_events` | overlap part kept (it catches late docs) but fetched with the minimal projection; dedup set = `FxHashSet<u64>` (hash of `_id`), pruned by ts. Opt-in `ingest_timestamp_field` (e.g. `event.ingested`) queries only docs ingested since last run: no overlap at all | ~15x less read volume with opt-in; ~5x less memory for dedup by default |
| W4 | Scroll API, recursive, capped at 990 pages to dodge Python's stack limit | `run_query` recursion, `max_scrolling_count` comment | PIT + `search_after` (`_shard_doc` tiebreak), iterative; scroll fallback for clusters without PIT. Next page prefetched while current page is processed | no depth cap, no scroll contexts held, pipelined I/O |
| W5 | One HTTP request per writeback doc; silence check queries ES per new key | `writeback()` -> `index()` per doc; `is_silenced` search | single **bulk writer** task (flush every 1 s or 500 docs). `_id` generated client-side (UUIDv7) so no round-trip is needed for aggregate ids. Silence state authoritative in memory, loaded once at startup, written through bulk | writeback cost ~1 request/s instead of N/s |
| W6 | Pending/aggregated alerts: polls ES every `run_every`, `delete_by_query` **per alert and per aggregated child**; 1000-doc page limit | `send_pending_alerts`, `get_aggregated_matches` | pending + aggregation queues in memory (per rule), ES is the durability log: bulk index on enqueue, bulk delete by `_id` on send. One full scan at startup (search_after, no 1000 cap) to rebuild | removes the costliest periodic ES calls |
| W7 | `new_term`: seen values kept in a **list** (`in` = O(n) per event); startup terms agg with `size: 2147483647` per step | `ruletypes.py:914-930`, `get_all_terms` | `FxHashSet` per field; startup uses **composite aggregation** paging; optional local snapshot file to skip re-scan on restart | O(1) lookup; bounded memory at startup |
| W8 | Event windows store full deep-copied docs (`copy.deepcopy`, sortedlist) | `EventWindow`, `add_match`, `FlatlineRule.check_for_match` | windows store compact `(ts_micros: i64, count: u32, doc_ref)`; `VecDeque` with binary-search insert for out-of-order; full doc only at match | memory per event: ~1 KB+ -> ~24 B |
| W9 | Timestamps parsed to Python `datetime` per hit; dotted-key lookup re-split per call | `process_hits`, `lookup_es_key` | ts as `i64` micros UTC; field paths pre-split at rule load; serde borrows from the page buffer | CPU per hit down by an order of magnitude |
| W10 | One failing alerter marks the **whole** alert unsent; retry resends to every alerter -> duplicates | `send_alert` loop, `alert_sent` single flag | per-alerter delivery status stored in the alert doc (`alerters_sent: [..]`, additive field); retry only failed ones, with backoff | no duplicate Slack/email on retry |
| W11 | `SIGINT` -> `os._exit(0)`: in-flight alerts and writeback lost | `handle_signal` | graceful shutdown on SIGINT/SIGTERM: stop scheduling, finish in-flight alerts, flush bulk writer (10 s cap) | no lost state on deploy/restart |
| W12 | Arbitrary code: `eval()` timestamp exprs, `get_module` plugins, `command` with `shell=True` | `loaders.py:398-410`, `util.get_module`, `alerters/command.py` | no eval, no plugins (rule types/alerters are compiled in). `command` string form still supported (compat) but warns; argv list recommended | smaller attack surface |
| W13 | Heavy image: elasticsearch-py pinned 7.10.1, boto3, twilio, tencent SDK, jira... for every install | `requirements.txt` | one static binary; rarely used alerters behind cargo features | ~10 MB binary, ~100 ms start |
| W14 | Rule validation via jsonschema at runtime + scattered `rule.get(...)` with defaults everywhere | `loaders.load_options`, `schema.yaml` | typed serde structs per rule type and alerter, defaults in one place, errors with file:line. Unknown keys warn (upstream rules carry extra keys) | errors at load, not at 3 am |
| W15 | No HA: two instances = double alerts | none | (could) per-rule lease doc in writeback with `if_seq_no` optimistic concurrency | active/standby later |

Not changed on purpose: alert text format, silence key format, realert timing, `gt start / lte end` range, rule type math. Parity first, then speed.

## Stack

Not a web app: no Postgres, no auth, no payments, no hosting. State stays in Elasticsearch writeback indices (compat + one less system to run).

| layer | choice | why |
| --- | --- | --- |
| language | Rust stable (1.99), edition 2024 | user ask; no GC, predictable latency |
| async runtime | `tokio` (multi-thread) | standard; timers, signals, process, mpsc |
| ES client | `reqwest` (rustls) + `serde_json`, raw REST | official `elasticsearch` crate does not cover OpenSearch and 7.x cleanly; we use ~8 endpoints |
| YAML | `serde_yaml_ng` | maintained serde_yaml fork; env expansion done on raw text before parse (compat) |
| CLI | `clap` derive | flags keep upstream names (`--pin_rules`, `--silence_qk_value`) |
| time | `chrono` + `chrono-tz` | strftime close to Python's for index patterns and pretty ts |
| cron | `croner` | `aggregation.schedule`, `limit_execution` |
| templates | `minijinja` | Jinja-compatible `alert_text_jinja`; templates compiled at rule load |
| SMTP | `lettre` (tokio, rustls) | email alerter, STARTTLS/SSL/auth |
| logs | `tracing` + `tracing-subscriber` (text or JSON) | replaces `logging:` dictConfig; same "Ran rule..." lines |
| metrics | `metrics` + `metrics-exporter-prometheus` | same counter names as upstream |
| hashing | `rustc-hash` (FxHash) | dedup and term sets, hot path |
| ids | `uuid` v7 | client-side writeback `_id` |
| allocator | `mimalloc` | fewer allocator stalls with many small docs |
| tests | built-in `#[test]`, fixtures from upstream `tests/`; integration tests vs ES in docker, `#[ignore]` by default | no framework needed |

One crate, one binary. No workspace until a second binary needs it. Release profile: `lto = "fat"`, `codegen-units = 1`, `panic = "unwind"` (a panicking rule task is caught and the rule disabled, like `disable_rules_on_error`; abort would kill every rule).

## Process model

```
main
 ├─ config + rules load (sync, fail fast)
 ├─ EsClient (Arc, pooled HTTP/1.1 keep-alive, semaphore = max_threads)
 ├─ Writeback task  <─ mpsc ─ every rule task      (bulk flush 1 s / 500 docs / shutdown)
 ├─ SilenceStore    (Mutex<FxHashMap<key,(until,exponent)>>, preloaded from `silence` index)
 ├─ Rule task × N   (owns RuleState: windows, dedup set, pending aggregation; no locks)
 │     tick(run_every, jitter) -> plan range -> query pages (prefetch) -> RuleType::add_page
 │       -> matches -> silence -> enhance (top counts, mget full doc) -> alert | enqueue aggregation
 ├─ Alert dispatcher (per rule, sequential per alert; alerters in config order; jira before email)
 ├─ Reload task     (every run_every: sha1 of rule files + imports; diff; restart affected rule tasks with carried state)
 └─ Metrics server  (optional, --prometheus_port)
```

Shared-state rule: only `EsClient`, `SilenceStore` and the writeback channel are shared. Everything else is owned by one task, so the hot path has no locks.

## "Schema": writeback indices

No SQL. Five ES indices, same names and fields as upstream (ES 8 mappings, `dynamic: true` on objects). Created by `elastalert create-index`. New fields marked `+`.

```
elastalert            (alerts, pending, aggregated)
  _id                 keyword   + client-side UUIDv7
  rule_name           keyword
  @timestamp          date
  alert_time          date
  match_time          date
  match_body          object (enabled: false on new installs + option; keeps mapping small)
  alert_info          object    {type, ...}
  alert_sent          boolean
  alert_exception     text
  aggregate_id        keyword   (children point to head _id)
  aggregation_key     keyword
  alerters_sent       keyword[] + per-alerter delivery status (W10)
  retry_count         integer   + backoff bookkeeping
  category/description/owner/priority   (add_metadata_alert)

elastalert_status     (one doc per rule run; resume point)
  rule_name keyword, @timestamp date, starttime date, endtime date,
  matches long, hits long, time_taken float
  + ingest_high_water date      (only with ingest_timestamp_field)

silence
  rule_name keyword  (= realert_key | realert_key.<qk> | <name>._silence)
  until date, exponent integer, @timestamp date

elastalert_error
  message text, traceback keyword[] (Rust: error chain lines), data object, @timestamp date

past_elastalert       created for compat, never written (upstream barely uses it)
```

Queries the daemon runs against them (all need these fields as keyword/date, which the mappings give):
- resume: `term rule_name` + sort `@timestamp desc` size 1 (startup only, once per rule; then in memory)
- silence preload: `range until > now`, search_after paging (startup)
- pending recovery: `alert_sent:false` and `alert_time >= now - alert_time_limit`, search_after paging (startup)

Retention (new, optional): `create-index --ilm-days N` attaches an ILM/ISM delete policy to `elastalert_status` and `elastalert_error`, which grow forever upstream.

Hard constraints:
- Rule names unique across all files (checked at load and reload).
- One running instance per writeback index (documented; W15 lease later).
- `_id` uniqueness from UUIDv7, so bulk retries are idempotent (`create` op, 409 = already written).

## Interfaces ("API")

### CLI (single binary, upstream-compatible flags)

| command | does | input | output | flow |
| --- | --- | --- | --- | --- |
| `elastalert [run] --config C [--rule R] [--start T\|NOW] [--end T] [--debug\|--verbose] [--patience unit=n] [--pin_rules] [--es_debug] [--es_debug_trace F] [--prometheus_port P] [--prometheus_addr A]` | daemon or bounded replay | config.yaml, rules | logs, alerts, writeback | F01 F02 F03 F04 F05 F08 F09 |
| `elastalert --rule R --silence unit=n [--silence_qk_value V]` (also `elastalert silence`) | write silence doc, exit | rule file | silence doc | F06 |
| `elastalert test-rule R [--schema-only] [--days N] [--start] [--end] [--data F] [--alert] [--save-json F] [--use-downloaded] [--max-query-size N] [--count-only] [--formatted-output] [--stop-error] [--config C]` | dry-run a rule | rule + ES or JSON | report on stdout, exit 0/2/3 | F07 |
| `elastalert create-index [--host..] [--index] [--old-index] [--ilm-days N]` | create/upgrade writeback indices | ES conn | indices | F10 |
| `elastalert validate --config C` (new) | load + type-check every rule, no ES | config + rules | errors file:line, exit code | CI for rule repos |

Symlinks `elastalert-test-rule` and `elastalert-create-index` dispatch on `argv[0]` so existing scripts keep working.

### Elasticsearch requests (outbound, only public REST APIs)

| request | when | notes |
| --- | --- | --- |
| `POST /<idx>/_pit?keep_alive=` + `POST /_search` (search_after) | rule query, startup scans | scroll fallback if PIT unsupported |
| `DELETE /_pit` | end of query | |
| `POST /<idx>/_count` | `use_count_query`, test-rule | |
| `POST /<idx>/_search` size 0 + aggs | `use_terms_query`, metric/percentage/spike agg, `top_count_keys`, new_term (composite) | |
| `POST /<idx>/_mget` | full doc for matches (W2) | grouped by index |
| `POST /_bulk` | all writeback | `create` ops, 1 s flush |
| `GET /` | version detect at startup | picks PIT/scroll, mappings 7 vs 8 |
| `HEAD /<writeback>` | `--patience` wait | |
| `PUT /<idx>`, `PUT /_index_template`, ILM/ISM | create-index | |

### Outbound alerts

| alerter | transport | core? |
| --- | --- | --- |
| debug | tracing log | yes |
| email | SMTP via lettre | yes |
| slack | HTTPS POST webhook(s) | yes |
| post / http_post | HTTPS POST per match | yes |
| command | tokio::process, argv or `sh -c` | yes |
| others (teams, mattermost, discord, telegram, pagerduty, opsgenie, thehive, iris, jira, ...) | HTTPS | could, by SOC demand |

Alerter trait: `async fn alert(&self, matches: &[Match], ctx: &AlertCtx) -> Result<()>` + `fn info(&self) -> Value`. Each alerter gets a 30 s timeout (configurable) so one dead webhook cannot stall a rule.

### Internal jobs

| job | schedule | does |
| --- | --- | --- |
| rule tick | per rule `run_every` (+0-15 s first offset, jitter) | F02 |
| aggregation flush | per rule, timer at each group's `alert_time` (no polling) | F03 |
| retry queue | exponential backoff from failure, capped by `alert_time_limit` | F09 |
| rule reload | global `run_every` (off with `--pin_rules`) | F05 |
| writeback flush | 1 s or 500 docs | all |
| dedup/window GC | end of each rule tick | memory bound |

## The parts that bite

- **Time zones**: everything internal is UTC `i64` micros. Only three places use local time: `pretty_ts` (`use_local_time`), `query_timezone`, strftime index names (UTC, like upstream). DST matters only for cron schedules (`croner` with the configured tz).
- **Idempotency**: client-side `_id` + bulk `create` makes writeback retries safe. Alert delivery is at-least-once (same as upstream); per-alerter status (W10) removes most duplicates.
- **Races**: a rule's state belongs to one task. `realert_key` can be shared by several rules -> SilenceStore is the one shared map (short mutex holds, no await inside).
- **Late data**: `buffer_time` overlap kept by default for parity (W3); `ingest_timestamp_field` is the fast path and needs a field set at ingest.
- **ES limits**: `max_query_size` page size; PIT keep-alive 1 m; 429/503 -> retry with backoff and log, rule run marked failed, next run resumes from last good endtime (no gap).
- **Memory bounds**: dedup set pruned each run; windows evict by timeframe; new_term sets are the only unbounded state (= cardinality of the field). Metric `elastalert_rule_state_bytes` (new) per rule to spot it.
- **Python format compat**: `str.format` subset (`{}`, `{0}`, `{name}`, `{name:spec}` basic specs) and `%s` / `%(name)s`. Unknown spec -> render raw and warn, never crash.
- **Clock skew**: start in the future -> skip run (upstream behavior), log once.
- **Secrets**: env expansion in YAML (compat). `smtp_auth_file` and webhook URLs never logged; `--es_debug_trace` redacts auth headers.
- **Security**: `command` alerter string form keeps a warning; values substituted into argv only, never re-parsed by a shell in list form.

## Performance targets (measured in M2, against Python on the same data)

| metric | target |
| --- | --- |
| idle RSS, 500 rules loaded | < 50 MB |
| CPU per 1 M hits processed (frequency rule) | < 1 s on one core |
| bytes read from ES per run, frequency rule, default settings | <= 10% of Python's |
| ES requests per minute for writeback, 500 rules, `run_every` 1 m | ~60 (bulk) vs >= 500 |
| startup to first query, 500 rules | < 1 s (excluding new_term init) |

Harness: `bench/` replays a fixed index (e.g. 5 M synthetic auth logs) with `--start/--end --debug` on both daemons and records wall time, RSS, ES request count (from ES `_nodes/stats`), and diffs alert output.

## Parity harness (acceptance gate)

Replay mode makes both daemons deterministic: same rules, same index, `--start A --end B --debug`. Script runs Python ElastAlert and elastalert-rs, normalises the `Alert for ...` blocks, and diffs them. Zero diff on the SOC rules folder + upstream `examples/rules` = parity. Unit tests port the rule-type cases from upstream `tests/rules_test.py` (same inputs, same expected matches).

## Source layout

```
src/
  main.rs          clap, argv[0] dispatch, shutdown
  config.rs        config.yaml + env + defaults
  rule/            loader.rs (files, imports, hashing, reload diff), model.rs (typed rule + per-type options)
  es.rs            client, auth, version detect, PIT/search_after/scroll, bulk, mget
  engine.rs        rule task: range planning, segmenting, dedup, match pipeline
  window.rs        EventWindow
  types/           any, frequency, spike, flatline, compare (black/white/change), new_term, cardinality, metric_agg, percentage, spike_agg
  silence.rs       SilenceStore, realert/exponential
  writeback.rs     bulk writer, startup recovery, pending/aggregation persistence
  alert/           mod.rs (trait, body text, summary table), pyfmt.rs, debug, email, slack, post, command
  test_rule.rs  create_index.rs  metrics.rs  field.rs (paths, .keyword fallback)  time.rs
tests/             fixtures from upstream + parity scripts
bench/
```

## Build order

1. **Vertical slice** (F01 + F02 thin): `config.rs`, `rule/loader` (no imports), `es.rs` search_after, `engine` with range planning + dedup, `types/any` + `types/frequency`, `window.rs`, debug alerter, status doc via bulk writer, `--start/--end/--debug/--rule`.
   Surfaces S01 S04 S05 S07 S08 S14 S19. Proves: Rust reads ES, finds a match, prints the same text as Python. First parity diff runs here.
2. **Must-haves** (47 rows):
   - rule loading: imports, env expansion, `rules_folder` list + subdirs, `is_enabled`, duplicates, compound keys, hot reload (S05 S06, F05)
   - query: strftime indices, timestamp types iso/unix/unix_ms, projection + `_mget` (W2), shard failure policy, PIT/scroll fallback (S19)
   - rule types: spike, flatline, blacklist, whitelist, new_term (W7)
   - match pipeline: realert/silence + SilenceStore preload (S15, F06), alert text compat incl. `alert_text_args/kw`, `$field$` refs
   - alerters: email, slack, post, command (S09-S12), per-alerter status + retry (W10, F09)
   - writeback: alert docs, error docs, pending recovery at startup (S13 S16, F04), graceful shutdown (W11)
   - CLI: `--silence`, `--patience`, `--pin_rules`, `--es_debug(_trace)`; env overrides; ES TLS + basic/bearer/apikey
   - parity harness + perf bench green
3. **Should-haves** (23): aggregation (timespan, cron, aggregation_key, summary tables) (F03), change, cardinality, count/terms queries, query_delay, scan_entire_timeframe, top_count_keys, exponential_realert, jinja, `test-rule` (S02, F07), `create-index` (S03, F10), Prometheus (S18), `ingest_timestamp_field` fast path (W3), `validate` command.
4. **Could-haves** (19): metric_aggregation, percentage_match, spike_aggregation, extra alerters by SOC demand, Kibana/OpenSearch discover URLs, EQL/ES|QL, SigV4, statsd, `_msearch` batching of rules sharing an index and tick, HA lease (W15), new_term snapshot file, Docker image.
5. **Fixes from replica-entrepreneur**: not run. For an internal SOC tool, read upstream GitHub issues instead and fold real bugs into the weakness table.
