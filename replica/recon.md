# Recon map: ElastAlert 2 v2.31.0 (headless daemon + CLI, Python)

Scope: core loop. Config + rule loader + query loop + core rule types + writeback state + 5 alerters (email, slack, http post, command, debug) + `test_rule` CLI. Drop-in for existing ElastAlert2 rule YAML.
For: the user's own SOC (internal Rust port, `elastalert-rs`). Skip brand / launch / pricing steps.
Date: 2026-10-23

Platform note: no GUI. "Screens" below are **surfaces**: CLI entry points, config files, rule files, log output, outbound alert payloads, and the Elasticsearch indices the daemon reads and writes. States = success / empty / error variants of each.

## Rules of engagement for this recon

- Source: local clone `/home/elie/Documents/soc/elastalert2`, **Apache-2.0**, public GitHub project (jertel/elastalert2). Reading it is allowed. No account, no paywall, no private API involved.
- Apache-2.0 also permits reuse, but plan is a **clean-room rewrite** in Rust from behavior described here. Keep a NOTICE crediting upstream if any text, schema.yaml or ES mappings are copied.
- Checked terms: no clause blocks building a derivative or competing tool.
- `replica/screens/` stays empty (no UI). Nothing to screenshot.

## Sources

| # | source | URL / path | notes |
| --- | --- | --- | --- |
| 1 | docs (rst) | `elastalert2/docs/source/{configuration,ruletypes,alerts,running_elastalert,elastalert_status}.rst` | most complete option list. ruletypes 110KB, alerts 117KB |
| 2 | public docs site | https://elastalert2.readthedocs.io/ | same content, rendered. FAQ at `/recipes/faq.html` |
| 3 | upstream repo | https://github.com/jertel/elastalert2 | Apache-2.0 |
| 4 | engine source | `elastalert/elastalert.py` (2008 lines) | run loop, query, silence, aggregation, writeback |
| 5 | rule types | `elastalert/ruletypes.py` (1330) | exact match semantics |
| 6 | loader + schema | `elastalert/loaders.py`, `schema.yaml` | defaults and validation |
| 7 | alerter base + text | `elastalert/alerts.py`, `alerters/*.py` (45 files) | |
| 8 | ES mappings | `elastalert/es_mappings/{7,8}/*.json` | writeback doc shapes |
| 9 | example rules | `examples/rules/*.yaml`, `examples/config.yaml.example` | fixtures |
| 10 | tests | `tests/*.py` (~8.6k lines), `tests/alerters/` | behavior oracle: port them as acceptance tests |
| 11 | changelog | `CHANGELOG.md` | what upstream thinks matters |
| 12 | user's own rules | SOC rules folder (not yet provided) | **ask user**: the real acceptance fixtures |

## Core loop

Every `run_every`, per rule: query ES for new events since last end time, feed them to a stateful rule type, and on a match apply realert/silence, optionally aggregate, then fire the alerters and record everything in a writeback index.

## Surfaces (S = "screens")

| ID | surface | how you reach it | purpose | key components | states seen |
| --- | --- | --- | --- | --- | --- |
| S01 | `elastalert` daemon CLI | `python -m elastalert.elastalert --config config.yaml` | run scheduler forever, or one pass with `--end` | flags: `--config --debug --verbose --rule --silence --silence_qk_value --start --end --patience --pin_rules --es_debug --es_debug_trace --prometheus_port --prometheus_addr` | running, `--debug` (alerts logged not sent), bad config exit, ES unreachable exit 1 (`--patience`), `SIGINT` immediate exit 0 |
| S02 | `elastalert-test-rule` CLI | `elastalert-test-rule rule.yaml` | dry-run rule vs history, print fields | flags: `--schema-only --days --start --end --stop-error --formatted-output --data FILE --alert --save-json --use-downloaded --max-query-size --count-only --config` | schema error, no hits ("Didn't get any results."), N hits + first-doc terms, query error (exit 2/3 with `--stop-error`), alert dry output |
| S03 | `elastalert-create-index` CLI | one-time setup | create 5 writeback indices + templates | ES 7 and 8 mappings | created, already exists, `--old-index` copy; flags `--host --port --username --password --bearer --api-key --url-prefix --ssl/--no-ssl --verify-certs --index --old-index --aws-region --profile --timeout` |
| S04 | global `config.yaml` | file + env vars | ES conn, scheduling, defaults, notify | see Config table below | missing required key error, bad timedelta error |
| S05 | rule YAML | `rules_folder/**/*.y(a)ml` | one alert definition | name, type, index, filter, timeframe, alert, per-type options, per-alerter options, text templates | valid, schema-invalid (skipped or fatal per `skip_invalid`), `is_enabled: false`, duplicate name |
| S06 | rule import chain | `import:` key | share common keys | DFS merge, filters AND-merged, later import wins | resolved, missing import (ENOENT hash) |
| S07 | log output | stdout/stderr, optional `logging:` dictConfig | ops visibility | per-run line `Ran <rule> from A to B: N query hits (M already seen), K matches, J alerts sent`; `Queried rule ... hits`; warnings | info, warning (`took longer than run_every`), error |
| S08 | debug alert output | `--debug` or `alert: debug` | print alert text | `Alert for <rule>[, <qk>] at <ts>:` + body | per-match |
| S09 | email alert | alerter `email` | SMTP message | subject `ElastAlert: <name>[ - <qk>]`, text or html body, cc/bcc, images, jira link | sent, SMTP connect error, auth rejected |
| S10 | slack alert | alerter `slack` | webhook POST | one attachment: color, title, text (body), fields, footer, author, discover links | sent, HTTP error |
| S11 | http post alert | alerter `post` | JSON POST per match | full match or `http_post_payload` map + static payload + headers | sent, HTTP error |
| S12 | command alert | alerter `command` | exec process | argv list or shell string, `%`/`{}` field substitution, stdin = match JSON or alert text | exit 0, non-zero (`fail_on_non_zero_exit`), OSError |
| S13 | ES index `elastalert` | writeback | one doc per match/alert | `match_body rule_name alert_info alert_sent alert_time match_time aggregate_id aggregation_key alert_exception @timestamp` | sent, unsent (pending / retry), aggregated child |
| S14 | ES index `elastalert_status` | writeback | one doc per rule run | `rule_name starttime endtime matches hits time_taken @timestamp` | per run |
| S15 | ES index `silence` | writeback | realert + manual silence | `rule_name until exponent @timestamp` | `rule` / `rule.qk` / `rule._silence` keys |
| S16 | ES index `elastalert_error` | writeback | error log | `data message traceback @timestamp` | per error |
| S17 | ES index `past_elastalert` | writeback | archive | same shape as S13 | legacy, low value |
| S18 | Prometheus endpoint | `--prometheus_port` | metrics scrape | counters `elastalert_{scrapes,hits,matches,time_taken,alerts_sent,alerts_not_sent,alerts_silenced}` (label rule_name), `elastalert_errors` | on / off |
| S19 | source data indices | rule `index` (wildcard, strftime) | what we query | any ES index with a timestamp field | empty, large (scroll), degraded shards |

### Config table (S04, core subset)

Required: `run_every buffer_time es_host es_port writeback_index` (+ `rules_folder` for file loader).
Defaults: `max_query_size 10000`, `scroll_keepalive 30s`, `max_scrolling_count 990`, `alert_time_limit 2d`, `old_query_limit 1w`, `disable_rules_on_error true`, `scan_subdirectories true`, `max_aggregation 10000`, `max_threads 10`, `misfire_grace_time 5`.
Env overrides: `ES_HOST ES_HOSTS ES_PORT ES_USERNAME ES_PASSWORD ES_API_KEY ES_BEARER ES_USE_SSL ES_URL_PREFIX STATSD_HOST STATSD_INSTANCE_TAG`. Whole YAML text goes through env expansion before parse.
Rule keys inherit every global key not set in the rule.

## Flows

```
F01 Daemon starts and runs forever
    S01 -> S04 (load+env) -> S05 (load all rules) -> S01 wait_until_responsive -> scheduler start
        -> per-rule job (random 0-15s first offset, jitter 5s) -> S07 log lines
    happy path commands: 1 (`elastalert --config config.yaml`)
    edge: required key missing, rules_folder missing, ES down (patience), writeback index missing, duplicate rule name,
          invalid rule (fatal unless skip_invalid)

F02 One rule run -> alert (the core)
    S19 query -> rule type add_data -> match -> silence check (cache, then S15) -> [enhancements] -> alert
        -> S09/S10/S11/S12 -> S13 write -> S14 write
    steps inside run_rule:
      1 starttime: previous_endtime | last S14 endtime (if < old_query_limit) | now - buffer_time (or timeframe w/ scan_entire_timeframe)
      2 split [start,end] into segments of buffer_time (run_every for count/terms)
      3 each segment: search (asc by ts, size=max_query_size, scroll) -> drop already-seen -> add_data -> garbage_collect
      4 each match: realert_key[.qk] silence -> set silence until now+realert (exponential if configured)
      5 no aggregation: alert now. else: queue pending (S13, alert_sent=false, alert_time=future)
      6 write S14 doc
    edge: ts field missing in hit (error), start in the future (sleep), query error (rule skipped this run, error to S16),
          shard failure, scroll > max_scrolling_count, all matches silenced

F03 Aggregated alert
    match -> S13 pending doc(s) with aggregate_id -> every run_every: find due pending -> fetch children -> one alert with N matches
        -> delete pending docs -> summary table in body
    edge: cron `aggregation.schedule`, aggregation_key per-group timers, restart with pending docs, ES write failure (kept in memory agg_matches)

F04 Restart recovery / retry
    S01 start -> pending scan: S13 where alert_sent=false and no aggregate_id and alert_time within alert_time_limit
        -> resend -> update/delete. last run end from S14 resumes querying.
    edge: rule removed meanwhile (alert kept), malformed doc dropped, >1000 pending (next pass)

F05 Hot reload
    every run_every: hash rule files (+imports) -> removed: stop job; changed: reload keep state; new: add; disabled: park
    edge: bad new version -> keep old, send notify email, log error; --pin_rules off switch

F06 Silence a rule from the CLI
    S01 `--rule X.yaml --silence hours=2 [--silence_qk_value V]` -> S15 doc (`X._silence` or `realert_key.V`) -> exit
    happy path commands: 1
    edge: no --rule, --debug, bad duration, ES write fails (exit 1)

F07 Author tests a rule
    S05 write -> S02 `--schema-only` -> S02 (query last day) -> S02 `--days 7` -> S02 `--alert`
    happy path commands: 2-3
    edge: no hits, bad filter, offline `--data file.json`, `--save-json` then `--use-downloaded`

F08 Backfill / replay
    S01 `--start ISO --end ISO --rule X.yaml [--debug]` -> run until end -> one cycle then exit

F09 Alert delivery failure
    alerter raises -> error to S16 (+ notify_alert/email if set) -> S13 doc with alert_sent=false + alert_exception -> F04 retries
    edge: one of several alerters fails: whole alert flagged unsent (other alerters may resend = duplicates upstream; decide if clone should fix)

F10 First-time setup
    S03 create-index -> S04 -> S05 sample rule -> S01
    happy path commands: 3
```

Number to beat: **F01 = 1 command** with config + rules folder in place; F07 = 1 command to validate a rule.

## Rule types (the engine core)

| type | required | state kept | match when | adds to match |
| --- | --- | --- | --- | --- |
| any | none | none | every hit | the hit |
| frequency | `num_events timeframe` | `EventWindow` per query_key (key `all` if none) | window count >= num_events; then key popped | `related_events` if `attach_related` |
| spike | `timeframe spike_height spike_type` | ref + cur EventWindow per key; first_event; skip_checks | cur >= ref*h (up) or cur <= ref/h (down); needs ref window filled (2x timeframe) unless `alert_on_new_data`; thresholds `threshold_ref/cur` | `spike_count reference_count` |
| flatline | `timeframe threshold` | occurrences + first_event per key | count in window < threshold after one full timeframe; GC injects zero-count event so absence is noticed | `key count threshold`; `forget_keys` |
| blacklist | `compare_key blacklist` | none | value in set; `!file path` lines expand | |
| whitelist | `compare_key whitelist ignore_null` | none | value missing from set (null handled by ignore_null) | |
| change | `query_key compare_key ignore_null` (+`timeframe`) | last values per key | compare values differ (within timeframe) | `old_value new_value` |
| new_term | `fields` or `query_key` (+`terms_window_size` 30d) | seen values per field; **startup terms-agg** (size 2^31-1) | value never seen; tuple for composite fields | `new_field` / `missing_field` |
| cardinality | `timeframe cardinality_field` + max or min | value->last_seen per key | unique count > max, or < min after timeframe | |
| metric_aggregation | `metric_agg_key metric_agg_type` + min/max_threshold | none (ES does the work) | agg value crosses threshold; types min max avg sum cardinality value_count percentiles | `metric_agg_value[_formatted]` |
| percentage_match | match_bucket_filter + min/max_percentage | none | % of docs in bucket vs total out of range | |
| spike_aggregation | metric_agg + spike_* | like spike | spike on agg value | |

EventWindow: sorted by timestamp, `running_count` sum of counts, append evicts while `last - first >= timeframe`, fires `onRemoved` (cur -> ref hand-off in spike).

## Components

| component | variants | states | used on |
| --- | --- | --- | --- |
| Rule loader | file (only upstream impl); Python custom loader (skip) | ok, invalid, disabled | S05 S06 |
| Rule type (trait) | 12 types above | per-key state, GC | F02 |
| EventWindow | plain, with onRemoved | empty, filling, evicting | frequency spike flatline |
| ES client | ES7, ES8, OpenSearch; basic / bearer / apikey / SigV4; TLS | healthy, degraded shards, down | all |
| Query builder | filter + range + sort; strftime index expander; scroll | single page, scrolling | F02 |
| Scheduler | per-rule interval job + internal jobs | on time, misfire, paused by limit_execution | F01 F05 |
| Silence / realert cache | in-memory map + S15 fallback; exponential | silenced, expired | F02 F06 |
| Pending-alert store | S13 docs w/ aggregate_id | pending, due, sent | F03 F04 |
| Alerter (trait) | email slack post command debug (core); 40 more | ok, error | F02 |
| Alert text builder | default body, `alert_text` + args/kw, jinja, aggregation summary (ascii/markdown/html) | | alerters |
| Field lookup | dotted path, `.keyword` fallback, `_missing` handling | found, missing | rules, text, alerters |
| Duration parser | timedelta map, `unit=n` CLI | | config, rules, S01 |
| Pretty timestamp | local vs UTC, `custom_pretty_ts_format` | | text, logs |

## Inferred data model (all persisted state lives in ES)

```
AlertDoc (index `elastalert`)
    rule_name keyword, @timestamp date, alert_time date, match_time date, match_body object,
    alert_info {type,...}, alert_sent bool, alert_exception string?, aggregate_id keyword?, aggregation_key keyword?,
    category/description/owner/priority (if add_metadata_alert), match fields at root (if include_match_in_root)
    evidence: es_mappings, get_alert_body(), add_aggregated_alert()      confidence: high

RunStatus (index `elastalert_status`)
    rule_name, starttime, endtime, matches, hits, time_taken, @timestamp
    evidence: run_rule(), get_starttime() reads latest endtime per rule   confidence: high

Silence (index `silence`)
    rule_name (= realert_key | realert_key.qk | name._silence), until date, exponent int, @timestamp
    evidence: set_realert(), is_silenced()                                confidence: high

ErrorDoc (index `elastalert_error`)
    message, traceback (list of lines), data {rule, query?}, @timestamp
    evidence: handle_error()                                              confidence: high (handle_error body: message, traceback[] lines, data)

Rule (in memory, from YAML)
    name, type, index, alert[], filter[], timeframe, run_every, buffer_time, query_key, realert, aggregation,
    timestamp_field/type/format, per-type + per-alerter options; runtime: starttime, previous_endtime,
    minimum_starttime, processed_hits{id->ts}, agg_matches[], aggregate_alert_time{}, current_aggregate_id{}
    evidence: loaders.load_options(), init_rule()                         confidence: high

Match = ES _source dict (+ _id _index) with ts as datetime, plus rule-added keys, + num_hits, num_matches
```

Relationships: Rule 1-n AlertDoc, Rule 1-n RunStatus, Rule(+qk) 1-n Silence, AlertDoc(aggregate head) 1-n AlertDoc(children via aggregate_id).

## Behaviors to preserve exactly (compat traps)

1. Time range is `gt start, lte end` (half open). Dedupe by `_id` across overlapping windows.
2. Silence key = `realert_key` + `.` + str(query_key value); flatline uses match `key`. Check cache, then rule-level `name._silence`, then ES.
3. `realert` default **1 minute** (0 when aggregation set). Silence is set when the match is processed, not when the alert succeeds.
4. Default match body: `name\n\n` + type `get_match_str` + `key: value` lines sorted by key (dict/list as sorted indented JSON).
5. Compound `query_key` value = `", ".join(str(v))` stored back into the doc under comma-joined key name.
6. `top_count_keys` get `.keyword` suffix unless `raw_count_keys: false` or `string_multi_field_name` set.
7. `blacklist`/`whitelist` filters are auto-added to the query (`enhance_filter`).
8. Match timestamps are converted back to ISO strings in `add_match`.
9. Python-isms to decide on: `alert_text` uses `str.format` / `%`; `resolve_string` mixes both with missing-value default; `eval()` timestamp exprs; `get_module` plugins.

## Feature matrix

See `features.csv`: 94 rows. Must 47, should 23, could 19, skip 5.

## Out of scope (cannot or should not be cloned)

- Python plugin surface: custom rule types, alerters, loaders, match enhancements, jinja filters (`get_module`). Replace with Rust traits or drop. Say so in README.
- `timestamp_format_expr` / `timestamp_to_datetime_format_expr` (Python `eval`). Security risk, skip.
- The other ~40 alerters: add on demand (listed as `could`). Start with the SOC's actual destinations.
- Upstream docs site, community, Helm chart (`could`), Docker image (`could`).
- Kibana/OpenSearch discover links, EQL, ES|QL: `could`, after core parity.
- No licensed content, no network effects, no regulated data. Nothing owned by upstream beyond Apache-2.0 code (credit it).

## Size

Surfaces 19 (11 in core), flows 10, entities 5 persisted + 1 runtime. Hard parts:
1. **Time/state semantics**: starttime resolution, segmenting, overlapping windows, EventWindow + GC for spike/flatline/frequency. Bugs here are silent (missed or duplicate alerts). Port upstream tests as the oracle.
2. **ES compatibility without elasticsearch-py**: raw Query DSL passthrough, scroll, strftime index wildcards, ES7/8/OpenSearch, TLS + 3 auth modes, shard-failure handling.
3. **Durable alert state in ES**: pending / aggregated alerts, restart recovery, silence cache vs ES, write-failure fallback, interop with a running Python ElastAlert on the same writeback indices.
4. (also) Python text semantics: `str.format`/`%`, Jinja, key ordering in default body.

Size: **M** (a few weeks) for the core slice. Core + all alerters would be L. Everything: XL.

## Open questions for the user

- Which ES version(s) / OpenSearch? (decides mappings 7 vs 8, `_type` handling)
- Which rule types and alerters do the SOC rules actually use? (send `rules_folder`; shrinks scope)
- Must the Rust daemon coexist with Python ElastAlert on the same writeback indices, or replace it with a clean index?
- Keep `str.format` alert text semantics, or migrate rules to Jinja only?
