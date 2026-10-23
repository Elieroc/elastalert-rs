# Build log

No GUI: "screens" are the surfaces S01-S19 from recon.md. No screenshots (`replica/clone-screens/` not used).

| ID | date | status | missing | harder than expected |
| --- | --- | --- | --- | --- |
| slice (F01+F02) | 2026-10-23 | done | see per-surface rows | Python `lookup_es_key` quirks (leaf short-circuit, single-digit `[n]`); `dt_to_ts` fraction rules; realert uses wall clock, not match time |
| S01 daemon CLI | 2026-10-23 | partial | `--es_debug`, `--es_debug_trace`, `--prometheus_port`; `--pin_rules` accepted but reload not built | |
| S04 config.yaml | 2026-10-23 | done | `es_hosts` list ignored (first host only) | |
| S05 rule YAML | 2026-10-23 | partial | types other than any/frequency, aggregation, alerters other than debug outside `--debug` | |
| S06 import chain | 2026-10-23 | done | | |
| S07 logs | 2026-10-23 | done | `Ran ...` line reports hits across all segments (upstream prints only the last segment: its own bug) | |
| S08 debug output | 2026-10-23 | done | | |
| S13 alert docs | 2026-10-23 | partial | only for `alert: debug` without `--debug`; no pending/retry | |
| S14 status docs | 2026-10-23 | done | | |
| S15 silence | 2026-10-23 | partial | written, and `--silence` works; but not read back at startup (restart forgets realert) | |
| S16 error docs | 2026-10-23 | partial | `traceback` always empty | |
| S19 source query | 2026-10-23 | partial | strftime index, count/terms queries, PIT | |

## Parity harness

`tests/parity/`: `seed.py` loads 3000 deterministic auth docs, `rules/` has 4 rules (any, frequency with qk + alert_text_args,
frequency without qk + legacy `query:` filter, compound query_key + alert_text_kw), `diff.py` compares alert blocks.

```
docker run -d --name ea-rs-test -p 127.0.0.1:19200:9200 -e discovery.type=single-node -e xpack.security.enabled=false docker.elastic.co/elasticsearch/elasticsearch:8.15.3
python3 tests/parity/seed.py http://127.0.0.1:19200
cd tests/parity
elastalert   --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z 2>py.log   # Python 2.31.0
../../target/release/elastalert --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z 2>rs.log
python3 diff.py py.log rs.log
```

2026-10-23 result: 81 vs 81 alerts, IDENTICAL. Wall time: Python 60.6 s (its replay waits one full run_every), Rust 0.45 s.
Not a performance benchmark yet; that is the bench in milestone 2.

## Known deviations (deliberate)

- Timestamps with a non-UTC offset are normalised to `Z` in match bodies (upstream keeps the offset).
- `related_events` timestamps print as `...Z` (upstream prints `+00:00` there).
- Format specs in `alert_text` (`{0:>5}`) are ignored, value printed plain. Warn-free for now.

## Milestone 2 (2026-10-23)

| area | status | notes |
| --- | --- | --- |
| rule types | done | spike (count + field_value), flatline, blacklist, whitelist, change, new_term (composite aggs at startup), cardinality (max + min). 15 parity rules, 444 alerts identical to Python 2.31.0 |
| strftime indices | done | daily and hourly, `search_extra_index`; parity-tested |
| alerters | done | email, slack, post, command (+ debug). Tested against local sinks (`tests/alerters/sink.py`): SMTP message, 2 slack channels, post with payload map + headers, command with substitution and `pipe_match_json` |
| per-alerter delivery | done | stored in `alerters_sent`; failed ones retried with backoff (30 s doubling, max 1 h); recovered from ES at startup; only the failed alerters are re-sent. Verified: slack/post/email down, command ok -> restart with sinks up -> the three are sent, command not repeated, doc updated in place |
| silences | done | preloaded at startup, refreshed every run_every; `--silence` from another process reaches a running daemon |
| hot reload | done | add / change / remove / disable / invalid-file tested; position, dedup set and pending alerts survive |
| projection + `_mget` (W2) | done | frequency, spike, flatline, change, new_term, cardinality fetch only the fields they use; matches get the full document. Same alert bodies as Python (549/549 on the bench) |
| `create-index` | done | upstream ES 8 mappings (embedded). Without them `term rule_name` on a multi-word name never matches |
| `es_hosts` | done | failover on connection errors |
| not done | | aggregation, count/terms queries, top_count_keys, exponential_realert, jinja, metric/percentage/spike_aggregation, test-rule CLI, prometheus, `--es_debug(_trace)`, PIT (scroll only), TLS untested |

### Correction to the milestone 1 report

I wrote that a second launch resumed from the last `endtime`. That check was wrong: without `create-index` the
status index was dynamically mapped (`rule_name` text), so the `term` query never matched, and the run started where
`end - buffer_time` happened to put it. Now verified properly (run ending 10:20, next run started at 10:50 = previous
endtime; the test config needs `old_query_limit` > the age of the replayed data, else the previous run counts as expired).

### Bench (400,000 docs, ~1.3 KB each, ES 8.15 single node, same machine, frequency rule over 3 days, buffer_time 6 h)

| | Python ElastAlert 2.31.0 | elastalert-rs |
| --- | --- | --- |
| rule time (`time_taken` in status doc) | 42.7 s | 4.8 s -> 4.2 s |
| max RSS | 397 MB | 143 MB |
| hits / matches | 398,769 / 549 | 398,769 / 549 |
| match bodies | | 549 / 549 identical (after `float_roundtrip`) |

Python process wall time is 60 s because replay mode waits one `run_every` before exiting; `time_taken` is the fair number.
Not measured yet: bytes on the wire, idle RSS with many rules, 500-rule startup. Those targets from architecture.md are still open.

Reproduce: `python3 bench/seed_fat.py http://127.0.0.1:19200 400000`, then run both daemons with `--start 2026-09-01T00:00:00Z --end 2026-09-04T00:00:00Z`
using `bench/config-{rs,py}.yaml` and compare `bench_{rs,py}_status` and the `bench_{rs,py}` alert docs.

### Known deviations (added)

- `new_term` composite fields print as a Python tuple in the alert body like upstream, but are a JSON array in the ES doc (upstream also stores a list).
- `ChangeRule` state is per rule instance (upstream shares one dict between all change rules).
- new_term startup loads terms with one composite aggregation over the whole window instead of one terms agg per day (`window_step_size` ignored).
- Log lines of an alert body are emitted in one call so parallel rules can't interleave them.

## Milestone 3 (2026-10-23)

| area | status | notes |
| --- | --- | --- |
| aggregation | done | `aggregation` (timespan or cron), `aggregation_key` (compound too), `aggregate_by_match_time`, summary table (ascii, markdown). Groups are persisted as pending docs (head + children via `aggregate_id`), recovered at startup, sent by a timer at the group's time (no polling), children deleted once fully sent. Replay (`--end`) sends open groups at the end. Summary tables byte-identical to Python on 3 golden cases (`tests/golden`); grouping identical on 12 alerts |
| exponential_realert | done | unit test against values printed by upstream's `next_alert_time` |
| count / terms queries | done | frequency, spike, flatline (+ new_term terms); segmented by the global `run_every` like upstream; parity-tested |
| top_count_keys | done | parity-tested; also with `test-rule --data` |
| jinja | done | minijinja, `alert_text_jinja`, `jinja_template_path`, subject. Python-module jinja filters not supported |
| `test-rule` | done | all upstream flags except `--max-query-size` semantics are approximate; works against ES or `--data` / `--save-json` / `--use-downloaded` |
| `validate` | done | new command; 500 rules in 0.02 s |
| Prometheus | done | `--prometheus_port`, same metric names |
| PIT + search_after | done | ES >= 7.12; scroll fallback (OpenSearch tested) |
| ingest_timestamp_field | done | opt-in; verified that a late document is found once and nothing is re-read |
| query_timezone, include_fields, degraded indices | done | first two parity-tested; degraded policy untested on a real degraded cluster |
| ES 7.17 / OpenSearch 2.17 | tested | replay of the 22-rule set gives the same alerts as ES 8 (7.17 adds `_type: _doc` to matches, as upstream does); create-index, resume, enrichment, new_term, silence work on OpenSearch |

### Parity at the end of milestone 3

23 rules, 730 alerts, identical to Python ElastAlert 2.31.0 (`tests/parity`, `diff.py py.log rs.log`). Rule types: any, frequency (hits, count, terms), spike (count, field_value, count query),
flatline (hits, count), blacklist, whitelist, change, new_term (composite), cardinality (max, min); strftime index, aggregation, top counts, jinja, query_timezone, include_fields, alert_text args/kw, subject args.

### Footprint (500 rules)

| | Python | elastalert-rs |
| --- | --- | --- |
| load + validate 500 rules | not measured | 0.02 s, 16 MB |
| RSS, daemon with 500 rules, 35 s after start | 94 MB (still starting rules) | 30 MB (all 500 had run once) |

Python's figure is a snapshot while it was still running its first rules; treat it as indicative only.

### Not done

metric_aggregation, percentage_match, spike_aggregation (aggregation queries), `limit_execution`, `notify_email` / `notify_alert` / `disable_rules_on_error`, `--es_debug(_trace)`,
summary_table_type html, `_source_enabled: false`, SigV4, statsd, Kibana/OpenSearch discover links, the other ~40 alerters, TLS/client-cert paths (still untested), HA lease.

## Milestone 4 (2026-10-23)

| area | status | notes |
| --- | --- | --- |
| `disable_rules_on_error` | done | only panics count as "uncaught" (upstream: non-EAException). Error doc written, rule parked until its file changes or restart, others keep running. Verified with an injected panic (patch removed afterwards): disabled, parked, reload retried it; with `false` it keeps running and fails each run. No notification (`notify_email` still missing) |
| `--es_debug`, `--es_debug_trace` | done | request lines `INFO:elasticsearch:...`; trace file with curl command, status, time, response (4 KB cap). Credentials never appear |
| Dockerfile | done | multi-stage (rust:1-bookworm -> debian:bookworm-slim), dependency layer cache, non-root uid 10001, 142 MB. Tested in a container against the host ES: validate, create-index, replay of the 23 parity rules = 730 alerts |
| `add_metadata_alert` | done | tested |
| load-time rejections added | done | `generate_kibana_discover_url`, `generate_opensearch_discover_url`, `match_enhancements`, `jinja_filters`, `include_rule_params_in_matches`, `_source_enabled: false`, and per-rule `es_host`/credentials/TLS options that differ from config.yaml. Before this they were silently ignored |
| README.md | done | coverage tables for config keys, rule types, rule options, alerters, differences, tests, measurements |

## Milestone 5 (2026-10-23)

| area | status | notes |
| --- | --- | --- |
| License | done | Apache-2.0 `LICENSE` (standard text), `license` / `repository` in Cargo.toml, NOTICE line, README section |
| `notify_email` | done | mails on rule panic (with location + backtrace, also stored in the error doc `traceback`), on rule files that fail to load, and with `notify_all_errors` on every logged error. Global + rule-level recipients, de-duplicated; SMTP options shared with the email alerter. Tested against the SMTP sink: panic mail to global + rule recipients, load-failure mail with the rule's own `notify_email`, notify_all_errors mail for an Elasticsearch 400 |
| bug fixed on the way | done | a new rule file that fails to load was retried (and logged, and now mailed) on every reload tick; its hash is now remembered |
| not done | | `notify_alert` |

## Milestone 6 (2026-10-23)

| area | status | notes |
| --- | --- | --- |
| `limit_execution`, `limit_execution_coverage` | done | upstream's rule: pause when `end + run_every < next cron time - 59 s`, never run a freshly loaded rule outside the window, with coverage resume at the window start. Checked live: rule outside the window logs `Pausing ... until next run at ...` and never queries; rules inside keep running. Upstream does not run such rules at all in `--debug --start/--end` replays (the end is in the past); here replays ignore the option |
| Kibana / OpenSearch Discover links | done | `discover.rs`: Rison encoder (python-prison), `urllib.quote`, `os.path.expandvars`, absolute and shortened Kibana URLs, security tenant. 7 cases generated with upstream's own functions are compared byte for byte (`tests/golden/discover.json`); the parity rule also matches. Slack attachments added |
| EQL / ES\|QL | done | `querylang.rs`: request split (`filter` list), `hits.events` relabelled, ES\|QL rows to documents (`_source` column, nested columns, multi-fields skipped, SHA-256 ids as upstream). Rejected with count/terms/aggregation rules and `new_term` (their sub-queries cannot carry these filters). Found on the way: the PyPI 2.31.0 wheel predates `format_source`; the parity run uses the repository checkout |
| `match_enhancements` | partial | only `TimeEnhancement`; `run_enhancements_first` implemented as upstream (failure keeps the match when run first, drops it when run late). Python classes cannot be loaded and are rejected |
| `jinja_filters` | not possible | the option names Python classes. Empty list accepted, otherwise rejected |
| parity | done | `tests/parity/rules-ql`: 203 alerts identical (ES 8.15.5); the 37 original rules still 931 identical. One known difference: `TimeEnhancement` + `frequency` (see README, differences) |

## Milestone 7 (2026-10-23)

| area | status | notes |
| --- | --- | --- |
| native match enhancements | done | `Enhancement` trait (`process(&mut Doc) -> Result<Outcome>`, `Outcome::Drop` = `DropMatchException`) and a name -> constructor registry; options validated at load. Entries are names or one-key maps. Modules: `TimeEnhancement`, `rust.add_field`, `rust.drop_if`, `rust.lookup`. Drop semantics as upstream: late run removes the match (empty aggregation group sends nothing), `run_enhancements_first` skips it after the silence is set. Checked with `test-rule --data --alert`. Guide: `docs/enhancements.md` |
