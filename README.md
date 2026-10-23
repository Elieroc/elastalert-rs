# elastalert-rs

A Rust rewrite of the core of [ElastAlert 2](https://github.com/jertel/elastalert2): a daemon that queries
Elasticsearch / OpenSearch on a schedule, applies rules (frequency, spike, new term, ...) and sends alerts.

It reads **existing ElastAlert 2 rule files and `config.yaml` unchanged** and writes the same writeback documents.
The goals were drop-in compatibility and speed. It is not a complete port: see [What is covered and what is not](#what-is-covered-and-what-is-not)
before replacing a production ElastAlert 2.

> **Status: beta.** Behaviour is checked against Python ElastAlert 2.31.0 by replaying the same data through both
> and diffing the alerts (see [Testing](#testing)). It has not been run in production by anyone yet, and several code paths
> (TLS, client certificates, degraded clusters) have never been exercised. Run it next to your current setup with `--debug` first.

Contents: [Quick start](#quick-start) · [Docker](#docker) · [Command line](#command-line) · [Configuration](#configuration) ·
[Writing rules](#writing-rules) · [What is covered and what is not](#what-is-covered-and-what-is-not) ·
[Differences from ElastAlert 2](#differences-from-elastalert-2) · [Performance](#performance) · [Testing](#testing) · [Layout](#layout) · [License](#license)

## Quick start

Build (edition 2024 with let-chains, so Rust 1.88 or newer in principle; developed and tested only with 1.99):

```sh
cargo build --release          # binary: target/release/elastalert
```

```sh
# 1. create the writeback indices (once)
elastalert --config config.yaml create-index

# 2. check every rule loads, without touching Elasticsearch
elastalert --config config.yaml validate

# 3. try a rule on past data, nothing is sent or written
elastalert --config config.yaml test-rule rules/my_rule.yaml --days 1

# 4. run
elastalert --config config.yaml
```

A minimal `config.yaml` (identical to ElastAlert 2's):

```yaml
rules_folder: rules
run_every: {minutes: 1}
buffer_time: {minutes: 15}
es_host: elasticsearch.example.com
es_port: 9200
writeback_index: elastalert_status
```

A minimal rule:

```yaml
name: ssh brute force
type: frequency
index: logs-*
num_events: 10
timeframe: {minutes: 5}
query_key: source.ip
filter:
- term: {event.outcome: failure}
alert: [slack]
slack_webhook_url: https://hooks.slack.com/services/XXX
```

## Docker

```sh
docker build -t elastalert-rs .
docker run -d --name elastalert \
  -v $PWD/config.yaml:/opt/elastalert/config.yaml:ro \
  -v $PWD/rules:/opt/elastalert/rules:ro \
  -e ES_HOST=elasticsearch -e ES_PORT=9200 -e ES_API_KEY=... \
  elastalert-rs
```

- Image: Debian slim, non-root (uid 10001), about 140 MB. `sh` is present for the `command` alerter.
- The working directory is `/opt/elastalert`, so `rules_folder: rules` means `/opt/elastalert/rules`.
- Default command: `--config /opt/elastalert/config.yaml`. Any other argument replaces it, e.g.
  `docker run --rm elastalert-rs validate`, `... create-index`, `... test-rule rules/x.yaml --days 1`.
- Environment overrides (same as ElastAlert 2): `ES_HOST`, `ES_HOSTS`, `ES_PORT`, `ES_USERNAME`, `ES_PASSWORD`,
  `ES_API_KEY`, `ES_BEARER`, `ES_USE_SSL`, `ES_URL_PREFIX`.
- Environment variables are also expanded inside the YAML files (`$VAR`, `${VAR}`), like ElastAlert 2 does.
- Stop with `SIGTERM`: running rules finish and the writeback buffer is flushed (10 s limit).

## Command line

The daemon flags keep ElastAlert 2's names.

| Command / flag | What it does |
| --- | --- |
| `elastalert [--config FILE]` | Run the daemon (default config `config.yaml`) |
| `--debug` | Log alerts instead of sending them; nothing is written to Elasticsearch |
| `--verbose` | Info-level logs without suppressing alerts |
| `--rule FILE` | Run only this rule (file name inside the rules folder, or a path) |
| `--start ISO\|NOW` | Start querying from this time (default: where the last run ended) |
| `--end ISO` | Query up to this time, run once, exit. Aggregated alerts still open are sent at the end |
| `--silence unit=n [--silence_qk_value V]` | Silence a rule (needs `--rule`); reaches a running daemon within one `run_every` |
| `--patience unit=n` | Wait for Elasticsearch and the writeback index at startup |
| `--pin_rules` | Do not reload rule files when they change |
| `--es_debug` | Log every request sent to Elasticsearch (`INFO:elasticsearch:POST http://... [status:200 request:0.002s]`) |
| `--es_debug_trace FILE` | Append every request as a `curl` command with its (truncated) response to FILE. Credentials are never written |
| `--prometheus_port N [--prometheus_addr A]` | Serve metrics on `http://A:N/metrics` |
| `create-index [--index N] [--old-index N] [--recreate]` | Create the five writeback indices with the right mappings |
| `validate` | Load the config and every rule, build the alerters, report each error, exit 1 if any. No Elasticsearch needed |
| `test-rule FILE [...]` | Run one rule on past data (see below) |

`test-rule` flags: `--schema-only`, `--days N`, `--start`, `--end`, `--data FILE` (use a JSON file instead of
Elasticsearch), `--save-json FILE` / `--use-downloaded` (download the range, then test on the file), `--max-query-size N`,
`--count-only`, `--formatted-output` (one JSON document), `--alert` (really send), `--stop-error`.
Exit codes: 2 query error, 3 invalid rule, 4 missing timestamp.
The output text is similar to ElastAlert 2's but not byte-identical; scripts that parse it need adjusting.

ElastAlert 2's separate commands `elastalert-test-rule` and `elastalert-create-index` do not exist here: use the `test-rule` and `create-index` subcommands.

## Configuration

Global keys read from `config.yaml` (and inherited by every rule that does not set them):

| Key | Status |
| --- | --- |
| `run_every`, `buffer_time`, `writeback_index`, `es_host`, `es_port` (required) | supported |
| `rules_folder` (string or list), `scan_subdirectories` | supported |
| `es_hosts` (list, failover on connection errors) | supported |
| `use_ssl`, `verify_certs`, `ca_certs`, `client_cert`, `client_key` | supported, **never tested against a real TLS endpoint** |
| `es_username` / `es_password`, `es_bearer`, `es_api_key`, `es_url_prefix`, `es_conn_timeout` | supported |
| `max_query_size`, `max_scrolling_count`, `scroll_keepalive`, `max_threads` | supported (`max_threads` bounds concurrent rule runs) |
| `old_query_limit`, `alert_time_limit` | supported |
| `skip_invalid`, `custom_pretty_ts_format`, `jinja_root_name`, `jinja_template_path`, `string_multi_field_name` | supported |
| `add_metadata_alert` | supported (category, description, owner, priority in the alert doc) |
| `disable_rules_on_error` (default `true`) | supported: see below |
| `show_disabled_rules` | supported (lists disabled rules in the log each `run_every`, only when there are some) |
| `allow_queries_on_degraded_indices` | supported, untested on a degraded cluster |
| `use_pit` (new, default `true`) | use point in time + `search_after` when the cluster supports it |
| `from_addr`, `smtp_host`, `email_reply_to` | used by the email alerter |
| `rules_loader` | only the built-in file loader; custom Python loaders are not possible |
| `es_send_get_body_as`, `ssl_show_warn`, `misfire_grace_time`, `max_aggregation` | accepted, ignored |
| `notify_email`, `notify_alert`, `notify_all_errors` | **not supported** (accepted, ignored) |
| `aws_region`, `profile` (SigV4 signing) | **not supported** |
| `replace_dots_in_field_names`, `statsd_host`, `statsd_instance_tag` | **not supported** |
| `logging:` (Python `dictConfig`) | **not supported**; logs go to stderr, level set by `--verbose` / `--debug` |

**`disable_rules_on_error`**: when a rule hits a bug (a panic in the Rust code, the equivalent of ElastAlert 2's
"uncaught exception"), an error document is written to the `_error` index and, if the option is `true` (default), the rule
is parked: it is not run again until its file changes (reload) or the daemon restarts. Other rules keep running.
Ordinary errors (Elasticsearch unreachable, bad query, missing timestamp field, alerter failure) never disable a rule; the next
run retries. Unlike ElastAlert 2, no notification email is sent (`notify_email` is not supported).

## Writing rules

Existing rules work as they are. Supported rule files can use `import:`, `is_enabled`, `$other_key$` references,
compound `query_key` / `aggregation_key` / `compare_key`, and environment variables.

### Rule types

| `type` | Status |
| --- | --- |
| `any`, `frequency`, `spike`, `flatline`, `blacklist`, `whitelist`, `change`, `new_term`, `cardinality` | supported |
| `metric_aggregation`, `percentage_match`, `spike_aggregation` | **not supported** (rejected at load) |
| custom Python rule classes | **not possible** |

`frequency`, `spike` and `flatline` also work with `use_count_query` and `use_terms_query`; `new_term` with `use_terms_query`.

### Common rule options

| Option | Status |
| --- | --- |
| `name`, `type`, `index`, `filter`, `alert`, `description`, `owner`, `priority`, `category` | supported |
| `timeframe`, `num_events`, `query_key`, `buffer_time`, `run_every`, `query_delay`, `scan_entire_timeframe`, `max_query_size` | supported |
| `realert`, `realert_key`, `exponential_realert` | supported |
| `aggregation` (time span or cron `schedule`), `aggregation_key`, `aggregate_by_match_time`, `summary_table_fields`, `summary_table_type` (`ascii`, `markdown`), `summary_table_max_rows`, `summary_prefix`, `summary_suffix` | supported; `summary_table_type: html` is rejected |
| `use_strftime_index`, `search_extra_index` | supported |
| `timestamp_field`, `timestamp_type` (`iso`, `unix`, `unix_ms`), `query_timezone`, `use_local_time` | supported; `unix` / `unix_ms` untested; `timestamp_type: custom` and the `*_expr` options (Python `eval`) are rejected |
| `include`, `include_fields` | supported |
| `top_count_keys`, `top_count_number`, `raw_count_keys` | supported |
| `alert_text`, `alert_text_args`, `alert_text_kw`, `alert_text_type` (`alert_text_only`, `exclude_fields`, `alert_text_jinja`, `aggregation_summary_only`), `alert_subject`, `alert_subject_args`, `alert_subject_max_len`, `alert_missing_value`, `jinja_template_path` | supported (Python `str.format` subset: `{}`, `{0}`, `{name}`; format specs such as `{:>5}` are ignored) |
| `attach_related`, `filter_by_list`, `!file` entries in `blacklist` / `whitelist`, `terms_window_size`, `alert_on_new_data`, `field_value`, `forget_keys`, ... | supported (per rule type options as documented upstream) |
| `limit_execution`, `generate_kibana_discover_url`, `generate_opensearch_discover_url`, `match_enhancements`, `jinja_filters`, `include_rule_params_in_matches`, `_source_enabled: false` | **not supported**: the rule is rejected at load with a message |
| `es_host`, `es_port`, credentials, TLS options **inside a rule** (different cluster per rule) | **not supported**: rejected unless identical to `config.yaml` |
| `ingest_timestamp_field` | **new**, see [Performance](#performance) |

Rules using an option marked "rejected" fail at load (or are skipped with `skip_invalid: true`), they are never run with different behaviour.
Options not listed anywhere are ignored, as in ElastAlert 2, so typos are not detected.

### Alerters

ElastAlert 2 has 44 alerters. **5 are ported** (`debug`, `email`, `slack`, `post`, `command`); a rule naming any other alerter is rejected.

| Alerter | Status |
| --- | --- |
| `debug` | supported |
| `email` | supported: `email`, `cc`, `bcc`, `smtp_host`, `smtp_port`, `smtp_ssl`, STARTTLS, `smtp_auth_file`, `from_addr`, `email_reply_to`, `email_format: html`, `email_from_field`, `email_add_domain`. **Not**: `email_image_keys` / `assets_dir` (inline images), `smtp_cert_file` / `smtp_key_file` (a warning is logged) |
| `slack` | supported: webhook URL(s), channel overrides (one message per channel), username, emoji / icon, colour, title, fields, footer, author, image, pretext, proxy, CA file, timeout, aggregation table in a code block. **Not**: Kibana / OpenSearch / Jira attachment links |
| `post` | supported: `http_post_url` (list), `http_post_payload`, `http_post_static_payload`, `http_post_all_values`, `http_post_headers`, proxy, CA file, timeout, ignore SSL errors |
| `command` | supported: argument list or shell string, `{field}` / `%(field)s` substitution, `pipe_match_json`, `pipe_alert_text`, `fail_on_non_zero_exit` |
| `post2`, `mattermost`, `ms_power_automate`, `discord`, `telegram`, `googlechat`, `rocketchat`, `webex_webhook`, `matrixhookshot`, `gitter`, `lark`, `dingtalk`, `workwechat`, `chatwork`, `line`, `yzj` | **not ported** (chat webhooks: the easiest to add) |
| `pagerduty`, `opsgenie`, `victorops`, `pagertree`, `alertmanager`, `flashduty`, `alerta`, `zabbix`, `datadog` | **not ported** |
| `jira`, `servicenow`, `hivealerter` (TheHive), `iris`, `gelf`, `indexer` | **not ported** |
| `sns`, `sqs`, `ses`, `stomp`, `twilio`, `exotel`, `smseagle`, `tencent_sms` | **not ported** |
| custom Python alerters | **not possible** |

Each alerter has its own delivery state: if Slack is down and email works, only Slack is retried (see below).

## What is covered and what is not

**Covered**

- Reading ElastAlert 2 `config.yaml` and rule files unchanged (supported options above), `import:`, environment expansion,
  rules folder scanning, **hot reload** of added / changed / removed / disabled rule files (a rule keeps its position, dedup set and pending alerts).
- Core loop with the same semantics: time range `gt start, lte end`, resume from the last recorded `endtime`, segmenting of long ranges,
  dedup of documents seen in overlapping windows, realert / silence keys, `exponential_realert`, aggregation groups.
- Writeback indices with the upstream mappings and document shapes: `<writeback_index>` (alerts, pending),
  `<writeback_index>_status`, `_silence`, `_error` and `_past` (created, never written).
- Pending alerts survive restarts: unsent alerts and open aggregation groups are read back from Elasticsearch at startup.
- Elasticsearch 7.17 and 8.15, OpenSearch 2.17 (tested; see [Testing](#testing)). Point in time + `search_after` paging on Elasticsearch 7.12+,
  scroll otherwise (including OpenSearch).
- Jinja alert text (`minijinja`, close to but not identical to Python Jinja2).
- Prometheus metrics with ElastAlert 2's names: `elastalert_{scrapes,hits,matches,time_taken,alerts_sent,alerts_not_sent,alerts_silenced}_total{rule_name=...}`, `elastalert_errors_total`.

**Not covered** (summary; details in the tables above)

- 39 of 44 alerters, notably PagerDuty, Opsgenie, Jira, TheHive, Teams, Mattermost, Discord, Telegram, SNS/SES, Zabbix.
- Rule types `metric_aggregation`, `percentage_match`, `spike_aggregation`; the aggregation-query options (`bucket_interval`, ...).
- `limit_execution`, Kibana / OpenSearch Discover links, EQL and ES|QL rules, `match_enhancements`, `jinja_filters`.
- `notify_email`, `notify_alert`, `notify_all_errors` (no error notifications of any kind), statsd, AWS SigV4 signing, `replace_dots_in_field_names`.
- Per-rule Elasticsearch connections, Python plugins of any kind (rule types, alerters, loaders, enhancements, filters), Python `logging:` config.
- Helm chart.
- Elasticsearch older than 7 and any cluster not listed above.
- High availability: do not run two instances against the same writeback index, they would alert twice (same as two ElastAlert 2 instances).

## Differences from ElastAlert 2

Deliberate or unavoidable differences in behaviour:

| Topic | ElastAlert 2 | elastalert-rs |
| --- | --- | --- |
| Documents fetched | whole `_source` for every hit | only the fields the rule type uses; the full document is fetched (`_mget`) for the few matches. Same alert text. Set `fetch_full_source: true` or `include:` to opt out |
| Failed alerter | the whole alert is marked unsent and every alerter is resent | per-alerter status in `alerters_sent`; only failed alerters are retried (30 s doubling, max 1 h, until `alert_time_limit`) |
| Writeback | one request per document | one `_bulk` per second (or 500 docs); client-side ids make retries idempotent |
| Pending alerts | polled every `run_every`, one `delete_by_query` each | kept in memory, mirrored in ES, aggregation groups sent by a timer |
| Paging | scroll, recursive, capped at 990 pages | point in time + `search_after`, iterative, no cap |
| `new_term` startup | one terms aggregation per day of `terms_window_size` | one composite aggregation; `window_step_size` is ignored |
| `change` rule | state shared by all change rules (a bug) | state per rule |
| Shutdown | `SIGINT` exits immediately | running rules finish, writeback is flushed |
| Replay with `--end` | open aggregation groups are sent only if their time arrives | open groups are sent at the end |
| `silence` | checked in Elasticsearch per match | held in memory, refreshed every `run_every` (a silence set from the CLI takes up to one `run_every` to apply) |
| Resume right after a write | n/a | status documents are visible to search after the next refresh (about 1 s); a restart within that second resumes from `end - buffer_time` |
| Match timestamps | keep the original offset | printed as UTC `Z` |
| Log lines | `INFO:elastalert:...` per call | same text; the two lines of a debug alert are emitted in one call so parallel rules do not interleave them |
| Concurrency | thread pool | one task per rule, `max_threads` limits concurrent runs |
| `disabled rules` log | printed every cycle | printed only when some exist |

New options that ElastAlert 2 does not have: `ingest_timestamp_field`, `fetch_full_source`, `use_pit`, `validate`, `--es_debug_trace` with responses.

## Performance

Measured on one machine (Elasticsearch 8.15 single node in Docker, same host for both programs), rule time taken from each
daemon's own `time_taken` field in the status document. These are single measurements, not a benchmark suite; your data and hardware will differ.

| Scenario | ElastAlert 2.31.0 | elastalert-rs |
| --- | --- | --- |
| Frequency rule over 400,000 documents (1.3 KB each), 3 days, 6 h `buffer_time` | 42.7 s, 397 MB max RSS | 4.2 s, 143 MB max RSS |
| Same, matches | 549 | 549, every match body identical |
| 500 rules loaded and validated | not measured | 0.02 s, 16 MB |
| Daemon with 500 rules, 35 s after start | 94 MB, still running its first rules | 30 MB, every rule had run once |

Where the difference comes from: a compiled runtime without a GIL, field projection (only ts and key fields are read from Elasticsearch),
bulk writeback, compact event windows. Not measured yet: bytes on the wire, CPU per million hits, latency with many aggregation groups.

`ingest_timestamp_field: event.ingested` (optional, rule level): query on the ingest time instead of the event time and continue from
the previous `endtime`, so the `buffer_time` overlap is not read again on every run. The field must be set by your ingest pipeline.
Late documents (old event time, new ingest time) are then found exactly once. Without the option the behaviour is ElastAlert 2's.

## Testing

```sh
cargo test                                   # 17 unit tests, including golden outputs generated by upstream code
```

Integration and parity harnesses need a throwaway Elasticsearch (not included in `cargo test`):

| Path | What it checks |
| --- | --- |
| `tests/parity/` | `seed.py` loads 3,000 deterministic documents, 23 rules cover every supported rule type and many options, `diff.py` compares the alerts of Python ElastAlert 2.31.0 and this program replaying the same range with `--debug`. Last result: **730 alerts, identical** |
| `tests/golden/` | Aggregation summary tables printed by upstream (`texttable`, markdown), compared byte for byte in a unit test |
| `tests/alerters/` | `sink.py` is a local SMTP + HTTP receiver; used to check email, Slack (two channels), post, command, partial failure and retry, recovery after restart |
| `bench/` | 400,000-document dataset and 500-rule folder behind the numbers above |

Also checked by hand: Elasticsearch 7.17.24 and OpenSearch 2.17.1 give the same alerts as 8.15 (7.17 adds `_type: _doc` to matches, as upstream does);
hot reload; `--silence` reaching a running daemon; per-alerter retry; `disable_rules_on_error` (with an injected panic, not kept in the code);
`--es_debug` / `--es_debug_trace`; the Docker image.

**Not tested**: TLS and client certificates, basic auth / API key / bearer against a secured cluster, `unix` / `unix_ms` timestamps,
degraded clusters, clusters other than single-node, Windows and macOS, load beyond the numbers above.

Reproduce the parity run (Python ElastAlert 2 installed from its repository in a virtualenv):

```sh
python3 tests/parity/seed.py http://127.0.0.1:9200
cd tests/parity            # edit config.yaml: es_host / es_port
elastalert           --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z 2> rs.log
python -m elastalert.elastalert --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z 2> py.log
python3 diff.py py.log rs.log
```

## Layout

```
src/main.rs        CLI, scheduler tasks, hot reload, startup recovery
src/engine.rs      one rule run: queries, silence/realert, aggregation, alert delivery and retry
src/types.rs       rule types and EventWindow
src/rule.rs        rule loading, imports, validation, defaults
src/config.rs      config.yaml, environment overrides
src/es.rs          Elasticsearch / OpenSearch REST client (PIT, scroll, bulk, mget, request tracing)
src/alerters.rs    email, slack, post, command
src/alert.rs       alert text (match body, subject, summary tables, jinja)
src/writeback.rs   bulk writer for the writeback indices
src/testrule.rs    test-rule and validate
src/metrics.rs     Prometheus endpoint
src/setup.rs       create-index
mappings/          writeback index mappings (from ElastAlert 2, see NOTICE)
replica/           reconnaissance notes, architecture, feature matrix and build log written while porting
```

`replica/features.csv` lists every ElastAlert 2 feature with its status here; `replica/build-log.md` records what was done, measured and found.

## License

No license file has been chosen for this repository yet. ElastAlert 2 is Apache-2.0; the writeback mappings in `mappings/` come from it,
and the behaviour, option names, log lines and document shapes are reimplemented to stay compatible (see `NOTICE`).
Decide on a license before publishing or distributing images.
