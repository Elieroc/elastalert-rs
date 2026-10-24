<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-horizontal-dark.png">
    <img src="docs/assets/logo-horizontal-light.png" alt="elastalert3: alerting for Elasticsearch" width="520">
  </picture>
</p>

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
| `notify_email` (string or list), `notify_all_errors` | supported: see below |
| `smtp_host`, `smtp_port`, `smtp_ssl`, `smtp_auth_file`, `from_addr`, `email_reply_to` | used by the email alerter **and** by `notify_email` |
| `notify_alert` | **not supported** (accepted, ignored) |
| `aws_region`, `profile` (SigV4 signing) | **not supported** |
| `replace_dots_in_field_names`, `statsd_host`, `statsd_instance_tag` | **not supported** |
| `logging:` (Python `dictConfig`) | **not supported**; logs go to stderr, level set by `--verbose` / `--debug` |

**`disable_rules_on_error`**: when a rule hits a bug (a panic in the Rust code, the equivalent of ElastAlert 2's
"uncaught exception"), an error document is written to the `_error` index and, if the option is `true` (default), the rule
is parked: it is not run again until its file changes (reload) or the daemon restarts. Other rules keep running.
Ordinary errors (Elasticsearch unreachable, bad query, missing timestamp field, alerter failure) never disable a rule; the next
run retries.

**`notify_email`**: operators are mailed when
- a rule panics (subject `Uncaught exception in ElastAlert - <rule>`, text as in ElastAlert 2 plus the panic location and a backtrace;
  it says whether the rule was disabled);
- a new or changed rule file fails to load (subject `Uncaught exception in ElastAlert - <file>`; the previous version of the rule keeps running);
- with `notify_all_errors: true`, on **every** logged error (`ElastAlert notification`, body = the error message). This can send one mail per
  rule per run while Elasticsearch is down; use it knowingly.

Recipients are `notify_email` from `config.yaml` plus the rule's own `notify_email` when it has one (de-duplicated). Mail is sent through
`smtp_host` / `smtp_port` (default `localhost:25`, STARTTLS when offered; `smtp_ssl: true` for implicit TLS; `smtp_auth_file` for login) in the
background, a failure to send is only logged. Differences from ElastAlert 2: generic error mails carry the message (upstream sends an empty
body), and SMTP port / TLS / login are honoured (upstream uses `SMTP(smtp_host)` only).

## Writing rules

Existing rules work as they are. Supported rule files can use `import:`, `is_enabled`, `$other_key$` references,
compound `query_key` / `aggregation_key` / `compare_key`, and environment variables.

### Rule types

| `type` | Status |
| --- | --- |
| `any`, `frequency`, `spike`, `flatline`, `blacklist`, `whitelist`, `change`, `new_term`, `cardinality` | supported |
| `metric_aggregation`, `percentage_match`, `spike_aggregation` | supported, see [aggregation rule types](#aggregation-rule-types) |
| custom Python rule classes | **not possible** |

`frequency`, `spike` and `flatline` also work with `use_count_query` and `use_terms_query`; `new_term` with `use_terms_query`.

#### Aggregation rule types

`metric_aggregation`, `percentage_match` and `spike_aggregation` run one Elasticsearch aggregation per query instead of fetching hits.
Options as in ElastAlert 2: `metric_agg_key`, `metric_agg_type` (`min`, `max`, `avg`, `sum`, `cardinality`, `value_count`, `percentiles` with
`percentile_range`), `metric_agg_script`, `max_threshold` / `min_threshold`, `metric_format_string`, `match_bucket_filter`,
`max_percentage` / `min_percentage`, `min_denominator`, `percentage_format_string`, `spike_height`, `spike_type`, `threshold_ref`, `threshold_cur`,
`alert_on_new_data`, `bucket_interval`, `sync_bucket_interval`, `use_run_every_query_size`, `allow_buffer_time_overlap`, `min_doc_count`, `terms_size`,
`query_key` (one terms level per key; a list works for `metric_aggregation` and `spike_aggregation`).
As upstream, such a rule only queries whole `buffer_time` segments (`run_every` with `use_run_every_query_size`): a shorter rest waits for the next run.

Rejected at load: `use_count_query` / `use_terms_query`, `ingest_timestamp_field`, a compound `query_key` on `percentage_match`
(upstream fails on it at the first match), `bucket_interval` on `spike_aggregation`.
`test-rule --data` / `--use-downloaded` cannot replay them (they need Elasticsearch to aggregate).

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
| `limit_execution` (cron, UTC), `limit_execution_coverage` | supported: outside the cron window the rule sleeps until the next one (`Pausing <rule> until next run at ...`); a rule that has not run since it was loaded does not run at all until then. Like upstream, `limit_execution_coverage` skips the time between two windows instead of catching up. Not applied to `--debug` / `--start` replays and `test-rule` (upstream would not run the rule at all there) |
| `active_hours` (**extension**, not in ElastAlert 2) | `timezone` (IANA name, default `UTC`) and `windows`, a list of `{days: [mon..sun], from: "HH:MM", to: "HH:MM"}` (`days` defaults to every day, `to` is exclusive, `from` later than `to` crosses midnight and belongs to its start day). A match whose timestamp is outside every window is ignored (`Ignoring match for rule X outside active_hours`) before realert and silence bookkeeping. The rule keeps running, so its state stays continuous. Decided on the match timestamp, so it also applies to `--start`/`--end` and `test-rule`. Daylight saving follows the timezone. ElastAlert 2 ignores the key and alerts at all hours |
| `generate_kibana_discover_url`, `kibana_url`, `kibana_discover_app_url`, `kibana_discover_index_pattern_id`, `kibana_discover_columns`, `kibana_discover_from_timedelta`, `kibana_discover_to_timedelta`, `kibana_discover_security_tenant`, `shorten_kibana_discover_url`, `kibana_discover_version`, `kibana_username` / `kibana_password` / `kibana_verify_certs` (shortener) | supported: `kibana_discover_url` is added to the first match, byte-identical to upstream's link (compared in unit tests and in `tests/parity/rules-ql`). Shortening calls Kibana's short URL API; AWS SigV4 for it is rejected at load |
| `generate_opensearch_discover_url`, `opensearch_url`, `opensearch_discover_app_url`, `opensearch_discover_index_pattern_id`, `opensearch_discover_columns`, `opensearch_discover_from_timedelta`, `opensearch_discover_to_timedelta` | supported: `opensearch_discover_url` is added to the first match. A missing app URL or index pattern id logs a warning and the alert goes out without a link, as upstream |
| `filter: [{eql: "..."}]`, `filter: [{esql: "..."}]` | supported (see [EQL and ES\|QL](#eql-and-esql-rules)) |
| `match_enhancements`, `run_enhancements_first` | supported with modules compiled into the binary: upstream's `TimeEnhancement` and the native `rust.add_field`, `rust.drop_if`, `rust.lookup`; add your own in Rust (see [docs/enhancements.md](docs/enhancements.md)). A Python class name rejects the rule at load |
| `jinja_filters` | an empty list is accepted; a non-empty one names Python classes with `filter_*` methods and the rule is rejected at load |
| `include_rule_params_in_matches`, `_source_enabled: false` | **not supported**: the rule is rejected at load with a message |
| `es_host`, `es_port`, credentials, TLS options **inside a rule** (different cluster per rule) | **not supported**: rejected unless identical to `config.yaml` |
| `ingest_timestamp_field` | **new**, see [Performance](#performance) |

Rules using an option marked "rejected" fail at load (or are skipped with `skip_invalid: true`), they are never run with different behaviour.
Options not listed anywhere are ignored, as in ElastAlert 2, so typos are not detected.

### Alerters

ElastAlert 2 has 44 alerters. **all 44 are ported** (`debug`, `email`, `slack`, `post`, `command`, the sixteen chat webhooks, the nine on-call / incident alerters, the six SOC / ticketing alerters and the eight cloud / queue / SMS alerters below); a rule naming any other alerter is rejected.

| Alerter | Status |
| --- | --- |
| `debug` | supported |
| `email` | supported: `email`, `cc`, `bcc`, `smtp_host`, `smtp_port`, `smtp_ssl`, STARTTLS, `smtp_auth_file`, `from_addr`, `email_reply_to`, `email_format: html`, `email_from_field`, `email_add_domain`. **Not**: `email_image_keys` / `assets_dir` (inline images), `smtp_cert_file` / `smtp_key_file` (a warning is logged) |
| `slack` | supported: webhook URL(s), channel overrides (one message per channel), username, emoji / icon, colour, title, fields, footer, author, image, pretext, proxy, CA file, timeout, aggregation table in a code block. `slack_attach_kibana_discover_url` / `slack_attach_opensearch_discover_url` with their colour and title. `slack_attach_jira_ticket_url` (+ `slack_jira_ticket_color`, `slack_jira_ticket_title`) links the ticket opened by the `jira` alerter of the same rule |
| `post` | supported: `http_post_url` (list), `http_post_payload`, `http_post_static_payload`, `http_post_all_values`, `http_post_headers`, proxy, CA file, timeout, ignore SSL errors |
| `command` | supported: argument list or shell string, `{field}` / `%(field)s` substitution, `pipe_match_json`, `pipe_alert_text`, `fail_on_non_zero_exit` |
| `post2` | supported: `http_post2_url` (list), Jinja `http_post2_payload` and `http_post2_headers` (values JSON-escaped as upstream, `jinja_root_name`), `http_post2_raw_fields`, `http_post2_all_values`, proxy, CA file, timeout, ignore SSL errors. Invalid templates fail at alert time, as upstream |
| `mattermost` | supported: webhook URL(s), channel overrides (one post per channel), username, emoji / icon, pretext, colour, `mattermost_msg_fields` (with `args`), title, footer, author, image, thumb, Kibana / OpenSearch Discover attachments, `alert_text_type: alert_text_only`, proxy |
| `rocketchat` | supported: webhook URL(s), channel overrides, username, emoji, colour, text, `rocket_chat_alert_fields`, Discover attachments, proxy, CA file, timeout, ignore SSL errors |
| `ms_power_automate` | supported: Adaptive Card with summary, body size, facts, Kibana / OpenSearch Discover actions, full width, `ms_power_automate_webhook_url_from_field`, proxy, CA file, ignore SSL errors |
| `discord` | supported: single webhook URL (a list is rejected), emoji title, embed colour / footer / icon, embed cropping at 2047 characters, proxy with login |
| `telegram` | supported: bot token, room id, `telegram_api_url`, `telegram_parse_mode` (markdown / html), thread id, cropping at 4095 characters, proxy with login (`telegram_proxy_login`, `telegram_proxy_pass`) |
| `googlechat` | supported: `basic` and `card` formats, card header and Kibana footer button, proxy |
| `webex_webhook` | supported: `webex_webhook_id`, `webex_webhook_msgtype` (text / markdown) |
| `matrixhookshot` | supported: webhook URL(s), username, text and html overrides, proxy, CA file, timeout, ignore SSL errors |
| `gitter` | supported: single webhook URL, `gitter_msg_level`, proxy |
| `chatwork` | supported: API key, room id, form-encoded post, cropping at 2047 characters, proxy with login |
| `line` | supported: LINE Messaging API push (`line_channel_access_token`, `line_to`), cropping at 4800 characters. Both options are required here; upstream mistypes `required_options` and never checks them |
| `lark` | supported: `lark_bot_id`, `lark_msgtype` |
| `dingtalk` | supported: `text`, `markdown`, `single_action_card`, `action_card`, `dingtalk_sign` secret, proxy with login. Another `dingtalk_msgtype` is rejected at load (upstream fails at send time). The signature is computed for every alert; upstream appends a second `timestamp`/`sign` to its stored URL on each alert |
| `workwechat` | supported: `work_wechat_bot_id`, `work_wechat_msgtype` `text` or `markdown` (other values rejected at load) |
| `yzj` | supported: `yzj_token`, `yzj_type`, `yzj_custom_loc`, proxy |
| `pagerduty` | supported: Events API v1 and v2 (`pagerduty_api_version`), `pagerduty_incident_key` with `_args`, all `pagerduty_v2_payload_*` options, proxy, CA file, ignore SSL errors, `pagerduty_event_type`. **Not**: NTLM proxy authentication (`pagerduty_proxy_login` / `pagerduty_proxy_pass` are rejected at load) |
| `opsgenie` | supported: `opsgenie_key`, account, recipients / teams with `_args` and defaults, tags, message / subject (+ `_args`), description, entity, source, alias, priority, `opsgenie_details`, `opsgenie_addr`, proxy. `.format(**match)` options fail like upstream when a field is missing (`KeyError`); only `{name}` and `{name[key]}` references are understood |
| `victorops` | supported: API key, routing key, message type, entity id / display name, proxy. The entity display name is computed per alert (upstream keeps the first one for the life of the alerter) |
| `pagertree` | supported: `pagertree_integration_url`, proxy |
| `alertmanager` | supported: several hosts, API version, alertname, Jinja `alertmanager_labels` / `alertmanager_annotations`, `alertmanager_fields`, label names for title and body, `alertmanager_resolve_time`, `jinja_root_name`, basic auth, proxy, CA file, timeout, ignore SSL errors |
| `flashduty` | supported: all `flashduty_*` options |
| `alerta` | supported: all `alerta_*` options, including `alerta_use_match_timestamp` and `alerta_use_qk_as_resource` (applied per alert; upstream overwrites its stored resource the first time). `createTime` is UTC (upstream uses the local clock labelled `Z`) |
| `datadog` | supported: API / app keys, `datadog_api_url` |
| `zabbix` | supported: `zbx_host`, `zbx_key`, `zbx_host_from_field`, `zbx_sender_host`, `zbx_sender_port`, `timestamp_strptime`; native trapper protocol, no TLS (`zbx_sender` without PSK/cert). A server-side failed item only logs a warning, as upstream |
| `jira` | supported: `jira_server`, `jira_account_file` (user + password, or `apikey` as a bearer token), project, issue type, parent, components, labels, priority (index in Jira's priority list), assignee, watchers, description, any other `jira_<field name or id>` option (typed from the field's schema, `'#match.field'` reads a match field), `jira_bump_tickets` with `jira_bump_in_statuses` / `jira_bump_not_in_statuses` / `jira_bump_after_inactivity` / `jira_max_age` / `jira_ignore_in_title` / `jira_bump_only`, `jira_transition_to`. The ticket is linked in the `email` body and the `slack` attachment (`alerts_order`: `jira` runs before the other alerters of a rule). Jira is contacted on the first alert, not at load, so `validate` works offline. Searching for an existing ticket uses `/rest/api/3/search/jql` on Jira Cloud and `/rest/api/2/search` on Server / Data Center (upstream only knows the first, so bumping never finds anything on Data Center). Upstream also appends labels to an existing ticket in memory only; that no-op is not reproduced. When a fresh ticket is left alone because it was updated recently, no link is added (upstream prints `.../browse/None`) |
| `hivealerter` | supported: `hive_connection` (host, port, API key, proxies, `hive_verify`, false by default as upstream), `hive_alert_config` with `*_args` formatting for description, title, type and source, tags, custom fields, `hive_observable_data_mapping`. `type` and `source` are required in the alert config (upstream fails with `KeyError` without them). Of each observable mapping, the first key that is not `tlp` / `message` / `tags` is the observable type |
| `iris` | supported: `alert` and `case` types, IOCs, alert context, tags, source link, customer, case template, CA file, ignore SSL errors. Another `iris_type` is rejected at load (upstream silently sends nothing) |
| `servicenow` | supported: all options. The description holds only the last match, as upstream |
| `gelf` | supported: `http` (the HTTP status is not checked, as upstream) and `tcp`, headers, CA file for HTTP, timeout. `gelf_ca_cert` with `tcp` is rejected (upstream's TLS path cannot work); another `gelf_type` is rejected at load. The `host` field is the machine's host name, without the DNS lookup of `getfqdn()` |
| `indexer` | supported: `indexer_alert_config` with field lookup (match, then rule option, else the text itself), `name` / `value` lists, `filter`, nested keys; `indexer_connection` or an `indexer_config` YAML file (same keys as `config.yaml`) with `indexer_alerts_name` |
| `sns`, `sqs`, `ses` | supported: key pair in the rule (`<alerter>_aws_access_key_id` / `_secret_access_key`), `<alerter>_aws_profile` (keys from `~/.aws/credentials` or `~/.aws/config`; `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE`), region options, and without any of these the boto3 chain: environment variables, EKS web identity (`AWS_WEB_IDENTITY_TOKEN_FILE` + `AWS_ROLE_ARN`), the default profile, ECS task role, EC2 instance role. Requests are signed with SigV4 written here (checked against botocore); `AWS_ENDPOINT_URL` / `AWS_ENDPOINT_URL_<SERVICE>` override the endpoint (LocalStack). SQS takes its region from the queue URL; SES uses the SES API, not SMTP, with `ses_email_from_field`, `ses_email_add_domain`, cc, bcc, reply-to. **Not**: profiles that assume a role, use SSO or `credential_process` (rejected with a message when the alert is sent) |
| `stomp` | supported: `stomp_hostname`, `stomp_hostport`, `stomp_login`, `stomp_password`, `stomp_destination`; STOMP 1.0 to 1.2 over plain TCP written here (no TLS, as upstream) |
| `twilio` | supported: SMS (`twilio_from_number`) and Copilot (`twilio_use_copilot`, `twilio_message_service_sid`); the message body is the rule name, as upstream |
| `exotel` | supported. Upstream sends the SMS and then always reports failure (it compares the `Response` object to 200), so the alert is retried and the SMS repeated; here the alert succeeds when Exotel answers HTTP 200 |
| `smseagle` | supported: `sms`, `ring`, `tts`, `tts_adv` message types, recipients (`smseagle_to`, `_contacts`, `_groups`), duration, voice id |
| `tencent_sms` | supported: TC3-HMAC-SHA256 signature written here (checked against the Tencent Cloud SDK), `tencent_sms_template_parm` as JSON Pointers, region, sign name |
| custom Python alerters | **not possible** |

An `alert:` entry may carry options of its own, as in ElastAlert 2: `alert: [{slack: {slack_webhook_url: ...}}, email]` lays the entry's
options over the rule's for that alerter only (alert text and subject options included), so one rule can use the same alerter twice with
different settings. `$other_key$` references are resolved against the merged options. Options that shape the query or the rule type are not
re-read per alerter. An entry must be a name or a map with exactly one alert name whose value is a map; anything else is rejected at load.

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

- Python match enhancements (Rust modules instead, see [docs/enhancements.md](docs/enhancements.md)) and custom `jinja_filters`.
- `notify_alert` (error notifications through alerters), statsd, AWS SigV4 signing of Elasticsearch requests (the SNS / SQS / SES alerters sign their own), `replace_dots_in_field_names`.
- Per-rule Elasticsearch connections, Python plugins of any kind (rule types, alerters, loaders, enhancements, filters), Python `logging:` config.
- Helm chart.
- Elasticsearch older than 7 and any cluster not listed above.
- High availability: do not run two instances against the same writeback index, they would alert twice (same as two ElastAlert 2 instances).

### EQL and ES|QL rules

Put the query in a `filter` entry, as in ElastAlert 2:

```yaml
filter:
- eql: 'any where user.name == "eve" and event.outcome == "failure"'
# or
- esql: 'FROM logs-* METADATA _id, _index, _source | WHERE event.outcome == "failure"'
```

The time range and the other `filter` entries go in the request's `filter`; one request per range, results capped at `max_query_size`
(EQL `size`; ES|QL gets `| limit <max_query_size>` appended). Neither language can be paged, so a warning is logged when the cap is reached.
The rule types that read documents (`any`, `frequency`, `spike`, `flatline`, `blacklist`, `whitelist`, `change`, `cardinality`) work;
`use_count_query`, `use_terms_query`, `top_count_keys`, `new_term` and the aggregation rule types are rejected at load.
Whole documents are fetched (no field projection). ES|QL needs Elasticsearch 8.14+, EQL 7.9+; OpenSearch has neither.
Tested on Elasticsearch 8.15.5: same alerts as ElastAlert 2 (`tests/parity/rules-ql`).

## Differences from ElastAlert 2

Deliberate or unavoidable differences in behaviour:

| Topic | ElastAlert 2 | elastalert-rs |
| --- | --- | --- |
| Documents fetched | whole `_source` for every hit | only the fields the rule type uses; the full document is fetched (`_mget`) for the few matches. Same alert text. Set `fetch_full_source: true` or `include:` to opt out |
| Failed alerter | the whole alert is marked unsent and every alerter is resent | per-alerter status in `alerters_sent` (`slack`, then `slack#2`, ... for the same alerter used twice); only failed alerters are retried (30 s doubling, max 1 h, until `alert_time_limit`) |
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
| `spike_aggregation` with an empty bucket (`avg` / `min` / `max` of no document is `null`) | the rule run fails with a `TypeError` | the value is skipped |
| Log lines | `INFO:elastalert:...` per call | same text; the two lines of a debug alert are emitted in one call so parallel rules do not interleave them |
| Concurrency | thread pool | one task per rule, `max_threads` limits concurrent runs |
| `disabled rules` log | printed every cycle | printed only when some exist |
| EQL sequence / join queries | no events, silently | the run fails with an error (only event queries work) |
| EQL `timestamp_field` | always the Elasticsearch default `@timestamp` | the rule's `timestamp_field` is sent when it is not `@timestamp` |
| Discover link that cannot be built (bad `kibana_url`, shortener unreachable) | the rule run fails and the alert is not sent | an error is logged and the alert goes out without the link |
| Discover filters | `meta.value` keeps the key order of the YAML | keys are sorted (display text of the filter pill only) |
| `TimeEnhancement` with `frequency`, `spike`, `flatline`, `cardinality` | the sentence about the time range is built from the rewritten `@timestamp`, with a time zone that depends on the host | the sentence is left out, because the timestamp is no longer one |

New options that ElastAlert 2 does not have: `ingest_timestamp_field`, `fetch_full_source`, `use_pit`, `validate`, `--es_debug_trace` with responses, the `rust.*` match enhancements (a rule using one does not load in ElastAlert 2).

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
cargo test                                   # 46 unit tests, including golden outputs generated by upstream code
```

Integration and parity harnesses need a throwaway Elasticsearch (not included in `cargo test`):

| Path | What it checks |
| --- | --- |
| `tests/parity/` | `seed.py` loads 3,000 deterministic documents, 37 rules cover every supported rule type and many options (the `agg_*` rules: the three aggregation types), `diff.py` compares the alerts of Python ElastAlert 2.31.0 and this program replaying the same range with `--debug`. Last result: **931 alerts, identical** |
| `tests/parity/rules-ql/` | EQL, ES|QL, Kibana / OpenSearch Discover links (with `kibana_discover_security_tenant`) and `TimeEnhancement`; run it with `config-ql.yaml` the same way (needs Elasticsearch 8.14+). Last result: **203 alerts, identical** |
| `tests/golden/` | Aggregation summary tables printed by upstream (`texttable`, markdown) and Discover / external URLs generated by upstream's `kibana_discover.py`, `opensearch_discover.py` and URL formatters (`discover.json`), compared in unit tests |
| `tests/alerters/` | `sink.py` is a local SMTP + HTTP receiver; used to check email, Slack (two channels), post, command, partial failure and retry, recovery after restart |
| `bench/` | 400,000-document dataset and 500-rule folder behind the numbers above |

Also checked by hand: Elasticsearch 7.17.24 and OpenSearch 2.17.1 give the same alerts as 8.15 (7.17 adds `_type: _doc` to matches, as upstream does);
hot reload; `--silence` reaching a running daemon; per-alerter retry; `disable_rules_on_error` (with an injected panic, not kept in the code);
`--es_debug` / `--es_debug_trace`; the Docker image.

**Not tested**: TLS and client certificates, basic auth / API key / bearer against a secured cluster, `unix` / `unix_ms` timestamps,
`sync_bucket_interval` / `allow_buffer_time_overlap` (they act on the start time of live runs, not on `--start` replays), degraded clusters, clusters other than single-node, Windows and macOS, load beyond the numbers above.

Reproduce the parity run (Python ElastAlert 2 installed from its repository in a virtualenv):

```sh
python3 tests/parity/seed.py http://127.0.0.1:9200
cd tests/parity            # edit config.yaml: es_host / es_port
elastalert           --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z 2> rs.log
python -m elastalert.elastalert --config config.yaml --debug --start 2026-10-01T08:00:00Z --end 2026-10-01T10:05:00Z 2> py.log
python3 diff.py py.log rs.log
```

The same with `config-ql.yaml` replays `rules-ql/` (writes to `elastalert_parity_ql*`).

## Layout

```
src/main.rs        CLI, scheduler tasks, hot reload, startup recovery
src/engine.rs      one rule run: queries, silence/realert, aggregation, alert delivery and retry
src/types.rs       rule types and EventWindow
src/rule.rs        rule loading, imports, validation, defaults
src/config.rs      config.yaml, environment overrides
src/es.rs          Elasticsearch / OpenSearch REST client (PIT, scroll, bulk, mget, request tracing)
src/alerters/     one module per alerter, shared HTTP client (http.rs), AWS credentials + SigV4 (aws.rs), HMAC / base64 (crypto.rs)
src/alert.rs       alert text (match body, subject, summary tables, jinja)
src/discover.rs    Kibana / OpenSearch Discover links (Rison, URL formatters, Kibana short URLs)
src/querylang.rs   EQL / ES|QL request and response conversion
src/enhancements.rs match_enhancements: trait, module registry, built-in modules
src/writeback.rs   bulk writer for the writeback indices
src/testrule.rs    test-rule and validate
src/metrics.rs     Prometheus endpoint
src/notify.rs      notify_email
src/setup.rs       create-index
mappings/          writeback index mappings (from ElastAlert 2, see NOTICE)
docs/              enhancements.md (match enhancement modules, writing your own)
replica/           reconnaissance notes, architecture, feature matrix and build log written while porting
```

`replica/features.csv` lists every ElastAlert 2 feature with its status here; `replica/build-log.md` records what was done, measured and found.

## License

Apache License 2.0, see [`LICENSE`](LICENSE). ElastAlert 2 is also Apache-2.0; the writeback mappings in `mappings/` come from it,
and the behaviour, option names, log lines and document shapes are reimplemented to stay compatible (see [`NOTICE`](NOTICE)).
