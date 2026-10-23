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
