# Match enhancements

A match enhancement receives each match (the document that triggered the rule, plus fields such as `num_hits`)
and can change it or drop it before it is alerted. In ElastAlert 2 these are Python classes; elastalert3 cannot
run Python, so the modules are written in Rust and compiled into the binary.

## Using them in a rule

```yaml
match_enhancements:
- TimeEnhancement                                   # upstream's built-in, no options
- rust.drop_if: {field: user.name, equals: [svc_backup, svc_monitor]}
- rust.lookup:
    field: http.response.status_code
    target: status_text
    table: {404: not found, 500: server error}
    default: other
- rust.add_field: {field: team, value: secops}
run_enhancements_first: false                       # default
```

Each entry is a module name, or a map with one module name and its options. Modules run in the order listed;
a module that drops the match stops the chain.

**When they run** (same as ElastAlert 2):

- By default, right before the alert is sent: after silence and realert, and for an aggregated alert on every
  match of the group when the group is sent. A dropped match is left out of the alert; if every match of an
  aggregation group is dropped, nothing is sent.
- With `run_enhancements_first: true`, as soon as the match is found, before aggregation. The realert silence has
  already been set at that point, so a dropped match still silences the rule (or its `query_key` value).

**Errors**: a module that fails logs `Error running match enhancement: ...` and writes an error document. The match
is then dropped (default) or kept (`run_enhancements_first`), as upstream does.

**Load-time checks**: unknown module names, unknown options and missing required options reject the rule at load,
with the error message naming the module. A Python path (`mymodule.MyEnhancement`) is rejected too.

**Compatibility**: a rule that uses a `rust.*` module will not load in ElastAlert 2. Rules that only use
`TimeEnhancement` load in both.

## Built-in modules

### `TimeEnhancement`

Upstream's module (also accepted as `elastalert.enhancements.TimeEnhancement`). Replaces `@timestamp` with a
readable local time, `2026-10-01 11:01 CEST`. No options.

Because `@timestamp` is no longer a timestamp afterwards, the time-range sentence of the `frequency`, `spike`,
`flatline` and `cardinality` alert text is left out (ElastAlert 2 prints it with a host-dependent time zone).

### `rust.add_field`

Sets a field.

| Option | Required | Meaning |
| --- | --- | --- |
| `field` | yes | dotted path to set, intermediate objects are created (`team.name`) |
| `value` | one of `value` / `copy_from` | fixed value, any YAML type |
| `copy_from` | one of `value` / `copy_from` | dotted path to copy from; nothing happens when it is missing |
| `overwrite` | no, default `true` | `false` keeps a field that already has a value |

### `rust.drop_if`

Drops the match on a condition.

| Option | Required | Meaning |
| --- | --- | --- |
| `field` | yes | dotted path to test |
| `equals` | one of `equals` / `exists` | value or list of values; compared as text, so `404` and `"404"` are the same. A list field matches when any element does |
| `exists` | one of `equals` / `exists` | `true`: drop when the field has a value; `false`: drop when it is missing or null |

### `rust.lookup`

Replaces a value through a table.

| Option | Required | Meaning |
| --- | --- | --- |
| `field` | yes | dotted path to read |
| `table` | yes | map of value to replacement; keys are compared as text |
| `target` | no, default `field` | where to write the replacement |
| `default` | no | written when the value is not in the table (or missing); without it nothing is written |

## Writing a module

A module is a type that implements the `Enhancement` trait in `src/enhancements.rs`, plus one line in the
`REGISTRY` table. Then rebuild (`cargo build --release`).

```rust
pub enum Outcome {
    Keep,
    Drop, // ElastAlert 2's DropMatchException
}

pub trait Enhancement: Send + Sync {
    fn process(&self, m: &mut Doc) -> Result<Outcome>;
}
```

`Doc` is the match as a `serde_json::Map`. Options are read once, when the rule loads; `process` runs once per
match and must not block (no network calls without a timeout, no blocking I/O on large files).

Example: a module that lowercases a field.

1. Add the type and its constructor to `src/enhancements.rs`:

   ```rust
   /// Lowercases the text value of `field`.
   struct Lowercase {
       field: String,
   }

   impl Lowercase {
       fn build(opts: &Value, _rule: &Doc) -> Result<Arc<dyn Enhancement>> {
           let o = opts_map(opts, "rust.lowercase")?;
           check_keys(o, &["field"])?;
           Ok(Arc::new(Lowercase { field: opt_str(o, "field")? }))
       }
   }

   impl Enhancement for Lowercase {
       fn process(&self, m: &mut Doc) -> Result<Outcome> {
           if let Some(s) = field::lookup(m, &self.field).and_then(Value::as_str) {
               let lower = s.to_lowercase();
               set_path(m, &self.field, Value::String(lower));
           }
           Ok(Outcome::Keep)
       }
   }
   ```

2. Register it:

   ```rust
   const REGISTRY: &[(&str, Constructor)] = &[
       // ...
       ("rust.lowercase", Lowercase::build),
   ];
   ```

3. Test it in the `tests` module at the bottom of the file:

   ```rust
   #[test]
   fn lowercase() {
       let e = one(json!({"rust.lowercase": {"field": "user.name"}}));
       let mut m = doc(json!({"user": {"name": "EVE"}}));
       e.process(&mut m).unwrap();
       assert_eq!(m["user"]["name"], json!("eve"));
   }
   ```

4. `cargo test lowercase`, then use it: `- rust.lowercase: {field: user.name}`. Check a rule with
   `elastalert --config config.yaml validate`, and its alerts with
   `elastalert test-rule rule.yaml --data docs.json --alert`.

Helpers available in the file: `opts_map` (the options as a map, with an error naming the module when they are
missing), `opt_str` (a required text option), `check_keys` (rejects unknown options), `set_path` (sets a dotted
path, creating objects), and `field::lookup` / `field::py_str` from `src/field.rs` (dotted lookup, value as text).

The constructor also receives the rule document (`_rule`), so a module can read rule-level options, as Python
enhancements read `self.rule`.

Conventions: name new modules `rust.<name>`, reject unknown options, and return an error rather than panicking
(a panic counts as an uncaught exception and, with `disable_rules_on_error`, disables the rule).
