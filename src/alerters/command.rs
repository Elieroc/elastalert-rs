//! `command` alerter.

use super::{Doc, View, b, required, resolve_string};
use crate::alert::create_alert_body;
use crate::field::py_str;
use crate::rule::Rule;
use anyhow::{Context, Result, bail};
use serde_json::Value;

pub struct Command {
    pub(super) argv: Vec<String>,
    shell: bool,
    pipe_json: bool,
    pipe_text: bool,
    fail_on_non_zero: bool,
}

impl Command {
    pub(super) fn new(rule: &Rule) -> Result<Command> {
        required(rule, "command", "command")?;
        let (argv, shell) = match &rule.raw["command"] {
            Value::String(c) => {
                if c.contains('%') {
                    log::warn!("Warning! You could be vulnerable to shell injection!");
                }
                (vec![c.clone()], true)
            }
            Value::Array(a) => (a.iter().map(py_str).collect(), false),
            _ => bail!("command must be a string or a list"),
        };
        Ok(Command {
            argv,
            shell,
            pipe_json: b(rule, "pipe_match_json"),
            pipe_text: b(rule, "pipe_alert_text"),
            fail_on_non_zero: b(rule, "fail_on_non_zero_exit"),
        })
    }

    pub(super) async fn alert(&self, v: &View<'_>, matches: &[Doc]) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        let argv: Vec<String> = self.argv.iter().map(|a| resolve_string(a, &matches[0])).collect();
        let mut cmd = if self.shell {
            let mut c = tokio::process::Command::new("sh");
            c.arg("-c").arg(&argv[0]);
            c
        } else {
            let mut c = tokio::process::Command::new(argv.first().context("empty command")?);
            c.args(&argv[1..]);
            c
        };
        let stdin_data = if self.pipe_json {
            Some(format!("{}\n", serde_json::to_string(matches)?))
        } else if self.pipe_text {
            Some(create_alert_body(v.rule, v.rtype, matches, v.ts_fmt))
        } else {
            None
        };
        cmd.stdin(if stdin_data.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() });
        let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!("Error while running command {}: {e}", argv.join(" ")))?;
        if let (Some(data), Some(mut stdin)) = (stdin_data, child.stdin.take()) {
            let _ = stdin.write_all(data.as_bytes()).await;
        }
        if self.fail_on_non_zero {
            let status = child.wait().await?;
            if !status.success() {
                bail!("Non-zero exit code while running command {}", argv.join(" "));
            }
        } else {
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
        }
        log::info!("Alert sent to Command");
        Ok(())
    }
}
