//! `notify_email`: mail the operators when a rule crashes, a rule file fails to load, or (with
//! `notify_all_errors`) on any logged error. Sent in the background; a failure is only logged.

use crate::alerters::{mailbox, read_account_file, send_mail};
use crate::config::Config;
use anyhow::Result;
use lettre::Message;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

pub struct Notifier {
    host: String,
    port: Option<u16>,
    ssl: bool,
    creds: Option<Credentials>,
    from: String,
    reply_to: Option<String>,
    recipients: Vec<String>,
    disable_rules_on_error: bool,
    pin_rules: bool,
}

/// A string or a list of strings.
pub fn string_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

impl Notifier {
    /// `None` when `notify_email` is not set.
    pub fn from_conf(conf: &Config, config_file: &std::path::Path, pin_rules: bool) -> Result<Option<Arc<Notifier>>> {
        let recipients = string_list(conf.raw.get("notify_email"));
        if recipients.is_empty() {
            return Ok(None);
        }
        let s = |k: &str| conf.raw.get(k).and_then(Value::as_str).map(String::from);
        Ok(Some(Arc::new(Notifier {
            host: s("smtp_host").unwrap_or_else(|| "localhost".into()),
            port: conf.raw.get("smtp_port").and_then(Value::as_u64).map(|p| p as u16),
            ssl: conf.raw.get("smtp_ssl").and_then(Value::as_bool).unwrap_or(false),
            creds: s("smtp_auth_file").map(|f| read_account_file(config_file, &f)).transpose()?,
            from: s("from_addr").unwrap_or_else(|| "ElastAlert".into()),
            reply_to: s("email_reply_to"),
            recipients,
            disable_rules_on_error: conf.raw.get("disable_rules_on_error").and_then(Value::as_bool).unwrap_or(true),
            pin_rules,
        })))
    }

    /// Queues a mail to the global recipients plus `extra` (a rule's own `notify_email`).
    pub fn send(self: &Arc<Self>, subject: String, body: String, extra: Vec<String>) {
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.deliver(subject, body, extra).await {
                log::error!("Error sending notification email: {e:#}");
            }
        });
    }

    async fn deliver(&self, subject: String, body: String, extra: Vec<String>) -> Result<()> {
        let to: BTreeSet<String> = self.recipients.iter().chain(&extra).cloned().collect();
        let joined = to.iter().cloned().collect::<Vec<_>>().join(", ");
        let mut msg = Message::builder().from(mailbox(&self.from)?).subject(subject).header(ContentType::TEXT_PLAIN);
        for t in &to {
            msg = msg.to(mailbox(t)?);
        }
        msg = msg.reply_to(mailbox(self.reply_to.as_deref().unwrap_or(&joined.split(", ").next().unwrap_or("").to_string()))?);
        let email = msg.body(body)?;
        tokio::time::timeout(std::time::Duration::from_secs(60), send_mail(&self.host, self.port, self.ssl, self.creds.as_ref(), email))
            .await
            .map_err(|_| anyhow::anyhow!("timed out"))??;
        log::info!("Sent notification email to {joined}");
        Ok(())
    }

    /// A rule hit a bug (panic): subject and text follow ElastAlert 2's "uncaught exception" mail.
    pub fn uncaught(self: &Arc<Self>, rule: &str, extra: Vec<String>, message: &str, traceback: &str) {
        let (subject, body) = uncaught_text(rule, self.disable_rules_on_error, self.pin_rules, message, traceback);
        self.send(subject, body, extra);
    }

    /// A rule file could not be loaded (new or changed file).
    pub fn rule_load_failed(self: &Arc<Self>, file: &str, extra: Vec<String>, error: &str) {
        let body = format!("{error}\n\nThe rule file {file} could not be loaded.\nIf an earlier version of the rule was running, it keeps running; fix the file and it is reloaded within one run_every.\n");
        self.send(format!("Uncaught exception in ElastAlert - {file}"), body, extra);
    }
}

pub fn uncaught_text(rule: &str, disable_rules_on_error: bool, pin_rules: bool, message: &str, traceback: &str) -> (String, String) {
    let mut body = format!("{message}\n\nThe rule {rule} has raised an uncaught exception.\n\n");
    if disable_rules_on_error {
        let modified = if pin_rules { "" } else { " or if the rule config file has been modified" };
        body.push_str(&format!("It has been disabled and will be re-enabled when ElastAlert restarts{modified}.\n\n"));
    }
    body.push_str(traceback);
    (format!("Uncaught exception in ElastAlert - {rule}"), body)
}

static LAST_PANIC: Mutex<String> = Mutex::new(String::new());

/// Remember where and how the last panic happened (location + backtrace), then run the default hook.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        *LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()) = format!("{info}\n{}", std::backtrace::Backtrace::force_capture());
        previous(info);
    }));
}

/// Location and backtrace of the most recent panic, one line per element (for the `traceback` field).
pub fn last_panic() -> Vec<String> {
    LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()).lines().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncaught_mail_text() {
        let (s, b) = uncaught_text("r1", true, false, "boom", "tb");
        assert_eq!(s, "Uncaught exception in ElastAlert - r1");
        assert_eq!(
            b,
            "boom\n\nThe rule r1 has raised an uncaught exception.\n\nIt has been disabled and will be re-enabled when ElastAlert restarts or if the rule config file has been modified.\n\ntb"
        );
        assert!(uncaught_text("r1", true, true, "m", "t").1.contains("restarts.\n\n"));
        assert!(!uncaught_text("r1", false, false, "m", "t").1.contains("disabled"));
    }
}
