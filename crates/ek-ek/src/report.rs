// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the certificate commands write to standard output.
//!
//! One JSON object per line, the same shape the virtual router process uses.
//! That is what a supervisor collects, and `node-agent` is the supervisor once
//! it exists (ADR-0079). Two commands write it, so the pieces they share sit
//! here rather than in one of them.
//!
//! # What never appears in a record
//!
//! Key material of any kind. A challenge token does, because the server sends
//! it in the clear and it names nothing on its own; the value it is answered
//! with does not, because that value proves the account key.

use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::{Config, validate};
use ek_ek_tls::{Failure, Reason};

/// Writes one record, flushed, so a supervisor reading the pipe sees it now
/// rather than when the buffer happens to fill.
pub fn say(record: &str) {
    use std::io::Write;
    println!("{record}");
    let _ = std::io::stdout().flush();
}

/// Seconds since the epoch.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(0))
}

/// A list of strings as a JSON array.
pub fn list(values: &[String]) -> String {
    let quoted: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", escape(value)))
        .collect();
    format!("[{}]", quoted.join(","))
}

/// Makes text safe to sit inside a JSON string.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// Reads and checks a configuration document.
///
/// Every fault is named on its own line before the failure comes back, because
/// a document with six problems in it is one an operator wants to fix in one
/// pass rather than six.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the file cannot be read, is not a
/// configuration, or does not pass validation.
pub fn read_config(path: &str, kind: &str) -> Result<Config, Failure> {
    let document = std::fs::read_to_string(path).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{path} could not be read: {error}"),
        )
    })?;
    let config: Config = serde_json::from_str(&document).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{path} is not a configuration: {error}"),
        )
    })?;

    validate(&config).map_err(|faults| {
        for fault in faults.as_slice() {
            say(&format!(
                r#"{{"kind":"{kind}","ts":{},"event":"invalid","path":"{}","code":"{}"}}"#,
                now(),
                fault.path.as_text(),
                fault.code.key()
            ));
        }
        Failure::new(Reason::Configuration, format!("{path} is not valid"))
    })?;

    Ok(config)
}

/// Reports a failure on one line.
pub fn failed(kind: &str, failure: &Failure) {
    say(&format!(
        r#"{{"kind":"{kind}","ts":{},"event":"failed","reason":"{}","detail":"{}"}}"#,
        now(),
        failure.reason().key(),
        escape(failure.detail())
    ));
}
