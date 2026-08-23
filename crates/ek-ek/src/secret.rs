// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `secret set` command: put one credential into the store.
//!
//! A DNS provider's shared key and a Cloudflare token are referenced by the
//! configuration and never written into it (ADR-0018). Until the web
//! interface exists this is how they get in, and it is the same store and the
//! same sealing the certificate material uses.
//!
//! # Why the value comes from a file
//!
//! An argument is visible in the process table to every user on the machine
//! and lands in the shell's history. A file is neither, and the operator
//! already has one: the key the name server was configured with.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::{Config, SecretId};
use ek_ek_store::{Change, Secret, Snapshot, SqliteStore, Store};

/// Everything the command was told.
pub struct Arguments<'a> {
    /// Where the store lives.
    pub data_dir: &'a str,
    /// The identity the configuration refers to this credential by.
    pub id: &'a str,
    /// The file holding the value.
    pub from_file: &'a str,
    /// A configuration to start an empty store from, if it is empty.
    pub config: Option<&'a str>,
}

/// Stores one credential.
pub fn set(arguments: &Arguments<'_>) -> ExitCode {
    let value = match std::fs::read(arguments.from_file) {
        Ok(value) => value,
        Err(error) => {
            return refused(&format!(
                "{} could not be read: {error}",
                arguments.from_file
            ));
        }
    };

    // Trailing whitespace is what a file written by an editor or by
    // `tsig-keygen` ends with, and a credential with a newline glued to it
    // fails authentication in a way nobody can see by looking.
    let trimmed = String::from_utf8_lossy(&value).trim().to_owned();
    if trimmed.is_empty() {
        return refused(&format!("{} holds no value", arguments.from_file));
    }

    let store = match SqliteStore::open(Path::new(arguments.data_dir)) {
        Ok(store) => store,
        Err(error) => {
            return refused(&format!(
                "{} could not be opened: {error}",
                arguments.data_dir
            ));
        }
    };

    let mut state = match store.read() {
        Ok(Some(held)) => held,
        Ok(None) => match empty(arguments.config) {
            Ok(state) => state,
            Err(said) => return refused(&said),
        },
        Err(error) => return refused(&format!("the store could not be read: {error}")),
    };

    let id = SecretId::new(arguments.id);
    let replaced = state.secrets.contains_key(&id);
    state.secrets.insert(id, Secret::new(trimmed.into_bytes()));

    if let Err(error) = store.write(
        &state,
        &Change::new("secret", format!("{} stored", arguments.id)),
    ) {
        return refused(&format!("the credential could not be stored: {error}"));
    }

    // The identity, never the value. This line goes wherever standard output
    // goes, and a credential does not belong there.
    say(&format!(
        r#"{{"kind":"secret","ts":{},"event":"stored","id":"{}","replaced":{replaced}}}"#,
        now(),
        escape(arguments.id)
    ));
    ExitCode::SUCCESS
}

/// A state to write into a store that holds nothing yet.
fn empty(config: Option<&str>) -> Result<Snapshot, String> {
    let path = config.ok_or_else(|| {
        "the store is empty, so a configuration is needed to start it: pass --config".to_owned()
    })?;
    let document = std::fs::read_to_string(path)
        .map_err(|error| format!("{path} could not be read: {error}"))?;
    let config: Config = serde_json::from_str(&document)
        .map_err(|error| format!("{path} is not a configuration: {error}"))?;
    Ok(Snapshot::new(config))
}

fn refused(said: &str) -> ExitCode {
    say(&format!(
        r#"{{"kind":"secret","ts":{},"event":"failed","detail":"{}"}}"#,
        now(),
        escape(said)
    ));
    ExitCode::FAILURE
}

fn say(record: &str) {
    use std::io::Write;
    println!("{record}");
    let _ = std::io::stdout().flush();
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(0))
}

fn escape(value: &str) -> String {
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
