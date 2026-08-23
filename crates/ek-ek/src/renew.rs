// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `renew` command: order what is running out, warn about what is not
//! ordered at all.
//!
//! A certificate that runs out stops every handshake at once and nothing in
//! the configuration looks wrong when it happens. This is what stops that: it
//! orders an ACME certificate again before a third of its lifetime is left,
//! and it warns about an uploaded one, which nothing here can renew (ADR-0026).
//!
//! This is what drives renewal until `node-agent` runs it on a timer. It is
//! the same code path the agent will call, not a second one, and the decision
//! it works from is a pure function in `ek-ek-tls` (ADR-0079).
//!
//! # Why it does not stop on the first failure
//!
//! Every certificate is independent. One whose DNS provider is unreachable
//! must not stop the one next to it from being renewed, so a failure is
//! recorded against that certificate and the sweep carries on. The exit code
//! says whether anything failed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ek_ek_config::{CertificateId, Config, WarningCode, inspect};
use ek_ek_store::{SqliteStore, Store};
use ek_ek_tls::renewal::{Attempts, Because};
use ek_ek_tls::{Failure, Reason};

use crate::report::{escape, failed, now, read_config, say};

/// The kind every record this command writes carries.
pub const KIND: &str = "renew";

/// What the attempt state is filed under, inside the data directory.
pub const STATE_FILE: &str = "renewal-state.json";

/// Everything the command was told.
pub struct Arguments<'a> {
    /// The configuration document to work from.
    pub config: &'a str,
    /// Where the store lives, and where the attempt state is kept beside it.
    pub data_dir: &'a str,
    /// Where the live challenge answers are written for the agent to deliver.
    pub challenges: &'a str,
    /// The moment to decide against, or `None` for the system clock.
    ///
    /// An operator asking "what is due next month?" and a measurement moving
    /// the clock forward want the same thing, and a container cannot have a
    /// clock of its own: it shares the host's kernel (ADR-0079).
    pub at: Option<i64>,
    /// Where to write the Prometheus exposition, when it is wanted.
    pub metrics: Option<&'a str>,
}

/// What one sweep did.
struct Outcome {
    renewed: u32,
    failed: u32,
}

/// Runs one sweep.
pub fn sweep(arguments: &Arguments<'_>) -> ExitCode {
    let config = match read_config(arguments.config, KIND) {
        Ok(config) => config,
        Err(failure) => {
            failed(KIND, &failure);
            return ExitCode::FAILURE;
        }
    };
    let at = arguments.at.unwrap_or_else(now);

    // What an earlier order produced lives in the store and nowhere else, so
    // the decision is made against the document with that carried into it. A
    // sweep reading the document alone would see every certificate as one that
    // has never been obtained and order all of them (ADR-0079).
    let config = match obtained_so_far(&config, arguments.data_dir) {
        Ok(config) => config,
        Err(failure) => {
            failed(KIND, &failure);
            return ExitCode::FAILURE;
        }
    };

    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"sweeping","at":{at},"certificates":{}}}"#,
        now(),
        config.certificates.len()
    ));

    warn(&config, at);

    if let Some(path) = arguments.metrics
        && let Err(failure) = write_metrics(path, &config, at)
    {
        failed(KIND, &failure);
        return ExitCode::FAILURE;
    }

    let state_path = state_path(arguments.data_dir);
    let mut state = match read_state(&state_path) {
        Ok(state) => state,
        Err(failure) => {
            failed(KIND, &failure);
            return ExitCode::FAILURE;
        }
    };

    let outcome = renew_due(&config, arguments, at, &mut state);

    if let Err(failure) = write_state(&state_path, &state) {
        failed(KIND, &failure);
        return ExitCode::FAILURE;
    }

    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"swept","renewed":{},"failed":{}}}"#,
        now(),
        outcome.renewed,
        outcome.failed
    ));

    if outcome.failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Orders every certificate that is due and whose backoff has run out.
fn renew_due(
    config: &Config,
    arguments: &Arguments<'_>,
    at: i64,
    state: &mut BTreeMap<CertificateId, Attempts>,
) -> Outcome {
    let mut outcome = Outcome {
        renewed: 0,
        failed: 0,
    };

    for due in ek_ek_tls::due(&config.certificates, at) {
        let id = due.certificate.id.clone();
        // Read rather than inserted. A certificate that has never failed must
        // leave nothing behind, so only a failure ever writes a record.
        let held = state.get(&id).cloned().unwrap_or_default();

        // A certificate that failed recently is left alone until its wait is
        // over. Trying again now would spend the ACME server's allowance on
        // the same fault, and the allowance belongs to the server (ADR-0077).
        if !held.ready(at) {
            say(&format!(
                r#"{{"kind":"{KIND}","ts":{},"event":"waiting","certificate":"{}","failures":{},"until":{}}}"#,
                now(),
                id.as_str(),
                held.failures,
                held.next_attempt_unix
            ));
            continue;
        }

        say(&format!(
            r#"{{"kind":"{KIND}","ts":{},"event":"renewing","certificate":"{}","because":"{}"}}"#,
            now(),
            id.as_str(),
            match due.because {
                Because::NeverObtained => "never_obtained",
                Because::RunningOut => "running_out",
            }
        ));

        match crate::acme::obtain(config, arguments.data_dir, arguments.challenges, &id) {
            Ok(()) => {
                outcome.renewed += 1;
                // The record goes rather than being reset to zero, so a
                // certificate that has never failed and one that has recovered
                // read the same way.
                state.remove(&id);
                say(&format!(
                    r#"{{"kind":"{KIND}","ts":{},"event":"renewed","certificate":"{}"}}"#,
                    now(),
                    id.as_str()
                ));
            }
            Err(failure) => {
                outcome.failed += 1;
                let held = state.entry(id.clone()).or_default();
                held.failed(failure.reason().key(), at);
                say(&format!(
                    r#"{{"kind":"{KIND}","ts":{},"event":"renewal_failed","certificate":"{}","reason":"{}","detail":"{}","failures":{},"next_attempt":{}}}"#,
                    now(),
                    id.as_str(),
                    failure.reason().key(),
                    escape(failure.detail()),
                    held.failures,
                    held.next_attempt_unix
                ));
                if held.alarming() {
                    // The alarm state itself. A notification channel is
                    // T-059's; what this owes is a state that survives the
                    // process and a line the supervisor collects (ADR-0079).
                    say(&format!(
                        r#"{{"kind":"{KIND}","ts":{},"event":"alarm","certificate":"{}","failures":{},"since":{},"reason":"{}"}}"#,
                        now(),
                        id.as_str(),
                        held.failures,
                        held.first_failed_unix,
                        held.last_reason
                    ));
                }
            }
        }
    }

    outcome
}

/// The document with what the store has already obtained carried into it.
///
/// A store that has never been written is not a fault: it is what a first run
/// looks like, and then nothing has been obtained yet.
fn obtained_so_far(document: &Config, data_dir: &str) -> Result<Config, Failure> {
    let store = SqliteStore::open(Path::new(data_dir)).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{data_dir} could not be opened: {error}"),
        )
    })?;
    let held = store.read().map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("the store could not be read: {error}"),
        )
    })?;
    Ok(held.map_or_else(
        || document.clone(),
        |state| ek_ek_tls::carry_obtained(document, &state.config),
    ))
}

/// Says what is worth telling an operator about the certificates.
///
/// Read through the same channel the API and the interface read (ADR-0072), so
/// a rule cannot say one thing here and another there.
fn warn(config: &Config, at: i64) {
    for warning in inspect(config, at) {
        if !matches!(
            warning.code,
            WarningCode::CertificateExpiringSoon | WarningCode::FrontendCertificateExpired
        ) {
            continue;
        }
        say(&format!(
            r#"{{"kind":"{KIND}","ts":{},"event":"warning","code":"{}","path":"{}"}}"#,
            now(),
            warning.code.key(),
            warning.path.as_text()
        ));
    }
}

/// Where the attempt state is kept.
fn state_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join(STATE_FILE)
}

/// Reads the attempt state, treating an absent file as an empty one.
///
/// A file that cannot be parsed is a failure rather than an empty state. A
/// state silently thrown away is a backoff that starts over, which is exactly
/// what the ACME server's allowance cannot afford.
fn read_state(path: &Path) -> Result<BTreeMap<CertificateId, Attempts>, Failure> {
    let document = match std::fs::read_to_string(path) {
        Ok(document) => document,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => {
            return Err(Failure::new(
                Reason::Configuration,
                format!("{} could not be read: {error}", path.display()),
            ));
        }
    };
    serde_json::from_str(&document).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{} is not a renewal state: {error}", path.display()),
        )
    })
}

/// Writes the attempt state back.
fn write_state(path: &Path, state: &BTreeMap<CertificateId, Attempts>) -> Result<(), Failure> {
    let document = serde_json::to_string(state).map_err(|error| {
        Failure::new(
            Reason::Protocol,
            format!("the renewal state could not be written out: {error}"),
        )
    })?;
    std::fs::write(path, document).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{} could not be written: {error}", path.display()),
        )
    })
}

/// Writes the Prometheus exposition for the certificates.
fn write_metrics(path: &str, config: &Config, at: i64) -> Result<(), Failure> {
    let text = ek_ek_tls::exposition(&config.certificates, at);
    std::fs::write(path, &text).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{path} could not be written: {error}"),
        )
    })?;
    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"metrics","path":"{}","bytes":{}}}"#,
        now(),
        escape(path),
        text.len()
    ));
    Ok(())
}
