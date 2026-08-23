// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `acme` command: obtain one certificate and file it.
//!
//! This is what drives an order until `node-agent` exists to do it on a timer
//! (T-030). It is the same code path the agent will call, not a second one, so
//! nothing here has to be written twice.
//!
//! # What it reports
//!
//! One JSON object per line on standard output, the same shape the virtual
//! router process writes. That is what a supervisor collects and what a
//! measurement reads. The account key, the certificate key and the challenge
//! answers never appear in one: a token does, because the server sends it in
//! the clear and it names nothing on its own, but the value it is answered
//! with does not.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ek_ek_config::{
    ACCOUNT_KEY, CertificateId, CertificateSource, Config, SecretId, acme_faults, http01_listener,
    validate,
};
use ek_ek_store::{Change, Secret, Snapshot, SqliteStore, Store};
use ek_ek_tls::{Failure, Reason};

/// Everything the command was told.
pub struct Arguments<'a> {
    /// The configuration document to work from.
    pub config: &'a str,
    /// Where the store lives.
    pub data_dir: &'a str,
    /// Which certificate to obtain.
    pub certificate: &'a str,
    /// Where the live challenge answers are written for the agent to deliver.
    pub challenges: &'a str,
}

/// Runs one order.
pub fn order(arguments: &Arguments<'_>) -> ExitCode {
    let config = match read_config(arguments.config) {
        Ok(config) => config,
        Err(code) => return code,
    };

    let id = CertificateId::new(arguments.certificate);
    let Some(record) = config
        .certificates
        .iter()
        .find(|certificate| certificate.id == id)
    else {
        return failed(&Failure::new(
            Reason::Configuration,
            format!("{} names no certificate", arguments.certificate),
        ));
    };

    if record.source != CertificateSource::AcmeHttp01 {
        return failed(&Failure::new(
            Reason::Configuration,
            format!("{} is not obtained with HTTP-01", arguments.certificate),
        ));
    }
    if record.sni_names.is_empty() {
        return failed(&Failure::new(
            Reason::Configuration,
            format!("{} covers no name", arguments.certificate),
        ));
    }

    // What the configuration layer reports as a warning stops the order here.
    // The same function decides both, so the two can never drift apart: a
    // certificate an operator was warned about is exactly the one an order
    // refuses, by the same name and the same code (ADR-0026, ADR-0072).
    let faults = acme_faults(&config, Some(&id));
    if !faults.is_empty() {
        for fault in &faults {
            say(&format!(
                r#"{{"kind":"acme","ts":{},"event":"blocked","path":"{}","code":"{}"}}"#,
                now(),
                fault.path.as_text(),
                fault.code.key()
            ));
        }
        return failed(&Failure::new(
            Reason::Configuration,
            format!(
                "{} cannot be ordered: {}",
                arguments.certificate,
                faults
                    .iter()
                    .map(|fault| fault.code.key())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ),
        ));
    }

    // Both are present, because `acme_faults` found nothing to say about
    // either. Read again rather than assumed, so a future rule change cannot
    // leave this reading a value nothing checked.
    let (Some(settings), Some(listener)) = (config.acme.clone(), http01_listener(&config)) else {
        return failed(&Failure::new(
            Reason::Configuration,
            "the ACME settings and the port 80 listener must both be there".to_owned(),
        ));
    };
    let Some(bound) = config
        .vips
        .iter()
        .find(|vip| vip.id == listener.vip)
        .map(|vip| SocketAddr::new(vip.address, listener.port))
    else {
        return failed(&Failure::new(
            Reason::Configuration,
            format!(
                "{} is bound to a virtual address that is not defined",
                listener.id.as_str()
            ),
        ));
    };

    say(&format!(
        r#"{{"kind":"acme","ts":{},"event":"ordering","certificate":"{}","names":{},"listener":"{}","directory":"{}"}}"#,
        now(),
        id.as_str(),
        list(&record.sni_names),
        listener.id.as_str(),
        settings.directory_url
    ));

    let store = match SqliteStore::open(Path::new(arguments.data_dir)) {
        Ok(store) => store,
        Err(error) => {
            return failed(&Failure::new(
                Reason::Configuration,
                format!("{} could not be opened: {error}", arguments.data_dir),
            ));
        }
    };

    let mut state = match store.read() {
        Ok(Some(held)) => held,
        Ok(None) => Snapshot::new(config.clone()),
        Err(error) => {
            return failed(&Failure::new(
                Reason::Configuration,
                format!("the store could not be read: {error}"),
            ));
        }
    };
    // The document is the authority on what to serve. The store carries the
    // account key and, after this run, the material.
    state.config = config.clone();

    let account = match account_key(&mut state, &store) {
        Ok(key) => key,
        Err(failure) => return failed(&failure),
    };

    let names = record.sni_names.clone();
    // What was published last, so a withdrawal can be confirmed against the
    // tokens that were actually live rather than against nothing.
    let mut live: Vec<String> = Vec::new();
    let mut publish = |challenges: &BTreeMap<String, String>| {
        write_challenges(arguments.challenges, challenges)?;
        // Confirmed before this returns, because the very next thing the order
        // does is tell the certificate authority to come and read it. A server
        // that arrives first reads a 404 and marks the name invalid, and that
        // failure is not one a retry fixes (ADR-0026).
        reachable(bound, challenges, &live)?;
        live = challenges.keys().cloned().collect();
        Ok(())
    };
    let mut pause = |wait: std::time::Duration| std::thread::sleep(wait);

    let obtained = match ek_ek_tls::obtain(&settings, &account, &names, &mut publish, &mut pause) {
        Ok(obtained) => obtained,
        Err(failure) => return failed(&failure),
    };

    say(&format!(
        r#"{{"kind":"acme","ts":{},"event":"obtained","certificate":"{}"}}"#,
        now(),
        id.as_str()
    ));

    let upload = match ek_ek_tls::inspect(&obtained.chain_pem, &obtained.key_pem, None, now()) {
        Ok(upload) => upload,
        Err(errors) => {
            return failed(&Failure::new(
                Reason::Protocol,
                format!(
                    "the certificate the server issued is not usable: {:?}",
                    errors.codes()
                ),
            ));
        }
    };
    for warning in &upload.warnings {
        say(&format!(
            r#"{{"kind":"acme","ts":{},"event":"warning","certificate":"{}","code":"{}"}}"#,
            now(),
            id.as_str(),
            warning.code.key()
        ));
    }

    let next = ek_ek_tls::install(&state, &id, CertificateSource::AcmeHttp01, upload);
    if let Err(error) = store.write(
        &next,
        &Change::new("acme", format!("{} obtained", id.as_str())),
    ) {
        return failed(&Failure::new(
            Reason::Configuration,
            format!("the certificate could not be stored: {error}"),
        ));
    }

    say(&format!(
        r#"{{"kind":"acme","ts":{},"event":"stored","certificate":"{}"}}"#,
        now(),
        id.as_str()
    ));

    match usable(&store, &id) {
        Ok(names) => say(&format!(
            r#"{{"kind":"acme","ts":{},"event":"usable","certificate":"{}","names":{}}}"#,
            now(),
            id.as_str(),
            list(&names)
        )),
        Err(failure) => return failed(&failure),
    }

    ExitCode::SUCCESS
}

/// Reads the certificate back out of the store and checks it can be served.
///
/// The material went in sealed with the node's master key (ADR-0018), so this
/// is what says it comes back intact: the chain parses, the key opens, and the
/// two still belong together. Without it, a fault in the sealing would only
/// show up as a handshake that fails on a certificate the interface called
/// stored.
///
/// Returns the names the certificate covers, which is what a TLS listener
/// matches an incoming handshake against.
fn usable(store: &SqliteStore, id: &CertificateId) -> Result<Vec<String>, Failure> {
    let state = store
        .read()
        .map_err(|error| {
            Failure::new(
                Reason::Configuration,
                format!("the store could not be read back: {error}"),
            )
        })?
        .ok_or_else(|| {
            Failure::new(
                Reason::Configuration,
                "the store holds nothing after the write".to_owned(),
            )
        })?;

    let chain = state
        .secrets
        .get(&ek_ek_tls::chain_id(id))
        .ok_or_else(|| Failure::new(Reason::Configuration, "the chain is not in the store"))?;
    let key = state
        .secrets
        .get(&ek_ek_tls::key_id(id))
        .ok_or_else(|| Failure::new(Reason::Configuration, "the key is not in the store"))?;

    let read = ek_ek_tls::inspect(chain.expose(), key.expose(), None, now()).map_err(|errors| {
        Failure::new(
            Reason::Configuration,
            format!(
                "what came back out of the store cannot be served: {:?}",
                errors.codes()
            ),
        )
    })?;
    Ok(read.sni_names)
}

/// Reads and checks the configuration document.
fn read_config(path: &str) -> Result<Config, ExitCode> {
    let document = std::fs::read_to_string(path).map_err(|error| {
        failed(&Failure::new(
            Reason::Configuration,
            format!("{path} could not be read: {error}"),
        ))
    })?;
    let config: Config = serde_json::from_str(&document).map_err(|error| {
        failed(&Failure::new(
            Reason::Configuration,
            format!("{path} is not a configuration: {error}"),
        ))
    })?;

    validate(&config).map_err(|faults| {
        for fault in faults.as_slice() {
            say(&format!(
                r#"{{"kind":"acme","ts":{},"event":"invalid","path":"{}","code":"{}"}}"#,
                now(),
                fault.path.as_text(),
                fault.code.key()
            ));
        }
        failed(&Failure::new(
            Reason::Configuration,
            format!("{path} is not valid"),
        ))
    })?;

    Ok(config)
}

/// Reads the account key, generating and storing one the first time.
///
/// One key for the whole installation, under a fixed identity: the server
/// recognises the account by the key, so a second one would be a second
/// account and a second rate limit allowance to lose track of (ADR-0026).
fn account_key(state: &mut Snapshot, store: &SqliteStore) -> Result<ek_ek_tls::Account, Failure> {
    let id = SecretId::new(ACCOUNT_KEY);

    if let Some(held) = state.secrets.get(&id) {
        return ek_ek_tls::account_from_pem(held.expose());
    }

    let generated = ek_ek_tls::account_key()?;
    state
        .secrets
        .insert(id, Secret::new(ek_ek_tls::account_to_pem(&generated)?));
    store
        .write(state, &Change::new("acme", "account key generated"))
        .map_err(|error| {
            Failure::new(
                Reason::Configuration,
                format!("the account key could not be stored: {error}"),
            )
        })?;

    say(&format!(
        r#"{{"kind":"acme","ts":{},"event":"account_key_created"}}"#,
        now()
    ));
    Ok(generated)
}

/// How long an answer is given to become reachable on the listener.
///
/// The agent has to deliver the change and the traffic path has to swap it in.
/// Both take milliseconds; this is generous enough that a loaded machine still
/// makes it and short enough that a listener which will never answer is a
/// failure rather than a hang.
const REACHABLE_WITHIN: Duration = Duration::from_secs(10);

/// How often the listener is asked while waiting.
const REACHABLE_POLL: Duration = Duration::from_millis(100);

/// Waits until the listener serves exactly what was published.
///
/// Both directions are confirmed. A token that went up has to answer with its
/// value, and a token that came down has to stop answering, because a path
/// left open after an order is an endpoint nobody is watching.
fn reachable(
    listener: SocketAddr,
    published: &BTreeMap<String, String>,
    withdrawn: &[String],
) -> Result<(), Failure> {
    let gone: Vec<&String> = withdrawn
        .iter()
        .filter(|token| !published.contains_key(*token))
        .collect();

    let deadline = Instant::now() + REACHABLE_WITHIN;
    let mut last = String::new();
    loop {
        let mut settled = true;
        for (token, answer) in published {
            match served(listener, token) {
                Some(body) if body == *answer => {}
                other => {
                    settled = false;
                    last = format!("{token} answers {other:?}");
                }
            }
        }
        for token in &gone {
            if let Some(body) = served(listener, token) {
                settled = false;
                last = format!("{token} still answers {body}");
            }
        }
        if settled {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Failure::new(
                Reason::Configuration,
                format!(
                    "the listener on {listener} did not settle within {}s: {last}",
                    REACHABLE_WITHIN.as_secs()
                ),
            ));
        }
        std::thread::sleep(REACHABLE_POLL);
    }
}

/// What the listener answers on one challenge path, if anything.
fn served(listener: SocketAddr, token: &str) -> Option<String> {
    let agent = ureq::config::Config::builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .new_agent();
    let mut response = agent
        .get(format!(
            "http://{listener}/.well-known/acme-challenge/{token}"
        ))
        .call()
        .ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    response.body_mut().read_to_string().ok()
}

/// Writes the live challenge answers where the agent reads them.
///
/// Written whole every time, including the empty map that closes the path.
/// A file that is only ever added to would leave every token from every order
/// answerable for as long as the process lives.
fn write_challenges(path: &str, challenges: &BTreeMap<String, String>) -> Result<(), Failure> {
    let document = serde_json::to_string(challenges).map_err(|error| {
        Failure::new(
            Reason::Protocol,
            format!("the challenge answers could not be written out: {error}"),
        )
    })?;
    std::fs::write(path, document).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{path} could not be written: {error}"),
        )
    })?;

    if challenges.is_empty() {
        say(&format!(
            r#"{{"kind":"acme","ts":{},"event":"withdrawn"}}"#,
            now()
        ));
    } else {
        // The token, never the answer. The token is what the server sends in
        // the clear and names nothing by itself; the answer is what proves the
        // account key, and a log is not where it belongs.
        say(&format!(
            r#"{{"kind":"acme","ts":{},"event":"published","tokens":{}}}"#,
            now(),
            list(&challenges.keys().cloned().collect::<Vec<String>>())
        ));
    }
    Ok(())
}

/// Reports a failure and stops.
fn failed(failure: &Failure) -> ExitCode {
    say(&format!(
        r#"{{"kind":"acme","ts":{},"event":"failed","reason":"{}","detail":"{}"}}"#,
        now(),
        failure.reason().key(),
        escape(failure.detail())
    ));
    ExitCode::FAILURE
}

/// Writes one record, flushed, so a supervisor reading the pipe sees it now
/// rather than when the buffer happens to fill.
fn say(record: &str) {
    use std::io::Write;
    println!("{record}");
    let _ = std::io::stdout().flush();
}

/// Seconds since the epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| i64::try_from(since.as_secs()).unwrap_or(0))
}

/// A list of strings as a JSON array.
fn list(values: &[String]) -> String {
    let quoted: Vec<String> = values
        .iter()
        .map(|value| format!("\"{}\"", escape(value)))
        .collect();
    format!("[{}]", quoted.join(","))
}

/// Makes text safe to sit inside a JSON string.
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
