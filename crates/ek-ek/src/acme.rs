// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `acme` command: obtain one certificate and file it.
//!
//! This is what drives one order by hand. [`obtain`] is the body of it, and
//! renewal drives the same function for every certificate that is running out
//! (ADR-0079), so nothing here is written twice.
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
use std::time::{Duration, Instant};

use ek_ek_config::{
    ACCOUNT_KEY, CertificateId, CertificateSource, Config, DnsProvider, DnsProviderConnection,
    SecretId, acme_faults, http01_listener,
};
use ek_ek_store::{Change, Secret, Snapshot, SqliteStore, Store};
use ek_ek_tls::{Challenge, Failure, Publication, Reason};

use crate::report::{failed, list, now, read_config, say};

/// The kind every record this command writes carries.
pub const KIND: &str = "acme";

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
    let config = match read_config(arguments.config, KIND) {
        Ok(config) => config,
        Err(failure) => {
            failed(KIND, &failure);
            return ExitCode::FAILURE;
        }
    };

    let id = CertificateId::new(arguments.certificate);
    match obtain(&config, arguments.data_dir, arguments.challenges, &id) {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            failed(KIND, &failure);
            ExitCode::FAILURE
        }
    }
}

/// Obtains one certificate and files it.
///
/// Separate from [`order`] because renewal drives the same thing for a list of
/// certificates and has to know why each one failed, which an exit code cannot
/// say (ADR-0079).
///
/// # Errors
///
/// Returns why the order stopped. Whether it is worth another attempt is
/// [`Failure::worth_retrying`].
pub fn obtain(
    config: &Config,
    data_dir: &str,
    challenges: &str,
    id: &CertificateId,
) -> Result<(), Failure> {
    let Some(record) = config
        .certificates
        .iter()
        .find(|certificate| &certificate.id == id)
    else {
        return Err(Failure::new(
            Reason::Configuration,
            format!("{} names no certificate", id.as_str()),
        ));
    };

    let kind = match &record.source {
        CertificateSource::AcmeHttp01 => Challenge::Http01,
        CertificateSource::AcmeDns01 { .. } => Challenge::Dns01,
        CertificateSource::ManualUpload => {
            return Err(Failure::new(
                Reason::Configuration,
                format!(
                    "{} is uploaded by hand and is not ordered from anywhere",
                    id.as_str()
                ),
            ));
        }
    };
    if record.sni_names.is_empty() {
        return Err(Failure::new(
            Reason::Configuration,
            format!("{} covers no name", id.as_str()),
        ));
    }

    // What the configuration layer reports as a warning stops the order here.
    // The same function decides both, so the two can never drift apart: a
    // certificate an operator was warned about is exactly the one an order
    // refuses, by the same name and the same code (ADR-0026, ADR-0072).
    let faults = acme_faults(config, Some(id));
    if !faults.is_empty() {
        for fault in &faults {
            say(&format!(
                r#"{{"kind":"{KIND}","ts":{},"event":"blocked","path":"{}","code":"{}"}}"#,
                now(),
                fault.path.as_text(),
                fault.code.key()
            ));
        }
        return Err(Failure::new(
            Reason::Configuration,
            format!(
                "{} cannot be ordered: {}",
                id.as_str(),
                faults
                    .iter()
                    .map(|fault| fault.code.key())
                    .collect::<Vec<&str>>()
                    .join(", ")
            ),
        ));
    }

    // Present, because `acme_faults` found nothing to say about it. Read
    // again rather than assumed, so a future rule change cannot leave this
    // reading a value nothing checked.
    let Some(settings) = config.acme.clone() else {
        return Err(Failure::new(
            Reason::Configuration,
            "the ACME settings must be there".to_owned(),
        ));
    };

    let bound = match kind {
        Challenge::Http01 => {
            let Some(listener) = http01_listener(config) else {
                return Err(Failure::new(
                    Reason::Configuration,
                    "the port 80 listener must be there".to_owned(),
                ));
            };
            let Some(bound) = config
                .vips
                .iter()
                .find(|vip| vip.id == listener.vip)
                .map(|vip| SocketAddr::new(vip.address, listener.port))
            else {
                return Err(Failure::new(
                    Reason::Configuration,
                    format!(
                        "{} is bound to a virtual address that is not defined",
                        listener.id.as_str()
                    ),
                ));
            };
            Some(bound)
        }
        // Nothing listens for a DNS-01 order. The certificate authority asks
        // a name server, which is why this is the only way a name with no
        // inbound path from the internet gets a certificate (ADR-0026).
        Challenge::Dns01 => None,
    };

    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"ordering","certificate":"{}","names":{},"challenge":"{}","directory":"{}"}}"#,
        now(),
        id.as_str(),
        list(&record.sni_names),
        kind.wire_name(),
        settings.directory_url
    ));

    let store = SqliteStore::open(Path::new(data_dir)).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{data_dir} could not be opened: {error}"),
        )
    })?;

    let mut state = match store.read() {
        Ok(Some(held)) => held,
        Ok(None) => Snapshot::new(config.clone()),
        Err(error) => {
            return Err(Failure::new(
                Reason::Configuration,
                format!("the store could not be read: {error}"),
            ));
        }
    };
    // The document is the authority on what to serve. What an earlier order
    // produced comes back with it, because only the store has ever held it and
    // dropping it would make every certificate look unobtained (ADR-0079).
    state.config = ek_ek_tls::carry_obtained(config, &state.config);

    let account = account_key(&mut state, &store)?;

    let names = record.sni_names.clone();
    let source = record.source.clone();
    let mut answering = match kind {
        Challenge::Http01 => {
            let Some(bound) = bound else {
                return Err(Failure::new(
                    Reason::Configuration,
                    "the port 80 listener must be there".to_owned(),
                ));
            };
            Answering::Http01 {
                listener: bound,
                file: challenges,
                live: Vec::new(),
            }
        }
        Challenge::Dns01 => {
            let (provider, secret) = dns_provider(config, &state, &record.source)?;
            Answering::Dns01 {
                provider,
                secret,
                live: Vec::new(),
            }
        }
    };

    let mut publish = |publication: &Publication| answering.apply(publication);
    let mut pause = |wait: std::time::Duration| std::thread::sleep(wait);

    let obtained = ek_ek_tls::obtain(&settings, &account, &names, kind, &mut publish, &mut pause)?;

    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"obtained","certificate":"{}"}}"#,
        now(),
        id.as_str()
    ));

    let upload = ek_ek_tls::inspect(&obtained.chain_pem, &obtained.key_pem, None, now()).map_err(
        |errors| {
            Failure::new(
                Reason::Protocol,
                format!(
                    "the certificate the server issued is not usable: {:?}",
                    errors.codes()
                ),
            )
        },
    )?;
    for warning in &upload.warnings {
        say(&format!(
            r#"{{"kind":"{KIND}","ts":{},"event":"warning","certificate":"{}","code":"{}"}}"#,
            now(),
            id.as_str(),
            warning.code.key()
        ));
    }

    let next = ek_ek_tls::install(&state, id, source, upload);
    store
        .write(
            &next,
            &Change::new(KIND, format!("{} obtained", id.as_str())),
        )
        .map_err(|error| {
            Failure::new(
                Reason::Configuration,
                format!("the certificate could not be stored: {error}"),
            )
        })?;

    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"stored","certificate":"{}"}}"#,
        now(),
        id.as_str()
    ));

    let served = usable(&store, id)?;
    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"usable","certificate":"{}","names":{}}}"#,
        now(),
        id.as_str(),
        list(&served)
    ));

    Ok(())
}

/// Where a challenge answer is put so the certificate authority can read it.
///
/// One type for both, because the rule they share is the one that matters:
/// nothing returns until the answer is actually reachable, and everything
/// that went up comes down again.
enum Answering<'a> {
    /// A path on the port 80 listener, answered by the traffic path.
    Http01 {
        listener: SocketAddr,
        file: &'a str,
        live: Vec<String>,
    },
    /// A TXT record at a name server.
    Dns01 {
        provider: &'a DnsProvider,
        secret: String,
        live: Vec<String>,
    },
}

impl Answering<'_> {
    /// Puts one publication in place and takes away what it replaced.
    fn apply(&mut self, publication: &Publication) -> Result<(), Failure> {
        // A publication of the other kind would be answered in the wrong
        // place and would never be found. The order builds both, so this is
        // what keeps one from reaching the other's publisher.
        publication.meant_for(self.kind())?;

        match self {
            Self::Http01 {
                listener,
                file,
                live,
            } => {
                // The traffic path answers one value per token, and the flow
                // never gives it more than one.
                let flat: BTreeMap<String, String> = publication
                    .entries
                    .iter()
                    .filter_map(|(token, values)| {
                        values.first().map(|value| (token.clone(), value.clone()))
                    })
                    .collect();
                // Recorded before the file is written, so a publication that
                // fails on the step after is still one the cleanup knows about.
                let previous = std::mem::replace(live, flat.keys().cloned().collect());
                write_challenges(file, &flat)?;
                // Confirmed before this returns, because the very next thing
                // the order does is tell the certificate authority to come and
                // read it. A server that arrives first reads a 404 and marks
                // the name invalid, and that failure is not one a retry fixes
                // (ADR-0026).
                reachable(*listener, &flat, &previous)
            }
            Self::Dns01 {
                provider,
                secret,
                live,
            } => {
                // Recorded before the write, for the same reason: a provider
                // that took the record and then failed the wait for it to
                // appear is still holding it.
                let previous =
                    std::mem::replace(live, publication.entries.keys().cloned().collect());
                let gone: Vec<String> = previous
                    .into_iter()
                    .filter(|name| !publication.entries.contains_key(name))
                    .collect();

                if !publication.entries.is_empty() {
                    // This waits until a name server answers with the record,
                    // for the same reason the listener is read back above.
                    ek_ek_tls::dns::publish(provider, secret, &publication.entries, &mut |wait| {
                        std::thread::sleep(wait)
                    })?;
                    say(&format!(
                        r#"{{"kind":"acme","ts":{},"event":"published","records":{}}}"#,
                        now(),
                        list(&publication.entries.keys().cloned().collect::<Vec<String>>())
                    ));
                }

                if !gone.is_empty() {
                    ek_ek_tls::dns::withdraw(provider, secret, &gone)?;
                    say(&format!(
                        r#"{{"kind":"acme","ts":{},"event":"withdrawn","records":{}}}"#,
                        now(),
                        list(&gone)
                    ));
                }

                Ok(())
            }
        }
    }

    const fn kind(&self) -> Challenge {
        match self {
            Self::Http01 { .. } => Challenge::Http01,
            Self::Dns01 { .. } => Challenge::Dns01,
        }
    }
}

/// The provider a DNS-01 certificate names, and the credential it uses.
///
/// The credential comes out of the store, where it sits sealed with the
/// node's master key (ADR-0018). The configuration carries only a reference
/// to it, so an exported document leaks nothing.
fn dns_provider<'a>(
    config: &'a Config,
    state: &Snapshot,
    source: &CertificateSource,
) -> Result<(&'a DnsProvider, String), Failure> {
    let CertificateSource::AcmeDns01 { provider: wanted } = source else {
        return Err(Failure::new(
            Reason::Configuration,
            "this certificate is not obtained with DNS-01".to_owned(),
        ));
    };

    let provider = config
        .dns_providers
        .iter()
        .find(|provider| &provider.id == wanted)
        .ok_or_else(|| {
            Failure::new(
                Reason::Configuration,
                format!("{} names no DNS provider", wanted.as_str()),
            )
        })?;

    let id = match &provider.connection {
        DnsProviderConnection::Rfc2136 { tsig_secret, .. } => tsig_secret,
        DnsProviderConnection::Cloudflare { api_token, .. } => api_token,
    };
    let held = state.secrets.get(id).ok_or_else(|| {
        Failure::new(
            Reason::Configuration,
            format!(
                "the credential of {} is not in the store; put it there with `ek-ek secret set --id {}`",
                provider.id.as_str(),
                id.as_str()
            ),
        )
    })?;

    let credential = String::from_utf8(held.expose().to_vec()).map_err(|_| {
        Failure::new(
            Reason::Configuration,
            format!("the credential of {} is not text", provider.id.as_str()),
        )
    })?;
    Ok((provider, credential))
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
