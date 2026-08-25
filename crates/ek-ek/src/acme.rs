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
    NodeId, SecretId, acme_faults, http01_listener,
};
use ek_ek_store::{Change, OrderChallenge, OrderRecord, Secret, Snapshot, SqliteStore, Store as _};
use ek_ek_tls::{Challenge, Failure, Reached, Reason};

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

/// Where an order reads the state it works from and files what it produces.
///
/// A trait because the same order runs in two places. On one node the state is
/// the local store; in a cluster it is the replicated state, and a write there
/// has to be agreed by a quorum before it counts (ADR-0086). Everything else
/// about the order is identical, and a second implementation of it would be
/// two places for the flow to drift apart.
pub trait Filing {
    /// The state this node holds.
    ///
    /// # Errors
    ///
    /// Returns why the state could not be read.
    fn read(&self) -> Result<Option<Snapshot>, Failure>;

    /// Reads the state, changes it and writes it back as one step.
    ///
    /// One call rather than a read and a write, because the node process has
    /// two writers: the loop that applies a configuration file and the task
    /// that drives an order. Two overlapping read-modify-writes lose whichever
    /// change landed first, and the one that gets lost is a challenge answer
    /// the certificate authority is about to ask for (ADR-0083, ADR-0086).
    ///
    /// `edit` is called exactly once. Nothing here retries a refused write: a
    /// refusal is a state of the cluster, and the caller decides what to do
    /// about it.
    ///
    /// # Errors
    ///
    /// Returns why the state could not be written. In a cluster that includes
    /// having no quorum, which is what stops an order being started at all.
    fn update(
        &self,
        change: &Change,
        edit: &mut dyn FnMut(Option<Snapshot>) -> Result<Snapshot, Failure>,
    ) -> Result<(), Failure>;
}

/// A store on this node, and nothing else.
pub struct Local<'a> {
    store: &'a SqliteStore,
}

impl<'a> Local<'a> {
    /// Files into the store given.
    #[must_use]
    pub const fn new(store: &'a SqliteStore) -> Self {
        Self { store }
    }
}

impl Filing for Local<'_> {
    fn read(&self) -> Result<Option<Snapshot>, Failure> {
        self.store.read().map_err(|error| {
            Failure::new(
                Reason::Configuration,
                format!("the store could not be read: {error}"),
            )
        })
    }

    fn update(
        &self,
        change: &Change,
        edit: &mut dyn FnMut(Option<Snapshot>) -> Result<Snapshot, Failure>,
    ) -> Result<(), Failure> {
        let next = edit(self.read()?)?;
        self.store
            .write(&next, change)
            .map(|_| ())
            .map_err(|error| {
                Failure::new(
                    Reason::Configuration,
                    format!("the state could not be written: {error}"),
                )
            })
    }
}

/// How the challenge answer reaches a traffic path.
#[derive(Clone, Copy, Debug)]
pub enum Delivery<'a> {
    /// Written straight to the file the agent reads.
    ///
    /// One node, one order, one process: nothing else is watching the state,
    /// so the order writes the file itself.
    File(&'a str),
    /// Left in the state for every node's own process to write out.
    ///
    /// A cluster. The answer replicates and each node writes its own file, so
    /// the certificate authority is answered by whichever node the name
    /// resolves to, and by one that is not driving the order (ADR-0032).
    Replicated,
}

/// Everything one order needs.
pub struct Order<'a> {
    /// The configuration to work from.
    pub config: &'a Config,
    /// Where the state is read and written.
    pub filing: &'a dyn Filing,
    /// How the challenge answer reaches a traffic path.
    pub delivery: Delivery<'a>,
    /// Which certificate to obtain.
    pub id: &'a CertificateId,
    /// Which node is driving, when one is running in a cluster.
    pub driver: Option<&'a NodeId>,
    /// How the order waits between attempts.
    ///
    /// `None` sleeps, which is what a node does. A measurement passes a wait
    /// that returns at once, for the same reason the driver underneath takes
    /// one: five attempts span fifteen minutes, and no measurement of what
    /// happens after them can afford to sit through that (ADR-0026).
    pub pause: Option<&'a dyn Fn(Duration)>,
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
    let store = SqliteStore::open(Path::new(data_dir)).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{data_dir} could not be opened: {error}"),
        )
    })?;
    obtain_order(&Order {
        config,
        filing: &Local::new(&store),
        delivery: Delivery::File(challenges),
        id,
        driver: None,
        pause: None,
    })
}

/// Obtains one certificate the way the order says.
///
/// # Errors
///
/// The same as [`obtain`].
#[allow(clippy::too_many_lines)]
pub fn obtain_order(order: &Order<'_>) -> Result<(), Failure> {
    let config = order.config;
    let id = order.id;
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

    let filing = order.filing;
    let names = record.sni_names.clone();
    let source = record.source.clone();

    let account = account_key(filing, config)?;

    // The order record, either taken over or opened. Whichever it is, the
    // signing key is in the state before the certificate authority is asked
    // anything, so a node taking the order over can finish it (ADR-0086).
    let opened = open_order(filing, order, kind, &names)?;
    // A key that does not open closes the order rather than failing on it.
    // Leaving the record in place would hand the same unusable order to every
    // node that leads after this one, and none of them could finish it either
    // (ADR-0086).
    let key = match ek_ek_tls::key_from_pem(opened.key_pem.expose()) {
        Ok(key) => key,
        Err(failure) => {
            close_order(filing, order)?;
            return Err(failure);
        }
    };

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
                file: match order.delivery {
                    Delivery::File(path) => Some(path),
                    Delivery::Replicated => None,
                },
                live: Vec::new(),
            }
        }
        Challenge::Dns01 => {
            let held = filing.read()?.ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    "the state went away before the DNS credential could be read".to_owned(),
                )
            })?;
            let (provider, secret) = dns_provider(config, &held, &record.source)?;
            Answering::Dns01 {
                provider,
                secret,
                live: Vec::new(),
            }
        }
    };

    // What has to outlive this process goes into the state before the request
    // that depends on it goes out. The order URL first, so a node taking over
    // knows where to look; then the answer, so the server that is about to be
    // told to check finds something there (ADR-0086).
    let mut record_reached = |reached: &Reached| {
        file_reached(filing, order, reached)?;
        answering.apply(reached)
    };
    let mut pause = |wait: Duration| match order.pause {
        Some(wait_with) => wait_with(wait),
        None => std::thread::sleep(wait),
    };

    let driven = ek_ek_tls::obtain_planned(
        &settings,
        &account,
        &names,
        kind,
        ek_ek_tls::Plan {
            key: Some(&key),
            resume: opened.resume.as_deref(),
        },
        &mut record_reached,
        &mut pause,
    );

    // The record goes on every path out, so the only thing that ever leaves
    // one behind is a node that stopped. That is what makes a record another
    // node finds a half finished order rather than an abandoned one, and it is
    // what keeps a permanently failing order from being taken over for ever
    // (ADR-0086).
    let obtained = match driven {
        Ok(obtained) => obtained,
        Err(failure) => {
            close_order(filing, order)?;
            return Err(failure);
        }
    };

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

    // The certificate and the end of the order in one write. Two writes would
    // let a node fall between them and leave an order nobody is driving beside
    // a certificate that was already obtained.
    // Held in an option because the material moves into the state and the edit
    // runs once. Deriving a copy on the type instead would make a second copy
    // of a private key easy to leave lying about.
    let mut material = Some((source, upload));
    filing.update(
        &Change::new(KIND, format!("{} obtained", id.as_str())),
        &mut |held| {
            let (source, upload) = material.take().ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    "the certificate was offered to the state twice".to_owned(),
                )
            })?;
            let held = held.unwrap_or_else(|| Snapshot::new(config.clone()));
            let mut next = ek_ek_tls::install(&held, id, source, upload);
            next.orders.remove(id);
            next.secrets.remove(&ek_ek_tls::order_key_id(id));
            Ok(next)
        },
    )?;

    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"stored","certificate":"{}"}}"#,
        now(),
        id.as_str()
    ));

    let served = usable(filing, id)?;
    say(&format!(
        r#"{{"kind":"{KIND}","ts":{},"event":"usable","certificate":"{}","names":{}}}"#,
        now(),
        id.as_str(),
        list(&served)
    ));

    Ok(())
}

/// An order that is ready to be driven.
struct Opened {
    /// The key the certificate will be issued against, as PEM.
    key_pem: Secret,
    /// The order to take over, when one was already placed.
    resume: Option<String>,
}

/// Opens the order record, or picks up the one that is already there.
///
/// Written before the certificate authority is asked anything. The signing key
/// goes in with it, because the certificate is issued against that key and a
/// node taking the order over would otherwise download something it cannot
/// serve (ADR-0086).
fn open_order(
    filing: &dyn Filing,
    order: &Order<'_>,
    kind: Challenge,
    names: &[String],
) -> Result<Opened, Failure> {
    let id = order.id;
    let key_id = ek_ek_tls::order_key_id(id);

    if let Some(held) = filing
        .read()?
        .and_then(|state| state.orders.get(id).cloned())
    {
        let key = filing
            .read()?
            .and_then(|state| state.secrets.get(&held.key).cloned())
            .ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    format!(
                        "{} is running an order whose signing key is not in the state, \
                         so it cannot be taken over",
                        id.as_str()
                    ),
                )
            })?;
        say(&format!(
            r#"{{"kind":"{KIND}","ts":{},"event":"taking_over","certificate":"{}","placed":{}}}"#,
            now(),
            id.as_str(),
            held.placed()
        ));
        return Ok(Opened {
            key_pem: key,
            resume: held.order_url.clone(),
        });
    }

    let key_pem = Secret::new(ek_ek_tls::key_to_pem(&ek_ek_tls::generate()?)?);
    let opening = OrderRecord {
        names: names.to_vec(),
        challenge: match kind {
            Challenge::Http01 => OrderChallenge::Http01,
            Challenge::Dns01 => OrderChallenge::Dns01,
        },
        order_url: None,
        key: key_id.clone(),
        answers: BTreeMap::new(),
        driven_by: order.driver.cloned(),
        started_at_unix: now(),
    };
    filing.update(
        &Change::new(KIND, format!("{} order opened", id.as_str())),
        &mut |held| {
            let mut next = held.ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    "the state went away before the order could be opened".to_owned(),
                )
            })?;
            next.secrets.insert(key_id.clone(), key_pem.clone());
            next.orders.insert(id.clone(), opening.clone());
            Ok(next)
        },
    )?;

    Ok(Opened {
        key_pem,
        resume: None,
    })
}

/// Puts what the order has reached into the state.
///
/// Read and written whole, like every other write in this product, so a
/// certificate another process obtained while this order ran is not thrown
/// away by it.
fn file_reached(filing: &dyn Filing, order: &Order<'_>, reached: &Reached) -> Result<(), Failure> {
    let id = order.id;
    // The traffic path answers one value per token, and the flow never gives
    // it more than one. A DNS-01 answer is not here at all: it sits at a name
    // server, which no node in this cluster is.
    let answers: BTreeMap<String, String> = match reached.publication.kind {
        Some(ek_ek_tls::Challenge::Http01) => reached
            .publication
            .entries
            .iter()
            .filter_map(|(token, values)| {
                values.first().map(|value| (token.clone(), value.clone()))
            })
            .collect(),
        _ => BTreeMap::new(),
    };

    filing.update(
        &Change::new(KIND, format!("{} order progressed", id.as_str())),
        &mut |held| {
            let mut next = held.ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    "the state went away while the order was running".to_owned(),
                )
            })?;
            let record = next.orders.get_mut(id).ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    format!(
                        "the order record of {} went away while the order was running",
                        id.as_str()
                    ),
                )
            })?;
            record.order_url.clone_from(&reached.order_url);
            record.answers.clone_from(&answers);
            record.driven_by = order.driver.cloned();
            Ok(next)
        },
    )
}

/// Takes the order record and its signing key away.
///
/// Called on every path out of a failed order. A record left behind would be
/// taken over by the next leader for ever, and a key left behind would be a
/// private key kept for a certificate nobody obtained.
fn close_order(filing: &dyn Filing, order: &Order<'_>) -> Result<(), Failure> {
    let id = order.id;
    if filing
        .read()?
        .is_none_or(|state| !state.orders.contains_key(id))
    {
        return Ok(());
    }
    filing.update(
        &Change::new(KIND, format!("{} order closed", id.as_str())),
        &mut |held| {
            let mut next = held.ok_or_else(|| {
                Failure::new(
                    Reason::Configuration,
                    "the state went away while the order was being closed".to_owned(),
                )
            })?;
            next.orders.remove(id);
            next.secrets.remove(&ek_ek_tls::order_key_id(id));
            Ok(next)
        },
    )
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
        /// Where to write the answers, when this process writes them itself.
        ///
        /// `None` in a cluster: the answers travel in the state and every
        /// node's own process writes its own file, this one included, so the
        /// wait below measures the path every node uses (ADR-0086).
        file: Option<&'a str>,
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
    fn apply(&mut self, reached: &Reached) -> Result<(), Failure> {
        let publication = &reached.publication;
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
                if let Some(path) = file {
                    write_challenges(path, &flat)?;
                }
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
fn usable(filing: &dyn Filing, id: &CertificateId) -> Result<Vec<String>, Failure> {
    let state = filing.read()?.ok_or_else(|| {
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
fn account_key(filing: &dyn Filing, config: &Config) -> Result<ek_ek_tls::Account, Failure> {
    let id = SecretId::new(ACCOUNT_KEY);

    if let Some(held) = filing
        .read()?
        .as_ref()
        .and_then(|state| state.secrets.get(&id))
    {
        return ek_ek_tls::account_from_pem(held.expose());
    }

    let generated = ek_ek_tls::account_key()?;
    let pem = ek_ek_tls::account_to_pem(&generated)?;
    filing.update(&Change::new("acme", "account key generated"), &mut |held| {
        let mut next = held.unwrap_or_else(|| Snapshot::new(config.clone()));
        // The document is the authority on what to serve. What an earlier
        // order produced comes back with it, because only the store has
        // ever held it and dropping it would make every certificate look
        // unobtained (ADR-0079).
        next.config = ek_ek_tls::carry_obtained(config, &next.config);
        next.secrets.insert(id.clone(), Secret::new(pem.clone()));
        Ok(next)
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

#[cfg(test)]
mod tests {
    // A measurement may panic on a broken precondition. Product code may not.
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        BTreeMap, CertificateId, Change, Config, Delivery, Duration, Failure, Filing, NodeId,
        Order, OrderChallenge, OrderRecord, Reason, Secret, SecretId, Snapshot, obtain_order,
    };

    const CERTIFICATE: &str = "cert-lab";

    /// A real signing key, because a record carrying anything else is a record
    /// no node could finish the order with.
    fn key_pem() -> Vec<u8> {
        ek_ek_tls::key_to_pem(&ek_ek_tls::generate().expect("a key")).expect("it writes out")
    }

    /// A state this measurement holds, and every write it was asked for.
    struct Watched {
        held: Mutex<Option<Snapshot>>,
        written: Mutex<Vec<Snapshot>>,
        refuse: Option<Reason>,
    }

    impl Watched {
        fn holding(state: Option<Snapshot>) -> Self {
            Self {
                held: Mutex::new(state),
                written: Mutex::new(Vec::new()),
                refuse: None,
            }
        }

        fn refusing(reason: Reason) -> Self {
            Self {
                held: Mutex::new(Some(Snapshot::new(config()))),
                written: Mutex::new(Vec::new()),
                refuse: Some(reason),
            }
        }

        fn written(&self) -> Vec<Snapshot> {
            self.written.lock().expect("nothing else holds it").clone()
        }

        fn now(&self) -> Option<Snapshot> {
            self.held.lock().expect("nothing else holds it").clone()
        }
    }

    impl Filing for Watched {
        fn read(&self) -> Result<Option<Snapshot>, Failure> {
            Ok(self.now())
        }

        fn update(
            &self,
            _change: &Change,
            edit: &mut dyn FnMut(Option<Snapshot>) -> Result<Snapshot, Failure>,
        ) -> Result<(), Failure> {
            if let Some(reason) = self.refuse {
                return Err(Failure::new(reason, "the cluster could not agree"));
            }
            let state = edit(self.now())?;
            self.written
                .lock()
                .expect("nothing else holds it")
                .push(state.clone());
            *self.held.lock().expect("nothing else holds it") = Some(state);
            Ok(())
        }
    }

    /// A port nothing is listening on.
    ///
    /// Bound and released, so the number is one the operating system handed
    /// out rather than one this file guessed and something else may hold.
    fn closed_port() -> u16 {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = socket.local_addr().expect("the port is readable").port();
        drop(socket);
        port
    }

    /// A listener that counts what reaches it and answers nothing.
    fn counting_port() -> (u16, std::sync::Arc<AtomicUsize>) {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
        let port = socket.local_addr().expect("the port is readable").port();
        let reached = std::sync::Arc::new(AtomicUsize::new(0));
        let held = std::sync::Arc::clone(&reached);
        std::thread::spawn(move || {
            for stream in socket.incoming() {
                if stream.is_err() {
                    return;
                }
                held.fetch_add(1, Ordering::SeqCst);
            }
        });
        (port, reached)
    }

    /// A configuration whose ACME server is at the port given.
    fn config_at(port: u16) -> Config {
        let document = format!(
            r#"{{
  "schema_version": 1,
  "nodes": [{{"id":"node1","address":"127.0.0.1","roles":["control_plane","data_plane"]}}],
  "vips": [{{"id":"vip","address":"127.0.0.1","prefix_length":8,"interface":"lo","preferred_node":"node1"}}],
  "frontends": [{{
    "id": "web",
    "vip": "vip",
    "port": 80,
    "transport": "tcp",
    "application": "http",
    "tls": null,
    "proxy_protocol": "disabled",
    "routing_rules": [],
    "sni_rules": [],
    "default_backend": "pool",
    "http2": "enabled",
    "connect_timeout_seconds": 5,
    "request_timeout_seconds": 30,
    "idle_timeout_seconds": 0,
    "drain_timeout_seconds": 5,
    "udp_session_limit": 0
  }}],
  "backends": [{{
    "id": "pool",
    "algorithm": "round_robin",
    "members": [{{"id":"one","address":"127.0.0.1","port":8080,"weight":1,"admin_state":"enabled"}}],
    "health_check": null,
    "stickiness": {{"mode":"disabled"}},
    "connection_pooling": "enabled",
    "connection_pool_size": 0,
    "connection_lifetime_seconds": 0
  }}],
  "certificates": [{{
    "id": "{CERTIFICATE}",
    "sni_names": ["lab.example.test"],
    "source": {{"type":"acme_http01"}},
    "validity": null,
    "chain": null,
    "private_key": null
  }}],
  "dns_providers": [],
  "acme": {{
    "directory_url": "https://127.0.0.1:{port}/dir",
    "contact_email": "yonetici@example.test",
    "accepted_terms": true,
    "trusted_root_pem": ""
  }}
}}"#
        );
        serde_json::from_str(&document).expect("the document is a configuration")
    }

    fn config() -> Config {
        config_at(1)
    }

    /// Runs one order that cannot reach its server, and returns why it stopped.
    fn against(filing: &Watched, config: &Config, node: Option<&NodeId>) -> Failure {
        let nothing = |_: Duration| {};
        obtain_order(&Order {
            config,
            filing,
            delivery: Delivery::Replicated,
            id: &CertificateId::new(CERTIFICATE),
            driver: node,
            // Five attempts span fifteen minutes of waiting, and what is being
            // measured here is what the state holds afterwards.
            pause: Some(&nothing),
        })
        .expect_err("a server nothing listens on cannot issue a certificate")
    }

    /// The order key of the certificate being measured.
    fn key_id() -> SecretId {
        ek_ek_tls::order_key_id(&CertificateId::new(CERTIFICATE))
    }

    #[test]
    fn an_order_records_itself_and_its_signing_key_in_one_write() {
        let filing = Watched::holding(None);
        let config = config_at(closed_port());
        against(&filing, &config, Some(&NodeId::new("node2")));

        let opened = filing
            .written()
            .into_iter()
            .find(|state| state.orders.contains_key(&CertificateId::new(CERTIFICATE)))
            .expect(
                "the order was never written down, so a node taking over would \
                 find nothing and the certificate authority's allowance would be \
                 spent again",
            );

        let record = opened
            .orders
            .get(&CertificateId::new(CERTIFICATE))
            .expect("it is there");
        assert_eq!(record.challenge, OrderChallenge::Http01);
        assert_eq!(record.names, vec!["lab.example.test".to_owned()]);
        assert_eq!(record.driven_by, Some(NodeId::new("node2")));
        assert_eq!(
            record.order_url, None,
            "the record claimed the server had named the order before anything reached it"
        );

        // The key is in the same write. Two writes would let a node fall
        // between them and leave an order whose key nobody holds (ADR-0086).
        assert!(
            opened.secrets.contains_key(&record.key),
            "the order was written without the key it will be finalised against"
        );
        assert_eq!(record.key, key_id());
    }

    #[test]
    fn an_order_that_failed_takes_its_record_and_its_key_away() {
        let filing = Watched::holding(None);
        let config = config_at(closed_port());
        against(&filing, &config, None);

        let held = filing.now().expect("something was written");
        assert!(
            held.orders.is_empty(),
            "a failed order stayed in the state, so the next node to lead \
             would take it over for ever"
        );
        assert!(
            !held.secrets.contains_key(&key_id()),
            "the signing key of a failed order stayed in the state"
        );
        // The account key stays. It belongs to the installation rather than to
        // the order, and a second one would be a second rate limit allowance.
        assert!(
            held.secrets
                .contains_key(&SecretId::new(ek_ek_config::ACCOUNT_KEY)),
            "the account key went away with the order"
        );
    }

    #[test]
    fn nothing_reaches_the_certificate_authority_when_the_cluster_cannot_agree() {
        let (port, reached) = counting_port();
        let filing = Watched::refusing(Reason::NoQuorum);
        let config = config_at(port);

        let refused = against(&filing, &config, Some(&NodeId::new("node2")));
        assert_eq!(
            refused.reason(),
            Reason::NoQuorum,
            "the order blamed something other than the cluster: {refused}"
        );
        assert_eq!(
            reached.load(Ordering::SeqCst),
            0,
            "an order that could not be written was placed anyway, \
             so a cluster with no quorum spends the server's allowance"
        );
        assert!(
            filing.written().is_empty(),
            "the refusing state recorded a write, so nothing was measured"
        );
    }

    #[test]
    fn a_taken_over_order_is_finished_with_the_key_it_was_started_with() {
        let key = key_id();
        let material = key_pem();
        let started =
            Snapshot::new(config()).with_secret(key.clone(), Secret::new(material.clone()));
        let started = started.with_order(
            CertificateId::new(CERTIFICATE),
            OrderRecord {
                names: vec!["lab.example.test".to_owned()],
                challenge: OrderChallenge::Http01,
                order_url: Some("https://acme.example.test/order/9".to_owned()),
                key: key.clone(),
                answers: BTreeMap::new(),
                driven_by: Some(NodeId::new("node1")),
                started_at_unix: 1_700_000_000,
            },
        );

        let filing = Watched::holding(Some(started));
        let config = config_at(closed_port());
        against(&filing, &config, Some(&NodeId::new("node2")));

        // Every state written while the order ran carried the key it started
        // with, never a fresh one. A node that generated its own key would
        // download a certificate it cannot serve (ADR-0086).
        for state in filing.written() {
            if let Some(held) = state.secrets.get(&key) {
                assert_eq!(
                    held.expose(),
                    material.as_slice(),
                    "the node taking the order over replaced the signing key"
                );
            }
        }
        assert!(
            filing
                .now()
                .expect("something was written")
                .orders
                .is_empty(),
            "the order that was taken over and failed stayed in the state"
        );
    }
}
