// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Carrying an ACME order over the network.
//!
//! [`crate::order::Flow`] decides what to ask; this sends it, holds the nonce,
//! waits between attempts and publishes the challenge answer. The split is
//! deliberate: everything that can be decided without a socket is decided in
//! the flow, and what is left here is small enough to read in one sitting.
//!
//! # What is injected and why
//!
//! The transport, the publisher and the wait are all passed in. A measurement
//! can then run the whole driver, including the growing waits between five
//! attempts, without a network and without waiting fifteen minutes. Production
//! passes an HTTPS transport and `std::thread::sleep`.

use std::time::Duration;

use ek_ek_config::AcmeSettings;
use openssl::pkey::{PKey, Private};

use crate::attempt::{ATTEMPTS, wait_before};
use crate::csr;
use crate::error::{Failure, Reason};
use crate::jws::sign;
use crate::order::{Answer, Ask, Challenge, Flow, MOST_NONCE_RETRIES, Progress, Publication};

/// How long to wait between two reads of an order the server is still
/// deciding on.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long one request may take.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The content type every signed ACME request carries.
const JOSE: &str = "application/jose+json";

/// One answer, with the nonce the server attached to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// What the flow reads.
    pub answer: Answer,
    /// The nonce to sign the next request with, when the server sent one.
    pub nonce: Option<String>,
}

/// Something that can carry one request to an ACME server.
pub trait Transport {
    /// Sends one request. `body` is `None` for an unsigned read.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Network`] when the answer never arrives.
    fn call(&mut self, url: &str, body: Option<&str>) -> Result<Reply, Failure>;
}

/// What an order produced.
///
/// Its `Debug` prints neither half, for the same reason
/// [`crate::csr::Request`]'s does not: one of the two is a private key, and a
/// struct holding one is printed by accident far more often than on purpose.
pub struct Obtained {
    /// The certificate chain, leaf first, as PEM.
    pub chain_pem: Vec<u8>,
    /// The private key it was issued against, as PEM.
    pub key_pem: Vec<u8>,
}

impl std::fmt::Debug for Obtained {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Obtained").finish_non_exhaustive()
    }
}

/// What an order has reached that has to outlive the process driving it.
///
/// Two things, reported together because they become durable at the same
/// points and a caller that wrote one without the other would leave an order
/// nobody can finish. The URL is what another node takes the order over at,
/// and the publication is what every node has to answer while the server
/// checks (ADR-0086).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reached {
    /// The URL the certificate authority named the order with, once it has.
    pub order_url: Option<String>,
    /// What has to be reachable right now.
    pub publication: Publication,
}

/// Records what an order has reached, and publishes its challenge answers.
///
/// Called whenever either half changes, and with an empty publication when the
/// order ends, whether it succeeded or not, so the path never stays open past
/// the order it was opened for.
pub type Record<'a> = &'a mut dyn FnMut(&Reached) -> Result<(), Failure>;

/// Waits, for as long as it is told to.
pub type Pause<'a> = &'a mut dyn FnMut(Duration);

/// How one order is driven.
#[derive(Clone, Copy, Debug, Default)]
pub struct Plan<'a> {
    /// The key the certificate is issued against, when the caller pins one.
    ///
    /// `None` generates a fresh key for every attempt, which is what a single
    /// node wants: a key that took part in a failed exchange never serves. A
    /// cluster pins one, because whichever node finishes the order has to hold
    /// the key the certificate belongs to, and it drops the key with the order
    /// (ADR-0086).
    pub key: Option<&'a PKey<Private>>,
    /// An order the server already named, to be taken over rather than placed.
    ///
    /// Only the first attempt takes it over. A retry places a fresh order,
    /// because an order that failed in a way worth retrying is not one to keep
    /// reading.
    pub resume: Option<&'a str>,
}

/// Obtains a certificate, trying again when the fault might pass.
///
/// The attempt count and the waits are fixed (ADR-0026). A caller cannot raise
/// them, because the allowance being spent belongs to the ACME server rather
/// than to this installation.
///
/// # Errors
///
/// Returns the last failure. [`Reason::TooManyAttempts`] means the attempts
/// ran out; anything else means the fault was not worth another attempt.
pub fn obtain(
    settings: &AcmeSettings,
    account: &PKey<Private>,
    names: &[String],
    kind: Challenge,
    record: Record<'_>,
    pause: Pause<'_>,
) -> Result<Obtained, Failure> {
    let mut transport = https(settings)?;
    obtain_over(
        settings,
        account,
        names,
        kind,
        &mut transport,
        record,
        pause,
    )
}

/// Obtains a certificate over a transport somebody else built.
///
/// # Errors
///
/// The same as [`obtain`].
pub fn obtain_over(
    settings: &AcmeSettings,
    account: &PKey<Private>,
    names: &[String],
    kind: Challenge,
    transport: &mut dyn Transport,
    record: Record<'_>,
    pause: Pause<'_>,
) -> Result<Obtained, Failure> {
    obtain_planned_over(
        settings,
        account,
        names,
        kind,
        Plan::default(),
        transport,
        record,
        pause,
    )
}

/// Obtains a certificate the way the plan says, over HTTPS.
///
/// # Errors
///
/// The same as [`obtain`].
pub fn obtain_planned(
    settings: &AcmeSettings,
    account: &PKey<Private>,
    names: &[String],
    kind: Challenge,
    plan: Plan<'_>,
    record: Record<'_>,
    pause: Pause<'_>,
) -> Result<Obtained, Failure> {
    let mut transport = https(settings)?;
    obtain_planned_over(
        settings,
        account,
        names,
        kind,
        plan,
        &mut transport,
        record,
        pause,
    )
}

/// Obtains a certificate the way the plan says, over a transport somebody else
/// built.
///
/// # Errors
///
/// The same as [`obtain`].
#[allow(clippy::too_many_arguments)]
pub fn obtain_planned_over(
    settings: &AcmeSettings,
    account: &PKey<Private>,
    names: &[String],
    kind: Challenge,
    plan: Plan<'_>,
    transport: &mut dyn Transport,
    record: Record<'_>,
    pause: Pause<'_>,
) -> Result<Obtained, Failure> {
    let thumbprint = crate::jws::thumbprint(account)?;
    let mut last: Option<Failure> = None;

    for attempt in 1..=ATTEMPTS {
        if let Some(wait) = wait_before(attempt)
            && !wait.is_zero()
        {
            log::warn!(
                "acme: attempt {attempt} of {ATTEMPTS} for {} starts in {}s",
                names.join(", "),
                wait.as_secs()
            );
            pause(wait);
        }

        // A fresh signing request per attempt, unless the caller pinned a key.
        // Generating one would hand the same key to a server that already
        // refused the order, and a key that took part in a failed exchange is
        // not one to keep serving. A pinned key belongs to one order and is
        // dropped with it, which is the same rule reached another way.
        let request = match plan.key {
            Some(key) => csr::request_with(names, key.clone())?,
            None => csr::request(names)?,
        };
        // Only the first attempt takes an order over. A retry places a fresh
        // one, because an order that failed is not one to keep reading.
        let mut flow = match plan.resume.filter(|_| attempt == 1) {
            Some(url) => Flow::resume(
                &settings.directory_url,
                names.to_vec(),
                &thumbprint,
                &settings.contact_email,
                request.encoded(),
                kind,
                url,
            ),
            None => Flow::new(
                &settings.directory_url,
                names.to_vec(),
                &thumbprint,
                &settings.contact_email,
                request.encoded(),
                kind,
            ),
        };

        match run(&mut flow, account, transport, &mut *record, &mut *pause) {
            Ok(chain) => {
                log::info!("acme: {} obtained on attempt {attempt}", names.join(", "));
                return Ok(Obtained {
                    chain_pem: chain.into_bytes(),
                    key_pem: request.key_pem()?,
                });
            }
            Err(failure) => {
                log::warn!(
                    "acme: attempt {attempt} of {ATTEMPTS} for {} failed: {failure}",
                    names.join(", ")
                );
                if !failure.worth_retrying() {
                    return Err(failure);
                }
                last = Some(failure);
            }
        }
    }

    Err(last.map_or_else(
        || {
            Failure::new(
                Reason::TooManyAttempts,
                format!("no attempt was made for {}", names.join(", ")),
            )
        },
        |failure| {
            Failure::new(
                Reason::TooManyAttempts,
                format!("{ATTEMPTS} attempts failed, last: {failure}"),
            )
        },
    ))
}

/// Drives one attempt from the directory to the certificate.
///
/// # Errors
///
/// Returns why this attempt stopped. Whether another one is worth making is
/// the caller's decision.
pub fn run(
    flow: &mut Flow,
    account: &PKey<Private>,
    transport: &mut dyn Transport,
    record: Record<'_>,
    pause: Pause<'_>,
) -> Result<String, Failure> {
    let mut nonce: Option<String> = None;
    // What the flow already reached before the first ask. For a fresh order
    // that is nothing; for one being taken over it is the URL the previous
    // node wrote down. Starting from it is what keeps a take-over from
    // withdrawing the answer that is already published and putting the same
    // one back, which would close the challenge path for a round trip while
    // the certificate authority is checking it (ADR-0086).
    let mut live = Reached {
        order_url: flow.order_url().map(str::to_owned),
        publication: flow.published().clone(),
    };
    let outcome = drive(
        flow,
        account,
        transport,
        &mut *record,
        pause,
        &mut nonce,
        &mut live,
    );

    // Whatever happened, the path closes. A failed attempt that left a token
    // answerable would leave an endpoint open on a name nobody is watching.
    flow.abandon();
    let closed = if live.publication.is_empty() {
        Ok(())
    } else {
        // The kind is kept, because taking a publication away means reaching
        // the same place it was put: a name server for one, a listener for
        // the other. The order URL is kept too: an attempt that failed while
        // the certificate was still to be collected is one another node can
        // take over, and a caller that dropped the URL here could not.
        record(&Reached {
            order_url: live.order_url.clone(),
            publication: Publication {
                kind: live.publication.kind,
                entries: std::collections::BTreeMap::new(),
            },
        })
    };

    match (outcome, closed) {
        (Ok(chain), Ok(())) => Ok(chain),
        // The order succeeded but the path is still open. That is a fault in
        // its own right, and reporting success would leave nobody to close it.
        (Ok(_), Err(close)) => Err(close),
        (Err(failure), Ok(())) => Err(failure),
        (Err(failure), Err(close)) => {
            log::error!("acme: the challenge path could not be closed either: {close}");
            Err(failure)
        }
    }
}

/// The body of one attempt, with the cleanup left to [`run`].
fn drive(
    flow: &mut Flow,
    account: &PKey<Private>,
    transport: &mut dyn Transport,
    record: Record<'_>,
    pause: Pause<'_>,
    nonce: &mut Option<String>,
    live: &mut Reached,
) -> Result<String, Failure> {
    let mut rejected = 0_u32;

    while let Some(ask) = flow.next() {
        // Recorded before the ask goes out, for two reasons that meet here.
        // The ask that follows a new token is the one telling the server to
        // come and read it, so the answer has to be reachable first. And the
        // ask that follows a placed order is the one that can be lost, so the
        // URL has to be somewhere another node can find it first (ADR-0086).
        let reached = Reached {
            order_url: flow.order_url().map(str::to_owned),
            publication: flow.published().clone(),
        };
        if reached != *live {
            // Recorded before the attempt rather than after it. A publisher
            // that put the answer in place and then failed on the step after
            // has still left something behind, and a cleanup that only knows
            // about publications that succeeded would walk past it.
            live.clone_from(&reached);
            record(&*live)?;
        }

        if flow.waiting_on_server() {
            pause(POLL_INTERVAL);
        }

        let reply = match &ask {
            Ask::Read { url } => transport.call(url, None)?,
            Ask::Send {
                url,
                payload,
                identify,
            } => {
                let held = nonce.clone().ok_or_else(|| {
                    Failure::new(
                        Reason::Protocol,
                        "the server sent no nonce to sign with".to_owned(),
                    )
                })?;
                let body = sign(
                    account,
                    *identify,
                    flow.account(),
                    url,
                    &held,
                    payload.as_deref(),
                )?;
                transport.call(url, Some(&body))?
            }
        };

        // Taken before the answer is read, so a rejected nonce is answered
        // with the fresh one the same response carried.
        *nonce = reply.nonce.clone();

        match flow.accept(&reply.answer)? {
            Progress::Moved => rejected = 0,
            Progress::Again => {
                rejected += 1;
                if rejected > MOST_NONCE_RETRIES {
                    return Err(Failure::new(
                        Reason::Server,
                        format!("the server rejected {MOST_NONCE_RETRIES} nonces in a row"),
                    ));
                }
                if nonce.is_none() {
                    return Err(Failure::new(
                        Reason::Protocol,
                        "the server rejected the nonce and sent no replacement".to_owned(),
                    ));
                }
            }
        }
    }

    flow.chain().map(str::to_owned).ok_or_else(|| {
        Failure::new(
            Reason::Protocol,
            "the order finished without a certificate".to_owned(),
        )
    })
}

/// An HTTPS transport pointed at the configured server.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the configured root certificate is
/// not readable.
fn https(settings: &AcmeSettings) -> Result<HttpsTransport, Failure> {
    let mut tls = ureq::tls::TlsConfig::builder().provider(ureq::tls::TlsProvider::NativeTls);

    if settings.trusted_root_pem.trim().is_empty() {
        // What the machine already trusts, which is what a public ACME server
        // needs and what an operator expects when they configured nothing.
        tls = tls.root_certs(ureq::tls::RootCerts::PlatformVerifier);
    } else {
        let root = ureq::tls::Certificate::from_pem(settings.trusted_root_pem.as_bytes()).map_err(
            |error| {
                Failure::new(
                    Reason::Configuration,
                    format!("the configured ACME root certificate is not readable: {error}"),
                )
            },
        )?;
        tls = tls.root_certs(ureq::tls::RootCerts::new_with_certs(&[root]));
    }

    let agent = ureq::config::Config::builder()
        // ACME answers 4xx to say what is wrong, and the flow reads those
        // documents. Treating a status as a transport error would throw away
        // the one thing that says why the order failed.
        .http_status_as_error(false)
        .timeout_global(Some(REQUEST_TIMEOUT))
        .tls_config(tls.build())
        .build()
        .new_agent();

    Ok(HttpsTransport { agent })
}

/// The transport used in production.
struct HttpsTransport {
    agent: ureq::Agent,
}

impl Transport for HttpsTransport {
    fn call(&mut self, url: &str, body: Option<&str>) -> Result<Reply, Failure> {
        let mut response = match body {
            Some(body) => self.agent.post(url).header("Content-Type", JOSE).send(body),
            None => self.agent.get(url).call(),
        }
        .map_err(|error| Failure::new(Reason::Network, format!("{url} did not answer: {error}")))?;

        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let location = header("location");
        let nonce = header("replay-nonce");

        let text = response.body_mut().read_to_string().map_err(|error| {
            Failure::new(
                Reason::Network,
                format!("{url} answered something unreadable: {error}"),
            )
        })?;

        Ok(Reply {
            answer: Answer::new(status, text, location),
            nonce,
        })
    }
}
