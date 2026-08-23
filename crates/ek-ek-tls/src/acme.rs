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

use std::collections::BTreeMap;
use std::time::Duration;

use ek_ek_config::AcmeSettings;
use openssl::pkey::{PKey, Private};

use crate::attempt::{ATTEMPTS, wait_before};
use crate::csr;
use crate::error::{Failure, Reason};
use crate::jws::sign;
use crate::order::{Answer, Ask, Flow, MOST_NONCE_RETRIES, Progress};

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

/// Publishes the challenge answers the server is about to ask for.
///
/// Called with an empty map when the order ends, whether it succeeded or not,
/// so the path never stays open past the order it was opened for.
pub type Publish<'a> = &'a mut dyn FnMut(&BTreeMap<String, String>) -> Result<(), Failure>;

/// Waits, for as long as it is told to.
pub type Pause<'a> = &'a mut dyn FnMut(Duration);

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
    publish: Publish<'_>,
    pause: Pause<'_>,
) -> Result<Obtained, Failure> {
    let mut transport = https(settings)?;
    obtain_over(settings, account, names, &mut transport, publish, pause)
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
    transport: &mut dyn Transport,
    publish: Publish<'_>,
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

        // A fresh signing request per attempt. Reusing one would hand the same
        // key to a server that already refused the order, and a key that took
        // part in a failed exchange is not one to keep serving.
        let request = csr::request(names)?;
        let mut flow = Flow::new(
            &settings.directory_url,
            names.to_vec(),
            &thumbprint,
            &settings.contact_email,
            request.encoded(),
        );

        match run(&mut flow, account, transport, &mut *publish, &mut *pause) {
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
    publish: Publish<'_>,
    pause: Pause<'_>,
) -> Result<String, Failure> {
    let mut nonce: Option<String> = None;
    let mut live: BTreeMap<String, String> = BTreeMap::new();
    let outcome = drive(
        flow,
        account,
        transport,
        &mut *publish,
        pause,
        &mut nonce,
        &mut live,
    );

    // Whatever happened, the path closes. A failed attempt that left a token
    // answerable would leave an endpoint open on a name nobody is watching.
    flow.abandon();
    let closed = if live.is_empty() {
        Ok(())
    } else {
        publish(&BTreeMap::new())
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
    publish: Publish<'_>,
    pause: Pause<'_>,
    nonce: &mut Option<String>,
    live: &mut BTreeMap<String, String>,
) -> Result<String, Failure> {
    let mut rejected = 0_u32;

    while let Some(ask) = flow.next() {
        // Published before the ask goes out, because the ask that follows a
        // new token is the one telling the server to come and read it.
        if flow.published() != &*live {
            publish(flow.published())?;
            live.clone_from(flow.published());
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
