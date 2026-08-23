// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Writing the DNS-01 challenge record, and waiting for it to be visible.
//!
//! Two providers, matched on rather than dispatched through a trait: a plugin
//! architecture for two of anything is a layer nobody reads (ADR-0026). What
//! is injected is one step lower, at the transport, which is what lets each
//! provider be measured without a name server or an API.
//!
//! # Why the wait is not optional
//!
//! Telling a certificate authority to check a record that is not visible yet
//! is the one failure no retry undoes: the server reads an empty name, marks
//! the identifier invalid, and the order is over. So nothing here returns
//! until a name server actually answers with the value, or until the
//! provider's own timeout says it never will.

pub mod cloudflare;
pub mod resolver;
pub mod rfc2136;
pub mod tsig;
pub mod wire;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use ek_ek_config::{CLOUDFLARE_API_BASE, DnsProvider, DnsProviderConnection};

use crate::error::{Failure, Reason};

/// The label a challenge record sits under (RFC 8555 section 8.4).
pub const CHALLENGE_LABEL: &str = "_acme-challenge";

/// How long to wait between two looks at a name server.
pub const LOOK_INTERVAL: Duration = Duration::from_secs(2);

/// How long one API call may take.
pub const API_TIMEOUT: Duration = Duration::from_secs(30);

/// The record name that answers the challenge for one identifier.
///
/// A wildcard is proven at the name it stands for: `*.example.org` and
/// `example.org` are both answered at `_acme-challenge.example.org`, which is
/// why one name can carry two values.
#[must_use]
pub fn challenge_name(identifier: &str) -> String {
    let base = identifier.strip_prefix("*.").unwrap_or(identifier);
    format!("{CHALLENGE_LABEL}.{base}")
}

/// Writes the challenge records and waits until a name server answers with
/// them.
///
/// `pause` is injected so a measurement runs the whole wait, including the
/// timeout, in milliseconds.
///
/// # Errors
///
/// Returns why the records could not be written or never appeared. A timeout
/// is [`Reason::Challenge`]: the records were accepted and are still not
/// visible, so telling the certificate authority to look would only lose the
/// identifier.
pub fn publish(
    provider: &DnsProvider,
    secret: &str,
    records: &BTreeMap<String, Vec<String>>,
    pause: &mut dyn FnMut(Duration),
) -> Result<(), Failure> {
    for (name, values) in records {
        match &provider.connection {
            DnsProviderConnection::Rfc2136 { .. } => {
                rfc2136::publish(
                    update_connection(provider, secret)?.as_connection(),
                    name,
                    values,
                )?;
            }
            DnsProviderConnection::Cloudflare { .. } => {
                let held = api_connection(provider, secret)?;
                let mut api = cloudflare::HttpsApi::new(API_TIMEOUT);
                cloudflare::publish(&mut api, held.as_connection(), name, values)?;
            }
        }
    }
    let server = asking(provider)?;
    let allowed = Duration::from_secs(u64::from(provider.propagation_timeout_secs));
    settle(
        records,
        allowed,
        &mut |name| resolver::txt(server, name),
        pause,
    )
}

/// Takes every challenge record away.
///
/// Called on the way out of an order whether it worked or not, so a zone
/// never collects records from attempts nobody is watching any more.
///
/// # Errors
///
/// Returns why a record could not be deleted. Every name is attempted, so one
/// failure does not leave the rest behind.
pub fn withdraw(provider: &DnsProvider, secret: &str, names: &[String]) -> Result<(), Failure> {
    let mut first: Option<Failure> = None;
    for name in names {
        let outcome = match &provider.connection {
            DnsProviderConnection::Rfc2136 { .. } => update_connection(provider, secret)
                .and_then(|held| rfc2136::withdraw(held.as_connection(), name)),
            DnsProviderConnection::Cloudflare { .. } => {
                api_connection(provider, secret).and_then(|held| {
                    let mut api = cloudflare::HttpsApi::new(API_TIMEOUT);
                    cloudflare::withdraw(&mut api, held.as_connection(), name)
                })
            }
        };
        if let Err(failure) = outcome {
            log::warn!("dns: {name} could not be taken away: {failure}");
            first.get_or_insert(failure);
        }
    }
    first.map_or(Ok(()), Err)
}

/// Waits until every value that was written can be looked up.
///
/// The lookup and the wait are both injected, so the timeout is measurable in
/// milliseconds rather than in the minutes an operator configures.
///
/// # Errors
///
/// Returns [`Reason::Challenge`] when a value is still not there once the
/// time is up, and whatever the lookup returned when it failed outright.
pub fn settle(
    records: &BTreeMap<String, Vec<String>>,
    allowed: Duration,
    look: &mut dyn FnMut(&str) -> Result<Vec<String>, Failure>,
    pause: &mut dyn FnMut(Duration),
) -> Result<(), Failure> {
    let mut waited = Duration::ZERO;

    loop {
        let mut missing = None;
        for (name, values) in records {
            let held = look(name)?;
            if values.iter().any(|value| !held.contains(value)) {
                // The name, never the value. The value is the answer to the
                // challenge, and a log is not where that belongs.
                missing = Some(name);
                break;
            }
        }
        let Some(name) = missing else {
            return Ok(());
        };

        if waited >= allowed {
            return Err(Failure::new(
                Reason::Challenge,
                format!(
                    "{name} was written but is still not answered with what it has to carry after \
                     {}s; raise this provider's propagation timeout or check that it serves this \
                     zone",
                    allowed.as_secs()
                ),
            ));
        }
        pause(LOOK_INTERVAL);
        waited += LOOK_INTERVAL;
    }
}

/// Which name server is asked whether a record is visible.
///
/// The one that was updated, when there is one: it is the authority and
/// there is no cache between here and its answer. Otherwise the machine's
/// own resolver, which is the closest thing to what the certificate authority
/// will ask.
fn asking(provider: &DnsProvider) -> Result<SocketAddr, Failure> {
    match &provider.connection {
        DnsProviderConnection::Rfc2136 { server, port, .. } => Ok(SocketAddr::new(*server, *port)),
        DnsProviderConnection::Cloudflare { .. } => resolver::system_resolver(),
    }
}

/// An update connection with its own storage for the decoded key.
struct Update<'a> {
    server: SocketAddr,
    zone: &'a str,
    key_name: &'a str,
    algorithm: ek_ek_config::TsigAlgorithm,
    secret: Vec<u8>,
}

impl Update<'_> {
    fn as_connection(&self) -> rfc2136::Connection<'_> {
        rfc2136::Connection {
            server: self.server,
            zone: self.zone,
            key_name: self.key_name,
            algorithm: self.algorithm,
            secret: &self.secret,
        }
    }
}

fn update_connection<'a>(provider: &'a DnsProvider, secret: &str) -> Result<Update<'a>, Failure> {
    let DnsProviderConnection::Rfc2136 {
        server,
        port,
        zone,
        tsig_key_name,
        tsig_algorithm,
        ..
    } = &provider.connection
    else {
        return Err(mismatched(provider));
    };

    // The stored value is what an operator copies out of the name server's
    // own configuration, which is base64. Decoding here rather than at rest
    // keeps the store holding exactly what was pasted in.
    let decoded = openssl::base64::decode_block(secret.trim()).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!(
                "the shared key of {} is not readable as base64: {error}",
                provider.id.as_str()
            ),
        )
    })?;
    if decoded.is_empty() {
        return Err(Failure::new(
            Reason::Configuration,
            format!("the shared key of {} is empty", provider.id.as_str()),
        ));
    }

    Ok(Update {
        server: SocketAddr::new(*server, *port),
        zone,
        key_name: tsig_key_name,
        algorithm: *tsig_algorithm,
        secret: decoded,
    })
}

/// An API connection with its own storage for the address.
struct Api<'a> {
    base: String,
    zone_id: &'a str,
    token: String,
}

impl Api<'_> {
    fn as_connection(&self) -> cloudflare::Connection<'_> {
        cloudflare::Connection {
            base: &self.base,
            zone_id: self.zone_id,
            token: &self.token,
        }
    }
}

fn api_connection<'a>(provider: &'a DnsProvider, secret: &str) -> Result<Api<'a>, Failure> {
    let DnsProviderConnection::Cloudflare {
        zone_id, api_base, ..
    } = &provider.connection
    else {
        return Err(mismatched(provider));
    };

    let token = secret.trim();
    if token.is_empty() {
        return Err(Failure::new(
            Reason::Configuration,
            format!("the API token of {} is empty", provider.id.as_str()),
        ));
    }

    let base = if api_base.is_empty() {
        CLOUDFLARE_API_BASE
    } else {
        api_base.as_str()
    };
    Ok(Api {
        base: base.trim_end_matches('/').to_owned(),
        zone_id,
        token: token.to_owned(),
    })
}

fn mismatched(provider: &DnsProvider) -> Failure {
    Failure::new(
        Reason::Configuration,
        format!(
            "{} was reached as a kind of provider it is not",
            provider.id.as_str()
        ),
    )
}
