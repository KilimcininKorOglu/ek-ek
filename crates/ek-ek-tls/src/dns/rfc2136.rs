// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Writing a challenge record with a dynamic DNS update (RFC 2136).
//!
//! One standard covers both name servers this product supports: BIND and
//! Windows DNS Server (ADR-0026). Every update is signed, and the answer's
//! own signature is checked before it is believed.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::TsigAlgorithm;

use crate::dns::resolver::{exchange, message_id};
use crate::dns::tsig;
use crate::dns::wire::{self, Record};
use crate::error::{Failure, Reason};

/// How long a resolver may hold a challenge record.
///
/// Short, because the record lives for one order and a resolver holding it
/// afterwards would answer for a name that no longer means anything.
pub const RECORD_TTL: u32 = 60;

/// Everything one update needs to reach its name server.
#[derive(Clone, Copy, Debug)]
pub struct Connection<'a> {
    /// Where the update goes.
    pub server: SocketAddr,
    /// The zone the record is written into.
    pub zone: &'a str,
    /// The name of the shared key.
    pub key_name: &'a str,
    /// The algorithm the signature uses.
    pub algorithm: TsigAlgorithm,
    /// The shared key itself, already decoded.
    pub secret: &'a [u8],
}

/// Replaces every TXT record at one name with the values given.
///
/// The set is deleted first and rebuilt in the same message, so a record an
/// earlier order left behind cannot survive and two values for the same name
/// (an apex and its wildcard) both land.
///
/// # Errors
///
/// Returns why the name server refused. A refusal about the key or the zone
/// is [`Reason::Configuration`], because no retry fixes it.
pub fn publish(connection: Connection<'_>, name: &str, values: &[String]) -> Result<(), Failure> {
    let mut changes = vec![Record::delete_txt_set(name)];
    for value in values {
        changes.push(Record::add_txt(name, value, RECORD_TTL)?);
    }
    apply(connection, &changes)
}

/// Takes every TXT record at one name away.
///
/// # Errors
///
/// The same as [`publish`].
pub fn withdraw(connection: Connection<'_>, name: &str) -> Result<(), Failure> {
    apply(connection, &[Record::delete_txt_set(name)])
}

/// Sends one update and reads the answer.
fn apply(connection: Connection<'_>, changes: &[Record]) -> Result<(), Failure> {
    let id = message_id()?;
    let message = wire::update(id, connection.zone, changes)?;
    let now = seconds_now()?;
    let signed = tsig::sign(
        &message,
        connection.key_name,
        connection.algorithm,
        connection.secret,
        now,
    )?;

    let answer = exchange(connection.server, &signed.message)?;
    let head = wire::header(&answer)?;
    if head.id != id {
        return Err(Failure::new(
            Reason::Protocol,
            "the name server answered an update nobody sent".to_owned(),
        ));
    }

    // Checked before the code is read. A forged answer saying the record was
    // written would let the order tell the certificate authority to come and
    // look at a name that holds nothing, and a refused identifier is not
    // something a retry undoes.
    tsig::verify(
        &answer,
        connection.key_name,
        connection.algorithm,
        connection.secret,
        &signed.mac,
        now,
    )?;

    if head.rcode() != 0 {
        return Err(refused(head.rcode(), connection.server));
    }
    Ok(())
}

/// Turns a response code into something an operator can act on.
fn refused(rcode: u8, server: SocketAddr) -> Failure {
    let (reason, said) = match rcode {
        1 => (Reason::Protocol, "the update was malformed"),
        2 => (Reason::Server, "the name server failed while applying it"),
        3 => (Reason::Configuration, "the zone does not exist there"),
        4 => (
            Reason::Configuration,
            "the name server does not do dynamic updates",
        ),
        5 => (
            Reason::Configuration,
            "the name server refused the update; the key is not allowed to write this zone",
        ),
        6..=8 => (
            Reason::Protocol,
            "the zone did not hold what the update expected",
        ),
        9 => (
            Reason::Configuration,
            "the name server did not accept the key this update was signed with",
        ),
        10 => (
            Reason::Configuration,
            "the name is not inside the zone this provider is configured with",
        ),
        _ => (
            Reason::Protocol,
            "the name server answered with a code this client does not know",
        ),
    };
    Failure::new(reason, format!("{server}: {said} (code {rcode})"))
}

fn seconds_now() -> Result<u64, Failure> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .map_err(|error| {
            Failure::new(
                Reason::Crypto,
                format!("this machine's clock is before the epoch: {error}"),
            )
        })
}
