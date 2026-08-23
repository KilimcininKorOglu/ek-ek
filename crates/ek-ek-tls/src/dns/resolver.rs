// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sending a DNS message and reading the answer.
//!
//! Over TCP, always. An update carries a signature and a set of records and
//! outgrows what a datagram holds; a truncated answer would then have to be
//! retried over TCP anyway. Doing it once removes the retry, removes the
//! truncation case, and removes the window in which an answer from somebody
//! else arrives first.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::error::{Failure, Reason};

/// How long one exchange may take.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the machine's own resolver is configured.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The port a name server listens on.
pub const DNS_PORT: u16 = 53;

/// Sends one message and reads one answer.
///
/// # Errors
///
/// Returns [`Reason::Network`] when the server cannot be reached, does not
/// answer in time, or closes the connection mid-answer.
pub fn exchange(server: SocketAddr, message: &[u8]) -> Result<Vec<u8>, Failure> {
    let length = u16::try_from(message.len()).map_err(|_| {
        Failure::new(
            Reason::Protocol,
            "the message is longer than the protocol carries".to_owned(),
        )
    })?;

    let mut stream = TcpStream::connect_timeout(&server, EXCHANGE_TIMEOUT)
        .map_err(|error| unreachable(server, &error))?;
    stream
        .set_read_timeout(Some(EXCHANGE_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(EXCHANGE_TIMEOUT)))
        .map_err(|error| unreachable(server, &error))?;

    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    stream
        .write_all(&framed)
        .map_err(|error| unreachable(server, &error))?;

    let mut size = [0_u8; 2];
    stream
        .read_exact(&mut size)
        .map_err(|error| unreachable(server, &error))?;
    let mut answer = vec![0_u8; usize::from(u16::from_be_bytes(size))];
    stream
        .read_exact(&mut answer)
        .map_err(|error| unreachable(server, &error))?;
    Ok(answer)
}

/// Asks one name server what TXT records sit at a name.
///
/// A name that holds nothing is an empty list rather than a fault, because
/// that is the normal state while an update is still spreading.
///
/// # Errors
///
/// Returns [`Reason::Network`] when the server does not answer and
/// [`Reason::Protocol`] when it answers with something unreadable or with a
/// code that is not about an absent name.
pub fn txt(server: SocketAddr, name: &str) -> Result<Vec<String>, Failure> {
    let message = crate::dns::wire::question(message_id()?, name, crate::dns::wire::TYPE_TXT)?;
    let answer = exchange(server, &message)?;
    let head = crate::dns::wire::header(&answer)?;
    // NXDOMAIN means the name is not there yet, which is what waiting is for.
    if head.rcode() != 0 && head.rcode() != 3 {
        return Err(Failure::new(
            Reason::Protocol,
            format!(
                "the name server at {server} answered the question about {name} with code {}",
                head.rcode()
            ),
        ));
    }
    crate::dns::wire::txt_answers(&answer)
}

/// A fresh message identity.
///
/// Random rather than counted: an off-path answer has to guess it, and a
/// counter makes guessing free.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the random source fails.
pub fn message_id() -> Result<u16, Failure> {
    let mut bytes = [0_u8; 2];
    openssl::rand::rand_bytes(&mut bytes).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("a message identity could not be drawn: {error}"),
        )
    })?;
    Ok(u16::from_be_bytes(bytes))
}

/// The first name server the machine is configured with.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the file cannot be read or names no
/// server, because a propagation check has nowhere to ask without one.
pub fn system_resolver() -> Result<SocketAddr, Failure> {
    let text = std::fs::read_to_string(RESOLV_CONF).map_err(|error| {
        Failure::new(
            Reason::Configuration,
            format!("{RESOLV_CONF} could not be read: {error}"),
        )
    })?;
    first_nameserver(&text).ok_or_else(|| {
        Failure::new(
            Reason::Configuration,
            format!("{RESOLV_CONF} names no name server to ask"),
        )
    })
}

/// Reads the first `nameserver` line out of a resolver configuration.
///
/// Split out so the parsing is measurable without a machine that happens to
/// be configured a particular way.
#[must_use]
pub fn first_nameserver(text: &str) -> Option<SocketAddr> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or(line).trim())
        .filter_map(|line| line.strip_prefix("nameserver"))
        .map(str::trim)
        // A scope suffix belongs to a link-local address and not to the
        // address itself, which is what has to be parsed here.
        .filter_map(|address| address.split('%').next())
        .find_map(|address| {
            address
                .parse()
                .ok()
                .map(|address| SocketAddr::new(address, DNS_PORT))
        })
}

fn unreachable(server: SocketAddr, error: &std::io::Error) -> Failure {
    Failure::new(
        Reason::Network,
        format!("the name server at {server} did not answer: {error}"),
    )
}
