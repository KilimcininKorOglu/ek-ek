// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Answering the ACME HTTP-01 challenge.
//!
//! An ACME server proves a name belongs to whoever answers it by asking for a
//! value under a well known path on port 80 (RFC 8555 section 8.3). The
//! product already terminates that port, so it answers the question itself and
//! an operator configures nothing (ADR-0026).
//!
//! # Why the path is not always open
//!
//! The answers are delivered with the configuration and are empty except while
//! an order is waiting on them. An endpoint that answers all the time tells
//! anybody who asks whether a given token is live, and it is one more path
//! into the process that exists for no reason between orders.
//!
//! Nothing here touches the network, so both halves are measurable directly:
//! what is answered while an order is live, and what is answered when none is.

use std::collections::BTreeMap;

use ek_ek_config::HTTP01_PORT;

use crate::route::normalise;

/// The path an ACME server asks the challenge on.
pub const PREFIX: &str = "/.well-known/acme-challenge/";

/// What to do with a request that arrived on a challenge path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply<'a> {
    /// Not a challenge. The request is routed like any other.
    Elsewhere,
    /// A challenge path with nothing behind it.
    Unknown,
    /// The value to answer with.
    Answer(&'a str),
}

/// Decides what a request on a listener gets.
///
/// The path is normalised first, so `/.well-known/acme-challenge/../../x`
/// cannot reach a token and a percent encoded separator cannot hide one
/// (ADR-0071).
///
/// A listener on any other port never takes this path away from routing: the
/// server asks on port 80 and nowhere else, so opening the path on a TLS
/// listener would only shadow a real one an operator configured.
#[must_use]
pub fn reply<'a>(challenges: &'a BTreeMap<String, String>, port: u16, path: &str) -> Reply<'a> {
    if port != HTTP01_PORT {
        return Reply::Elsewhere;
    }

    let path = normalise(path);
    let Some(token) = path.strip_prefix(PREFIX) else {
        return Reply::Elsewhere;
    };

    // Matched whole, never as a prefix. A deeper path under the prefix and an
    // empty one are both names nothing was published under, so they are
    // refused by the lookup itself rather than by a rule of their own.
    challenges
        .get(token)
        .map_or(Reply::Unknown, |answer| Reply::Answer(answer))
}
