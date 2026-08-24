// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What two nodes say to each other over the peer channel.
//!
//! # Framing
//!
//! One JSON object per line, the same shape `node-agent` and `data-plane`
//! already speak (ADR-0082). A reader takes a line, a writer appends a
//! newline, and nothing has to agree on a length prefix or a struct layout.
//!
//! Both directions are tagged, so a message from a newer release arrives as an
//! unknown tag and is refused by name instead of being read as the wrong
//! message. Peer traffic is exactly where that matters: an upgrade is rolling,
//! so two releases speak to each other for as long as it takes.
//!
//! # The first line
//!
//! Every connection opens with [`Ask::Hello`], and nothing else is answered
//! until it has been. It carries the protocol release and the config schema
//! this node reads, so a node that cannot read what the cluster holds is
//! refused before it takes a single log record (ADR-0019, ADR-0083).
//!
//! # What travels here
//!
//! A health question, and calls addressed to a named service. This crate does
//! not know what a service call means: the body is opaque JSON, and
//! `ek-ek-raft` is what fills it. That is what keeps consensus above peer
//! trust rather than inside it (ADR-0083).

use serde::{Deserialize, Serialize};

/// The release of the peer protocol this build speaks.
///
/// Sent in both directions and compared, so two nodes that cannot understand
/// each other say so rather than half working.
pub const PROTOCOL: &str = "ek-ek-peer/1";

/// Anything one node asks another.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum Ask {
    /// The first line of every connection.
    Hello(Hello),
    /// Are you there, and which release are you?
    Health(HealthAsk),
    /// A call addressed to a named service.
    Call(Call),
}

/// Anything a node answers with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum Answer {
    /// The answer to [`Ask::Hello`].
    Hello(HelloAnswer),
    /// The answer to [`Ask::Health`].
    Health(HealthAnswer),
    /// The answer to [`Ask::Call`].
    Reply(Reply),
    /// The question was not one this node will answer.
    Refused(Refusal),
}

/// The opening line of a connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The protocol release the caller speaks.
    pub protocol: String,
    /// The highest config schema the caller can read.
    pub schema_version: u32,
}

/// The answer to an opening line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloAnswer {
    /// The protocol release the answering node speaks.
    pub protocol: String,
    /// The highest config schema the answering node can read.
    pub schema_version: u32,
    /// Which node answered.
    pub node: String,
}

/// A health question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthAsk {
    /// The protocol release the caller speaks.
    pub protocol: String,
}

/// A health answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthAnswer {
    /// The protocol release the answering node speaks.
    pub protocol: String,
    /// Which node answered.
    ///
    /// This is the answering node naming itself. The caller checks it against
    /// the name it verified in the handshake, because only that one was
    /// signed by anything.
    pub node: String,
}

/// A call addressed to a named service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    /// Which service the call is for, for example `raft.append_entries`.
    pub service: String,
    /// What the service is being asked, in whatever shape it defines.
    pub body: serde_json::Value,
}

/// What a service answered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    /// What the service answered, in whatever shape it defines.
    pub body: serde_json::Value,
}

/// A question that was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refusal {
    /// A stable reason key.
    pub reason: String,
    /// What was wrong, for the log.
    pub detail: String,
}

/// The reason key for a line that is not a message this release knows.
pub const UNREADABLE: &str = "peer.unreadable";

/// The reason key for a caller speaking a protocol release this one does not.
pub const WRONG_PROTOCOL: &str = "peer.wrong_protocol";

/// The reason key for a caller that reads a different config schema.
pub const WRONG_SCHEMA: &str = "peer.wrong_schema";

/// The reason key for a caller that said something before it said hello.
pub const NO_HELLO: &str = "peer.no_hello";

/// The reason key for a call addressed to a service this node does not run.
pub const NO_SERVICE: &str = "peer.no_service";

/// The reason key for a caller with no certificate reaching past the services
/// this node opens to one.
///
/// Told apart from [`NO_SERVICE`] on purpose. A caller that joins and then
/// calls the same name again has to be able to see that the second refusal was
/// about the service and the first was about the certificate (ADR-0084).
pub const NOT_OPEN: &str = "peer.not_open";

/// The reason key for a caller this cluster has removed.
///
/// Its certificate is still valid, and nothing revokes it. This is what stops
/// it all the same (R-32, ADR-0084).
pub const REMOVED: &str = "peer.removed";
