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
//! # What travels here
//!
//! In this release, one health question and its answer. Raft rides the same
//! channel from T-037. Nothing secret goes in either direction: the channel is
//! encrypted, but a message that would be damaging in a log is a message that
//! should not exist.

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
    /// Are you there, and which release are you?
    Health(HealthAsk),
}

/// Anything a node answers with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum Answer {
    /// The answer to [`Ask::Health`].
    Health(HealthAnswer),
    /// The question was not one this release knows.
    Refused(Refusal),
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
    /// Taken from the certificate the caller presented nothing about: this is
    /// the answering node naming itself, and the caller checks it against the
    /// name it verified in the handshake.
    pub node: String,
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
