// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What can go wrong while replicating a configuration.
//!
//! # Why the reason and the detail are separate
//!
//! The reason is a stable value, so a caller can decide what to do without
//! reading text. A web handler turns [`Reason::NotLeader`] into a redirect and
//! [`Reason::NoQuorum`] into a refusal, and neither decision should depend on
//! wording that a dependency bump can change.
//!
//! # What never travels in one
//!
//! Key material. The state a write carries holds private keys, and a failure
//! about that write must name the write, never its contents (ADR-0018).

use std::fmt;

/// What kind of thing went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// This node is not the leader, so it will not write.
    NotLeader,
    /// There is no leader at all, so nothing can be written anywhere.
    NoQuorum,
    /// Consensus itself refused or could not complete the request.
    Consensus,
    /// The local store could not be read or written.
    Storage,
    /// What was asked for cannot be built at all.
    Configuration,
    /// A peer runs a schema this release cannot replicate with.
    Schema,
}

impl Reason {
    /// Every reason, so a test can walk the whole set.
    pub const ALL: [Self; 6] = [
        Self::NotLeader,
        Self::NoQuorum,
        Self::Consensus,
        Self::Storage,
        Self::Configuration,
        Self::Schema,
    ];

    /// A stable identifier for logs and reports.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::NotLeader => "raft.not_leader",
            Self::NoQuorum => "raft.no_quorum",
            Self::Consensus => "raft.consensus",
            Self::Storage => "raft.storage",
            Self::Configuration => "raft.configuration",
            Self::Schema => "raft.schema",
        }
    }

    /// Whether the same call, sent to the same node, could succeed later.
    ///
    /// A caller retries a lost quorum and stops retrying a schema mismatch,
    /// because no amount of waiting changes which release a peer runs.
    #[must_use]
    pub const fn worth_retrying(self) -> bool {
        match self {
            Self::NoQuorum | Self::Consensus => true,
            Self::NotLeader | Self::Storage | Self::Configuration | Self::Schema => false,
        }
    }
}

/// One failure, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    reason: Reason,
    detail: String,
}

impl Failure {
    /// Builds a failure.
    #[must_use]
    pub fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// What kind of thing went wrong.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// What consensus, or this crate, said about it.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.reason.key(), self.detail)
    }
}

impl std::error::Error for Failure {}

/// What this crate returns.
pub type Result<T> = std::result::Result<T, Failure>;
